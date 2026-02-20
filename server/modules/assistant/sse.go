package assistant

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"

	"github.com/apex/log"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/responses"
	"google.golang.org/genai"
)

// sseEventWriter handles writing Server-Sent Events in the expected format
type sseEventWriter struct {
	writer io.Writer
	logger log.Interface
}

func newSSEEventWriter(logger log.Interface, writer io.Writer) *sseEventWriter {
	return &sseEventWriter{writer: writer, logger: logger}
}

func (w *sseEventWriter) writeMessageStart(model string) error {
	_, err := fmt.Fprintf(w.writer, `data: {"type":"message_start","message":{"id":"assistant","type":"message","role":"assistant","content":[],"model":%s,"stop_reason":null,"stop_sequence":null}}`+"\n\n", strconv.Quote(model))
	return err
}

func (w *sseEventWriter) writeContentBlockDelta(index int, deltaType string, text string) error {
	_, err := fmt.Fprintf(w.writer, `data: {"type":"content_block_delta","index":%d,"delta":{"type":%s,"text":%s}}`+"\n\n", index, strconv.Quote(deltaType), strconv.Quote(text))
	return err
}

func (w *sseEventWriter) writeContentBlockStop(index int) error {
	_, err := fmt.Fprintf(w.writer, `data: {"type":"content_block_stop","index":%d}`+"\n\n", index)
	return err
}

func (w *sseEventWriter) writeContentBlockStart(index int, block interface{}) error {
	blockJSON, err := json.Marshal(block)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w.writer, `data: {"type":"content_block_start","index":%d,"content_block":%s}`+"\n\n", index, string(blockJSON))
	return err
}

func (w *sseEventWriter) writeInputJsonDelta(index int, partialJSON string) error {
	_, err := fmt.Fprintf(w.writer, `data: {"type":"content_block_delta","index":%d,"delta":{"type":"input_json_delta","partial_json":%s}}`+"\n\n", index, strconv.Quote(partialJSON))
	return err
}

func (w *sseEventWriter) writeStopReason(reason string) error {
	_, err := fmt.Fprintf(w.writer, `data: {"type":"message_delta","delta":{"stop_reason":%s,"stop_sequence":null}}`+"\n\n", strconv.Quote(reason))
	return err
}

func (w *sseEventWriter) writeUsage(inputTokens, outputTokens int64) error {
	_, err := fmt.Fprintf(w.writer, `data: {"type":"message_delta","usage":{"input_tokens":%d,"output_tokens":%d}}`+"\n\n", inputTokens, outputTokens)
	return err
}

func (w *sseEventWriter) writeMessageStop() error {
	_, err := fmt.Fprint(w.writer, `data: {"type":"message_stop"}`+"\n\n")
	return err
}

func (w *sseEventWriter) writeDone() error {
	_, err := fmt.Fprint(w.writer, `data: [DONE]`)
	return err
}

func (w *sseEventWriter) writeError(message string) error {
	_, err := fmt.Fprintf(w.writer, `data: {"type":"error","message":%s}`+"\n\n", strconv.Quote(message))
	w.logger.WithError(errors.New(message)).Error("writing error event to SSE stream")

	return err
}

// streamProcessor processes response chunks and manages streaming state
type streamProcessor struct {
	writer               *sseEventWriter
	model                string
	wg                   *sync.WaitGroup
	contentBlockIndex    int
	hasOpenBlock         bool
	firstSend            bool
	writingOpenAIToolUse bool
}

func newStreamProcessor(writer *sseEventWriter, model string, wg *sync.WaitGroup) *streamProcessor {
	return &streamProcessor{
		writer:            writer,
		model:             model,
		wg:                wg,
		contentBlockIndex: 0,
		hasOpenBlock:      false,
		firstSend:         true,
	}
}

// processGeminiChunk processes a response chunk and writes appropriate events
// Returns thought signatures, finish reason, and any error that occurred
func (p *streamProcessor) processGeminiChunk(resp *genai.GenerateContentResponse) (map[string][]byte, string, error) {
	thoughtSigs := make(map[string][]byte)
	finishReason := ""

	// Extract thought
	thought := getThought(resp)
	if thought != "" {
		p.ensureFirstSend()
		p.writeThought(thought)
	}

	// Extract text
	text := resp.Text()
	if text != "" {
		p.ensureFirstSend()
		p.writeText(text)
	}

	// Extract function calls
	functionCalls := resp.FunctionCalls()
	if len(functionCalls) > 0 {
		// Close any open text/thought block
		if p.hasOpenBlock {
			p.closeOpenBlock()
		}

		// Collect thought signatures from candidates
		for _, cand := range resp.Candidates {
			for _, part := range cand.Content.Parts {
				if part.FunctionCall != nil {
					toolUseId := part.FunctionCall.ID
					if toolUseId == "" {
						toolUseId = fmt.Sprintf("toolu_%d", p.contentBlockIndex)
					}
					if part.ThoughtSignature != nil {
						thoughtSigs[toolUseId] = part.ThoughtSignature
					}
				}
			}

			if cand.FinishReason != "" {
				finishReason = string(cand.FinishReason)
			}
		}

		// Write function calls
		sigs := p.writeGeminiFunctionCalls(functionCalls)
		for id, sig := range sigs {
			thoughtSigs[id] = sig
		}
	}

	// Check for finish reason in candidates
	for _, cand := range resp.Candidates {
		if cand.FinishReason != "" {
			finishReason = string(cand.FinishReason)
			break
		}
	}

	return thoughtSigs, finishReason, nil
}

func (p *streamProcessor) processOpenAIChunk(resp responses.ResponseStreamEventUnion) (map[string][]byte, error) {
	thoughtSigs := make(map[string][]byte)

	content := resp.Delta

	switch resp.Type {
	case "response.reasoning_text.delta", "response.reasoning_summary_text.delta":
		if content != "" {
			p.ensureFirstSend()
			p.writeThought(content)
		}
	case "response.output_text.delta":
		if content != "" {
			p.ensureFirstSend()
			p.writeText(content)
		}
	case "response.output_item.added":
		if resp.Item.Type == "function_call" {
			if p.hasOpenBlock {
				p.closeOpenBlock()
			}

			callId := resp.Item.CallID
			name := resp.Item.Name

			p.writeOpenAIFunctionHeader(callId, name)
		}
	case "response.function_call_arguments.delta":
		if p.hasOpenBlock {
			p.writeOpenAIFunctionInput(content)
		}
	case "response.output_item.done":
		if p.writingOpenAIToolUse {
			p.writeOpenAIFunctionStop()
		}
	}

	return thoughtSigs, nil

}

// writeError writes an error event and done message
func (p *streamProcessor) writeError(err error) {
	p.writer.writeError(err.Error())
	p.writer.writeDone()
}

// finalizeGemini closes any open blocks and writes final events
func (p *streamProcessor) finalizeGemini(finishReason string, usage *genai.GenerateContentResponseUsageMetadata) {
	if p.hasOpenBlock {
		p.closeOpenBlock()
	}

	if finishReason == "" {
		finishReason = "end_turn"
	}

	p.writer.writeStopReason(finishReason)
	if usage != nil {
		p.writer.writeUsage(int64(usage.PromptTokenCount), int64(usage.CandidatesTokenCount))
	}
	p.writer.writeMessageStop()
	p.writer.writeDone()
}

// finalizeOpenAI closes any open blocks and writes final events
func (p *streamProcessor) finalizeOpenAI(finishReason string, usage responses.ResponseUsage) {
	if p.hasOpenBlock {
		p.closeOpenBlock()
	}

	if finishReason == "" {
		finishReason = "end_turn"
	}

	p.writer.writeStopReason(finishReason)
	p.writer.writeUsage(int64(usage.InputTokens), int64(usage.OutputTokens))

	p.writer.writeMessageStop()
	p.writer.writeDone()
}

// ensureFirstSend handles first send ceremony (only once)
func (p *streamProcessor) ensureFirstSend() {
	if p.firstSend {
		p.wg.Done()
		p.firstSend = false
		p.writer.writeMessageStart(p.model)
	}
}

// writeThought writes a thought delta
func (p *streamProcessor) writeThought(thought string) {
	p.writer.writeContentBlockDelta(p.contentBlockIndex, "thought_delta", thought)
	p.hasOpenBlock = true
}

// writeText writes a text delta
func (p *streamProcessor) writeText(text string) {
	p.writer.writeContentBlockDelta(p.contentBlockIndex, "text_delta", text)
	p.hasOpenBlock = true
}

// writeGeminiFunctionCalls writes function call blocks and returns their thought signatures
func (p *streamProcessor) writeGeminiFunctionCalls(functionCalls []*genai.FunctionCall) map[string][]byte {
	thoughtSigs := make(map[string][]byte)

	for _, fc := range functionCalls {
		p.ensureFirstSend()

		toolUseId := fc.ID
		if toolUseId == "" {
			toolUseId = fmt.Sprintf("toolu_%d", p.contentBlockIndex)
		}

		toolUseBlock := map[string]any{
			"type":  "tool_use",
			"id":    toolUseId,
			"name":  fc.Name,
			"input": map[string]any{},
		}
		p.writer.writeContentBlockStart(p.contentBlockIndex, toolUseBlock)

		// Send function arguments as input_json_delta
		if len(fc.Args) > 0 {
			argsJSON, err := json.Marshal(fc.Args)
			if err == nil {
				p.writer.writeInputJsonDelta(p.contentBlockIndex, string(argsJSON))
			}
		}

		p.writer.writeContentBlockStop(p.contentBlockIndex)
		p.contentBlockIndex++
	}

	return thoughtSigs
}

func (p *streamProcessor) writeOpenAIFunctionHeader(id string, name string) {
	p.ensureFirstSend()

	if id == "" {
		id = fmt.Sprintf("toolu_%d", p.contentBlockIndex)
	}

	toolUseBlock := map[string]any{
		"type":  "tool_use",
		"id":    id,
		"name":  name,
		"input": map[string]any{},
	}

	p.writer.writeContentBlockStart(p.contentBlockIndex, toolUseBlock)
	p.hasOpenBlock = true
	p.writingOpenAIToolUse = true
}

func (p *streamProcessor) writeOpenAIFunctionInput(input string) {
	p.writer.writeInputJsonDelta(p.contentBlockIndex, input)
}

func (p *streamProcessor) writeOpenAIFunctionStop() {
	p.writer.writeContentBlockStop(p.contentBlockIndex)
	p.contentBlockIndex++
	p.hasOpenBlock = false
	p.writingOpenAIToolUse = false
}

// closeOpenBlock closes the currently open text/thought block
func (p *streamProcessor) closeOpenBlock() {
	if p.hasOpenBlock {
		p.writer.writeContentBlockStop(p.contentBlockIndex)
		p.contentBlockIndex++
		p.hasOpenBlock = false
	}
}

// processChatCompletionChunk processes a ChatCompletionChunk and writes appropriate events
func (p *streamProcessor) processChatCompletionChunk(chunk openai.ChatCompletionChunk) error {
	if len(chunk.Choices) == 0 {
		return nil
	}

	delta := chunk.Choices[0].Delta
	reasoning, ok := extractReasoning(delta)

	if ok && reasoning != "" {
		p.ensureFirstSend()
		p.writeThought(reasoning)
	}

	// Handle text content delta
	if delta.Content != "" {
		p.ensureFirstSend()
		p.writeText(delta.Content)
	}

	// Handle tool calls
	if len(delta.ToolCalls) > 0 {
		for _, toolCall := range delta.ToolCalls {
			// Check if this is a new tool call (has ID and Name)
			if toolCall.ID != "" && toolCall.Function.Name != "" {
				// Close any open text block
				if p.hasOpenBlock {
					p.closeOpenBlock()
				}

				p.writeChatCompletionFunctionHeader(toolCall.ID, toolCall.Function.Name)
			}
			if toolCall.Function.Arguments != "" {
				// This is a delta for function arguments
				p.writeChatCompletionFunctionInput(toolCall.Function.Arguments)
			}
		}
	}

	return nil
}

// writeChatCompletionFunctionHeader writes the start of a function call for ChatCompletion streaming
func (p *streamProcessor) writeChatCompletionFunctionHeader(id string, name string) {
	p.ensureFirstSend()

	if id == "" {
		id = fmt.Sprintf("toolu_%d", p.contentBlockIndex)
	}

	toolUseBlock := map[string]any{
		"type":  "tool_use",
		"id":    id,
		"name":  name,
		"input": map[string]any{},
	}

	p.writer.writeContentBlockStart(p.contentBlockIndex, toolUseBlock)
	p.hasOpenBlock = true
	p.writingOpenAIToolUse = true
}

// writeChatCompletionFunctionInput writes function arguments delta for ChatCompletion streaming
func (p *streamProcessor) writeChatCompletionFunctionInput(arguments string) {
	p.writer.writeInputJsonDelta(p.contentBlockIndex, arguments)
}

// writeChatCompletionFunctionStop closes a function call block for ChatCompletion streaming
func (p *streamProcessor) writeChatCompletionFunctionStop() {
	p.writer.writeContentBlockStop(p.contentBlockIndex)
	p.contentBlockIndex++
	p.hasOpenBlock = false
	p.writingOpenAIToolUse = false
}

// finalizeChatCompletion closes any open blocks and writes final events for ChatCompletion streaming
func (p *streamProcessor) finalizeChatCompletion(finishReason string, usage *openai.CompletionUsage) {
	if p.hasOpenBlock {
		if p.writingOpenAIToolUse {
			p.writeChatCompletionFunctionStop()
		} else {
			p.closeOpenBlock()
		}
	}

	if finishReason == "" || finishReason == "stop" {
		finishReason = "end_turn"
	}

	p.writer.writeStopReason(finishReason)

	if usage != nil && (usage.PromptTokens > 0 || usage.CompletionTokens > 0) {
		p.writer.writeUsage(usage.PromptTokens, usage.CompletionTokens)
	}

	p.writer.writeMessageStop()
	p.writer.writeDone()
}

func extractReasoning(delta openai.ChatCompletionChunkChoiceDelta) (string, bool) {
	fieldNames := []string{"reasoning", "reasoning_content", "reasoning_summary"}
	for _, fieldName := range fieldNames {
		reasoningField, ok := delta.JSON.ExtraFields[fieldName]
		if ok {
			reasoning := reasoningField.Raw()
			if !reasoningField.Valid() {
				reasoning, _ = strconv.Unquote(reasoning)
			}
			if reasoning != "" {
				return reasoning, true
			}
		}
	}

	return "", false
}
