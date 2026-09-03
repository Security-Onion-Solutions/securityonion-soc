package assistant

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"

	"github.com/apex/log"
	"github.com/google/uuid"
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
	_, err := fmt.Fprintf(w.writer, `data: {"type":"message_start","message":{"type":"message","role":"assistant","content":[],"model":%s,"stop_reason":null,"stop_sequence":null}}`+"\n\n", strconv.Quote(model))
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
	// Nest the message under "error" so both server.UnstreamResponse (sm.Error.Message)
	// and the UI's SSE handler (c.error.message) can read it.
	_, err := fmt.Fprintf(w.writer, `data: {"type":"error","error":{"type":"error","message":%s}}`+"\n\n", strconv.Quote(message))
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
	receivedFnArgs       bool
	// Identity of the open tool_use block (Responses output index / chat tool-call
	// index, and the call id); a repeated header for the same call must not reopen it.
	// The id is only consulted on the chat-completions path.
	openToolCallIndex int64
	openToolCallId    string
	// An announced Responses function_call whose header is not written until it
	// proves real (arguments arrive or it finishes typed as a function_call).
	pending *pendingCall
}

type pendingCall struct {
	index int64
	id    string
	name  string
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

	// Extract function calls from the first candidate only, matching the SDK helpers
	// (Text(), FunctionCalls()) — additional candidates are alternative completions,
	// not parts of this response.
	functionCalls := resp.FunctionCalls()
	if len(functionCalls) > 0 {
		// Close any open text/thought block
		if p.hasOpenBlock {
			p.closeOpenBlock()
		}

		// Write each function-call block and collect its thought signature keyed by
		// the same id the block was assigned, so UnstreamResponse can re-attach it.
		// The FunctionCalls() gate above guarantees Candidates[0].Content is non-nil.
		thoughtSigs = p.writeGeminiFunctionCalls(resp.Candidates[0].Content.Parts)
	}

	// Check for finish reason
	if len(resp.Candidates) > 0 && resp.Candidates[0].FinishReason != "" {
		finishReason = string(resp.Candidates[0].FinishReason)
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
			toolOpen := p.hasOpenBlock && p.writingOpenAIToolUse
			// A proxy may announce the same item more than once; only a different
			// output index is a new call.
			if (toolOpen && resp.OutputIndex == p.openToolCallIndex) || (p.pending != nil && resp.OutputIndex == p.pending.index) {
				break
			}
			if toolOpen {
				p.closeOpenBlock()
			}
			// Announce only: LiteLLM emits phantom function_call items it then closes as
			// message items, so the header waits for arguments to prove the call real.
			p.dropPendingFunction()
			p.pending = &pendingCall{index: resp.OutputIndex, id: resp.Item.CallID, name: resp.Item.Name}
		}
	case "response.function_call_arguments.delta":
		if content == "" && resp.Arguments != "" {
			content = resp.Arguments
		}
		if content == "" {
			break
		}
		p.openPendingFunction()
		if p.hasOpenBlock && p.writingOpenAIToolUse {
			p.receivedFnArgs = true
			p.writeFunctionInput(content)
		}
	case "response.function_call_arguments.done":
		// Only use .done arguments if no deltas were received (some models skip deltas)
		if content == "" && resp.Arguments != "" {
			content = resp.Arguments
		}
		if content == "" {
			break
		}
		p.openPendingFunction()
		if p.hasOpenBlock && p.writingOpenAIToolUse && !p.receivedFnArgs {
			p.receivedFnArgs = true
			p.writeFunctionInput(content)
		}
	case "response.output_item.done":
		isFn := resp.Item.Type == "function_call"
		if p.hasOpenBlock && p.writingOpenAIToolUse {
			// Only this call finishing closes it: another item (message, reasoning) or a
			// late done for an earlier index must not.
			if isFn && resp.OutputIndex == p.openToolCallIndex {
				// Some proxies carry the arguments only on the finished item.
				if !p.receivedFnArgs && resp.Item.Arguments.OfString != "" {
					p.writeFunctionInput(resp.Item.Arguments.OfString)
				}
				p.closeOpenBlock()
			}
			break
		}
		if p.pending != nil && resp.OutputIndex == p.pending.index {
			if isFn {
				// A real call that streamed no arguments (or carries them here).
				p.openPendingFunction()
				if resp.Item.Arguments.OfString != "" {
					p.writeFunctionInput(resp.Item.Arguments.OfString)
				}
				p.closeOpenBlock()
			} else {
				p.dropPendingFunction()
			}
		}
	}

	return thoughtSigs, nil
}

// openPendingFunction writes the header for an announced call once it has proven
// real. A text/thought block still open closes here rather than at announcement.
func (p *streamProcessor) openPendingFunction() {
	if p.pending == nil {
		return
	}
	p.closeOpenBlock()
	p.writeFunctionHeader(p.pending.index, p.pending.id, p.pending.name)
	p.pending = nil
}

func (p *streamProcessor) dropPendingFunction() {
	if p.pending == nil {
		return
	}
	p.pendingEntry().Debug("function_call announcement never received arguments; dropped")
	p.pending = nil
}

func (p *streamProcessor) pendingEntry() *log.Entry {
	return p.writer.logger.WithFields(log.Fields{
		"callId":      p.pending.id,
		"outputIndex": p.pending.index,
	})
}

// writeError writes an error event and done message
func (p *streamProcessor) writeError(err error) {
	// Pipe writes block until the caller starts reading the response body, so
	// the caller must be released before the first write on every path.
	p.releaseCaller()

	p.writer.writeError(err.Error())
	p.writer.writeDone()
}

func (p *streamProcessor) finalize(finishReason string) {
	p.ensureFirstSend()

	p.closeOpenBlock()
	if p.pending != nil {
		// A phantom is closed as a message item mid-stream; one still pending here means
		// the provider announced a call it never argued or finished, and it is lost.
		p.pendingEntry().Warn("stream ended with an announced function_call that never received arguments; dropped")
		p.pending = nil
	}

	if finishReason == "" {
		finishReason = "end_turn"
	}

	p.writer.writeStopReason(finishReason)
}

// finalizeGemini closes any open blocks and writes final events
func (p *streamProcessor) finalizeGemini(finishReason string, usage *genai.GenerateContentResponseUsageMetadata) {
	// An empty stream reaches finalize without any content event; emit the
	// message_start (which also releases the blocked caller) so the SSE stream
	// stays well-formed for UnstreamResponse.
	p.finalize(finishReason)

	if usage != nil {
		p.writer.writeUsage(int64(usage.PromptTokenCount), int64(usage.CandidatesTokenCount))
	}
	p.writer.writeMessageStop()
	p.writer.writeDone()
}

// finalizeOpenAI closes any open blocks and writes final events
func (p *streamProcessor) finalizeOpenAI(finishReason string, usage responses.ResponseUsage) {
	// See finalizeGemini: empty streams must still release the caller and emit
	// a well-formed message_start.
	p.finalize(finishReason)

	p.writer.writeUsage(int64(usage.InputTokens), int64(usage.OutputTokens))

	p.writer.writeMessageStop()
	p.writer.writeDone()
}

// ensureFirstSend handles first send ceremony (only once)
func (p *streamProcessor) ensureFirstSend() {
	if p.firstSend {
		p.releaseCaller()
		p.writer.writeMessageStart(p.model)
	}
}

// releaseCaller unblocks the SendMessageStream caller waiting on wg for the
// first event. ensureFirstSend covers the normal path; adapters must ALSO
// defer this in their stream goroutine so exits before any content — a
// first-chunk error or an empty stream — can't leave the caller blocked on
// wg.Wait forever. Safe to call more than once.
func (p *streamProcessor) releaseCaller() {
	if p.firstSend {
		p.firstSend = false
		p.wg.Done()
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

// writeGeminiFunctionCalls writes a content block for each function-call part and
// returns the parts' thought signatures keyed by the id assigned to each block.
// It takes the raw parts (not just the function calls) because the thought
// signature lives on the part alongside its function call: minting the id here and
// keying the signature by that same id keeps the block id and the signature key in
// lockstep, which is what UnstreamResponse relies on to re-attach signatures.
func (p *streamProcessor) writeGeminiFunctionCalls(parts []*genai.Part) map[string][]byte {
	thoughtSigs := make(map[string][]byte)

	for _, part := range parts {
		fc := part.FunctionCall
		if fc == nil {
			continue
		}
		p.ensureFirstSend()

		toolUseId := fc.ID
		if toolUseId == "" {
			// Gemini doesn't supply call ids; mint a unique one so the frontend's
			// id-keyed lookups don't collide across turns. Generated once here and
			// reused below as the thought-signature key, so the two always agree.
			toolUseId = "toolu_" + uuid.NewString()
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

		if part.ThoughtSignature != nil {
			thoughtSigs[toolUseId] = part.ThoughtSignature
		}
	}

	return thoughtSigs
}

// writeFunctionHeader opens a tool_use block for a Responses or ChatCompletion call.
func (p *streamProcessor) writeFunctionHeader(index int64, id string, name string) {
	p.ensureFirstSend()

	if id == "" {
		id = "toolu_" + uuid.NewString()
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
	p.receivedFnArgs = false
	p.openToolCallIndex = index
	p.openToolCallId = id
}

func (p *streamProcessor) writeFunctionInput(input string) {
	p.writer.writeInputJsonDelta(p.contentBlockIndex, input)
}

// closeOpenBlock closes the open text, thought, or tool_use block, if any. It also
// drops the tool-call state so a later item event can't act on a closed block.
func (p *streamProcessor) closeOpenBlock() {
	if !p.hasOpenBlock {
		return
	}
	p.writer.writeContentBlockStop(p.contentBlockIndex)
	p.contentBlockIndex++
	p.hasOpenBlock = false
	p.writingOpenAIToolUse = false
	p.receivedFnArgs = false
	p.openToolCallIndex = 0
	p.openToolCallId = ""
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

	for _, toolCall := range delta.ToolCalls {
		// Some providers repeat id+name on every argument chunk (or send a header-only
		// chunk first), so a header opens a block only when it names a different call:
		// a new non-empty id, or a new index under the same or absent id.
		toolOpen := p.hasOpenBlock && p.writingOpenAIToolUse
		isHeader := toolCall.ID != "" || toolCall.Function.Name != ""
		sameCall := toolOpen && (toolCall.ID == "" || toolCall.ID == p.openToolCallId) && toolCall.Index == p.openToolCallIndex
		if isHeader && !sameCall {
			p.closeOpenBlock()
			p.writeFunctionHeader(toolCall.Index, toolCall.ID, toolCall.Function.Name)
		}
		if toolCall.Function.Arguments != "" {
			p.writeFunctionInput(toolCall.Function.Arguments)
		}
	}

	return nil
}

// finalizeChatCompletion closes any open blocks and writes final events for ChatCompletion streaming
func (p *streamProcessor) finalizeChatCompletion(finishReason string, usage *openai.CompletionUsage) {
	// See finalizeGemini: empty streams must still release the caller and emit
	// a well-formed message_start.
	p.ensureFirstSend()

	p.closeOpenBlock()

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

func fabricateResponse(code int) (*http.Response, *io.PipeWriter) {
	bodyReader, bodyWriter := io.Pipe()

	response := &http.Response{
		StatusCode: code,
		Body:       bodyReader,
		Header:     make(http.Header),
	}

	response.Header.Add("Content-Type", "text/event-stream")

	return response, bodyWriter
}

// handleStreamError handles errors during streaming
// Returns a replacement response (if first send error) and whether the caller should return
func handleStreamError(err error, firstSend bool, writer *sseEventWriter, logger log.Interface, model string) (*http.Response, bool) {
	if firstSend {
		// No response sent yet: fabricate a 200 SSE stream carrying the real error as an
		// "error" event so UnstreamResponse parses it and the UI can render it, rather
		// than an opaque sentinel body.
		logger.WithFields(log.Fields{
			"model": model,
		}).WithError(err).Error("first response error from the LLM")

		response, body := fabricateResponse(http.StatusOK)
		errWriter := newSSEEventWriter(logger, body)

		// Write to pipe in goroutine to avoid blocking
		go func() {
			errWriter.writeError(err.Error())
			errWriter.writeDone()
			body.Close()
		}()

		return response, true
	}

	// Error after partial response sent to client
	logger.WithFields(log.Fields{
		"model": model,
	}).WithError(err).Error("subsequent response error from the LLM")

	writer.writeError(err.Error())
	writer.writeDone()

	return nil, true
}
