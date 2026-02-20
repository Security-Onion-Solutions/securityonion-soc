package assistant

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/apex/log"
	openai "github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/responses"
	"github.com/stretchr/testify/assert"
	"google.golang.org/genai"
)

func TestSSEEventWriter(t *testing.T) {
	tests := []struct {
		name     string
		writeOp  func(*sseEventWriter) error
		expected string
	}{
		{
			name: "writeMessageStart",
			writeOp: func(w *sseEventWriter) error {
				return w.writeMessageStart("gemini-2.0-flash-exp")
			},
			expected: `data: {"type":"message_start","message":{"id":"assistant","type":"message","role":"assistant","content":[],"model":"gemini-2.0-flash-exp","stop_reason":null,"stop_sequence":null}}` + "\n\n",
		},
		{
			name: "writeMessageStart with quotes in model",
			writeOp: func(w *sseEventWriter) error {
				return w.writeMessageStart(`model"with"quotes`)
			},
			expected: `data: {"type":"message_start","message":{"id":"assistant","type":"message","role":"assistant","content":[],"model":"model\"with\"quotes","stop_reason":null,"stop_sequence":null}}` + "\n\n",
		},
		{
			name: "writeContentBlockDelta text",
			writeOp: func(w *sseEventWriter) error {
				return w.writeContentBlockDelta(0, "text_delta", "Hello World")
			},
			expected: `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello World"}}` + "\n\n",
		},
		{
			name: "writeContentBlockDelta thought",
			writeOp: func(w *sseEventWriter) error {
				return w.writeContentBlockDelta(0, "thought_delta", "Thinking about it")
			},
			expected: `data: {"type":"content_block_delta","index":0,"delta":{"type":"thought_delta","text":"Thinking about it"}}` + "\n\n",
		},
		{
			name: "writeContentBlockDelta with newlines",
			writeOp: func(w *sseEventWriter) error {
				return w.writeContentBlockDelta(1, "text_delta", "Line 1\nLine 2\tTabbed")
			},
			expected: `data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"Line 1\nLine 2\tTabbed"}}` + "\n\n",
		},
		{
			name: "writeContentBlockStop",
			writeOp: func(w *sseEventWriter) error {
				return w.writeContentBlockStop(0)
			},
			expected: `data: {"type":"content_block_stop","index":0}` + "\n\n",
		},
		{
			name: "writeInputJsonDelta",
			writeOp: func(w *sseEventWriter) error {
				return w.writeInputJsonDelta(1, `{"query":"test"}`)
			},
			expected: `data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"query\":\"test\"}"}}` + "\n\n",
		},
		{
			name: "writeStopReason",
			writeOp: func(w *sseEventWriter) error {
				return w.writeStopReason("end_turn")
			},
			expected: `data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null}}` + "\n\n",
		},
		{
			name: "writeStopReason with quotes",
			writeOp: func(w *sseEventWriter) error {
				return w.writeStopReason(`stop"reason`)
			},
			expected: `data: {"type":"message_delta","delta":{"stop_reason":"stop\"reason","stop_sequence":null}}` + "\n\n",
		},
		{
			name: "writeUsage",
			writeOp: func(w *sseEventWriter) error {
				return w.writeUsage(100, 200)
			},
			expected: `data: {"type":"message_delta","usage":{"input_tokens":100,"output_tokens":200}}` + "\n\n",
		},
		{
			name: "writeMessageStop",
			writeOp: func(w *sseEventWriter) error {
				return w.writeMessageStop()
			},
			expected: `data: {"type":"message_stop"}` + "\n\n",
		},
		{
			name: "writeDone",
			writeOp: func(w *sseEventWriter) error {
				return w.writeDone()
			},
			expected: `data: [DONE]`,
		},
		{
			name: "writeError",
			writeOp: func(w *sseEventWriter) error {
				return w.writeError("Something went wrong")
			},
			expected: `data: {"type":"error","message":"Something went wrong"}` + "\n\n",
		},
		{
			name: "writeError with special characters",
			writeOp: func(w *sseEventWriter) error {
				return w.writeError(`Error: "API" failed\nLine 2`)
			},
			expected: `data: {"type":"error","message":"Error: \"API\" failed\\nLine 2"}` + "\n\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf strings.Builder
			writer := newSSEEventWriter(log.Log, &buf)

			err := tt.writeOp(writer)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, buf.String())
		})
	}

	// Sequence tests - these test multiple operations in sequence with flexible validation
	sequenceTests := []struct {
		name          string
		writeOps      []func(*sseEventWriter) error
		contains      []string
		orderedChecks []string
	}{
		{
			name: "writeContentBlockStart with complex object",
			writeOps: []func(*sseEventWriter) error{
				func(w *sseEventWriter) error {
					block := map[string]any{
						"type":  "tool_use",
						"id":    "toolu_123",
						"name":  "search",
						"input": map[string]any{},
					}
					return w.writeContentBlockStart(1, block)
				},
			},
			contains: []string{
				`"type":"content_block_start"`,
				`"index":1`,
				`"type":"tool_use"`,
				`"id":"toolu_123"`,
				`"name":"search"`,
			},
		},
		{
			name: "full message sequence with thought and text",
			writeOps: []func(*sseEventWriter) error{
				func(w *sseEventWriter) error { return w.writeMessageStart("gemini-2.0-flash-exp") },
				func(w *sseEventWriter) error {
					return w.writeContentBlockDelta(0, "thought_delta", "Let me think about this...")
				},
				func(w *sseEventWriter) error {
					return w.writeContentBlockDelta(0, "thought_delta", " analyzing the request")
				},
				func(w *sseEventWriter) error {
					return w.writeContentBlockDelta(0, "text_delta", "Here is the answer: ")
				},
				func(w *sseEventWriter) error { return w.writeContentBlockDelta(0, "text_delta", "42") },
				func(w *sseEventWriter) error { return w.writeContentBlockStop(0) },
				func(w *sseEventWriter) error { return w.writeStopReason("end_turn") },
				func(w *sseEventWriter) error { return w.writeUsage(50, 15) },
				func(w *sseEventWriter) error { return w.writeMessageStop() },
				func(w *sseEventWriter) error { return w.writeDone() },
			},
			contains: []string{
				`"type":"message_start"`,
				`"model":"gemini-2.0-flash-exp"`,
				`"type":"thought_delta","text":"Let me think about this..."`,
				`"type":"thought_delta","text":" analyzing the request"`,
				`"type":"text_delta","text":"Here is the answer: "`,
				`"type":"text_delta","text":"42"`,
				`"type":"content_block_stop","index":0`,
				`"stop_reason":"end_turn"`,
				`"input_tokens":50,"output_tokens":15`,
				`"type":"message_stop"`,
				`data: [DONE]`,
			},
			orderedChecks: []string{
				"thought_delta",
				"text_delta",
				"content_block_stop",
				"[DONE]",
			},
		},
		{
			name: "full message sequence with function call",
			writeOps: []func(*sseEventWriter) error{
				func(w *sseEventWriter) error { return w.writeMessageStart("gemini-2.0-flash-exp") },
				func(w *sseEventWriter) error {
					return w.writeContentBlockDelta(0, "text_delta", "I'll search for that.")
				},
				func(w *sseEventWriter) error { return w.writeContentBlockStop(0) },
				func(w *sseEventWriter) error {
					toolBlock := map[string]any{
						"type":  "tool_use",
						"id":    "toolu_abc123",
						"name":  "web_search",
						"input": map[string]any{},
					}
					return w.writeContentBlockStart(1, toolBlock)
				},
				func(w *sseEventWriter) error {
					return w.writeInputJsonDelta(1, `{"query":"test search"}`)
				},
				func(w *sseEventWriter) error { return w.writeContentBlockStop(1) },
				func(w *sseEventWriter) error { return w.writeStopReason("tool_use") },
				func(w *sseEventWriter) error { return w.writeUsage(30, 25) },
				func(w *sseEventWriter) error { return w.writeMessageStop() },
				func(w *sseEventWriter) error { return w.writeDone() },
			},
			contains: []string{
				`"type":"message_start"`,
				`"type":"text_delta","text":"I'll search for that."`,
				`"type":"content_block_stop","index":0`,
				`"type":"content_block_start"`,
				`"type":"tool_use"`,
				`"id":"toolu_abc123"`,
				`"name":"web_search"`,
				`"input_json_delta"`,
				`"type":"content_block_stop","index":1`,
				`"stop_reason":"tool_use"`,
				`data: [DONE]`,
			},
		},
	}

	for _, tt := range sequenceTests {
		t.Run(tt.name, func(t *testing.T) {
			var buf strings.Builder
			writer := newSSEEventWriter(log.Log, &buf)

			// Execute sequence of operations
			for _, op := range tt.writeOps {
				err := op(writer)
				assert.NoError(t, err)
			}

			result := buf.String()

			// Validate contains
			for _, expected := range tt.contains {
				assert.Contains(t, result, expected)
			}

			// Validate ordering if specified
			if len(tt.orderedChecks) > 0 {
				lastIndex := -1
				for _, expected := range tt.orderedChecks {
					currentIndex := strings.Index(result, expected)
					assert.Less(t, lastIndex, currentIndex,
						fmt.Sprintf("%s should come after previous element", expected))
					lastIndex = currentIndex
				}
			}
		})
	}
}

func TestStreamProcessorFirstSend(t *testing.T) {
	tests := []struct {
		name              string
		resp              *genai.GenerateContentResponse
		expectedInOutput  []string
		shouldTriggerSend bool
	}{
		{
			name: "first send on thought delta",
			resp: &genai.GenerateContentResponse{
				Candidates: []*genai.Candidate{
					{
						Content: &genai.Content{
							Parts: []*genai.Part{
								{Text: "thinking...", Thought: true},
							},
						},
					},
				},
			},
			expectedInOutput:  []string{`"type":"message_start"`, `"model":"test-model"`, `"type":"thought_delta"`, `"text":"thinking..."`},
			shouldTriggerSend: true,
		},
		{
			name: "first send on text delta",
			resp: &genai.GenerateContentResponse{
				Candidates: []*genai.Candidate{
					{
						Content: &genai.Content{
							Parts: []*genai.Part{
								{Text: "Hello world"},
							},
						},
					},
				},
			},
			expectedInOutput:  []string{`"type":"message_start"`, `"type":"text_delta"`, `"text":"Hello world"`},
			shouldTriggerSend: true,
		},
		{
			name: "first send only happens once",
			resp: &genai.GenerateContentResponse{
				Candidates: []*genai.Candidate{
					{
						Content: &genai.Content{
							Parts: []*genai.Part{
								{Text: "First"},
							},
						},
					},
				},
			},
			expectedInOutput:  []string{`"type":"message_start"`},
			shouldTriggerSend: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf strings.Builder
			writer := newSSEEventWriter(log.Log, &buf)
			wg := &sync.WaitGroup{}
			wg.Add(1)
			processor := newStreamProcessor(writer, "test-model", wg)

			thoughtSigs, reason, err := processor.processGeminiChunk(tt.resp)
			assert.NoError(t, err)
			assert.Empty(t, thoughtSigs)
			assert.Empty(t, reason)

			if tt.shouldTriggerSend {
				wg.Wait()
			}

			output := buf.String()
			for _, expected := range tt.expectedInOutput {
				assert.Contains(t, output, expected)
			}

			// Special check for "only happens once" test
			if tt.name == "first send only happens once" {
				// Send second chunk
				resp2 := &genai.GenerateContentResponse{
					Candidates: []*genai.Candidate{
						{
							Content: &genai.Content{
								Parts: []*genai.Part{
									{Text: " Second"},
								},
							},
						},
					},
				}
				processor.processGeminiChunk(resp2)

				output = buf.String()
				count := strings.Count(output, `"type":"message_start"`)
				assert.Equal(t, 1, count, "message_start should only appear once")
			}
		})
	}
}

func TestStreamProcessorContentProcessing(t *testing.T) {
	tests := []struct {
		name             string
		resp             *genai.GenerateContentResponse
		expectedInOutput []string
		expectOpenBlock  bool
	}{
		{
			name: "thought processing",
			resp: &genai.GenerateContentResponse{
				Candidates: []*genai.Candidate{
					{
						Content: &genai.Content{
							Parts: []*genai.Part{
								{Text: "Let me think about this", Thought: true},
							},
						},
					},
				},
			},
			expectedInOutput: []string{`"type":"thought_delta"`, `"text":"Let me think about this"`},
			expectOpenBlock:  true,
		},
		{
			name: "text processing",
			resp: &genai.GenerateContentResponse{
				Candidates: []*genai.Candidate{
					{
						Content: &genai.Content{
							Parts: []*genai.Part{
								{Text: "Here is the answer"},
							},
						},
					},
				},
			},
			expectedInOutput: []string{`"type":"text_delta"`, `"text":"Here is the answer"`},
			expectOpenBlock:  true,
		},
		{
			name: "mixed thought and text",
			resp: &genai.GenerateContentResponse{
				Candidates: []*genai.Candidate{
					{
						Content: &genai.Content{
							Parts: []*genai.Part{
								{Text: "thinking...", Thought: true},
								{Text: "answer here"},
							},
						},
					},
				},
			},
			expectedInOutput: []string{`"type":"thought_delta"`, `"thinking..."`, `"type":"text_delta"`, `"answer here"`},
			expectOpenBlock:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf strings.Builder
			writer := newSSEEventWriter(log.Log, &buf)
			wg := &sync.WaitGroup{}
			wg.Add(1)
			processor := newStreamProcessor(writer, "test-model", wg)

			processor.processGeminiChunk(tt.resp)
			wg.Wait()

			output := buf.String()
			for _, expected := range tt.expectedInOutput {
				assert.Contains(t, output, expected)
			}
			assert.Equal(t, tt.expectOpenBlock, processor.hasOpenBlock)
		})
	}
}

func TestStreamProcessorFunctionCallClosesTextBlock(t *testing.T) {
	var buf strings.Builder
	writer := newSSEEventWriter(log.Log, &buf)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	processor := newStreamProcessor(writer, "test-model", wg)

	resp1 := &genai.GenerateContentResponse{
		Candidates: []*genai.Candidate{
			{
				Content: &genai.Content{
					Parts: []*genai.Part{
						{Text: "I'll search for that"},
					},
				},
			},
		},
	}
	processor.processGeminiChunk(resp1)
	wg.Wait()

	initialIndex := processor.contentBlockIndex
	assert.True(t, processor.hasOpenBlock)

	resp2 := &genai.GenerateContentResponse{
		Candidates: []*genai.Candidate{
			{
				Content: &genai.Content{
					Parts: []*genai.Part{
						{
							FunctionCall: &genai.FunctionCall{
								ID:   "call_123",
								Name: "web_search",
								Args: map[string]any{"query": "test"},
							},
							ThoughtSignature: []byte("signature_data"),
						},
					},
				},
				FinishReason: "tool_use",
			},
		},
	}

	thoughtSigs, reason, err := processor.processGeminiChunk(resp2)
	assert.NoError(t, err)
	assert.Equal(t, "tool_use", reason)
	assert.Contains(t, thoughtSigs, "call_123")
	assert.Equal(t, []byte("signature_data"), thoughtSigs["call_123"])

	output := buf.String()
	assert.Contains(t, output, `"type":"content_block_stop"`)
	assert.Contains(t, output, `"type":"content_block_start"`)
	assert.Contains(t, output, `"type":"tool_use"`)
	assert.Contains(t, output, `"name":"web_search"`)
	assert.Contains(t, output, `"input_json_delta"`)

	assert.False(t, processor.hasOpenBlock)
	assert.Greater(t, processor.contentBlockIndex, initialIndex)
}

func TestStreamProcessorFunctionCallWithNoID(t *testing.T) {
	var buf strings.Builder
	writer := newSSEEventWriter(log.Log, &buf)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	processor := newStreamProcessor(writer, "test-model", wg)

	resp := &genai.GenerateContentResponse{
		Candidates: []*genai.Candidate{
			{
				Content: &genai.Content{
					Parts: []*genai.Part{
						{
							FunctionCall: &genai.FunctionCall{
								ID:   "",
								Name: "search",
								Args: map[string]any{},
							},
							ThoughtSignature: []byte("sig"),
						},
					},
				},
			},
		},
	}

	thoughtSigs, _, err := processor.processGeminiChunk(resp)
	assert.NoError(t, err)
	assert.Len(t, thoughtSigs, 1)

	foundGeneratedID := false
	for id := range thoughtSigs {
		if strings.HasPrefix(id, "toolu_") {
			foundGeneratedID = true
		}
	}
	assert.True(t, foundGeneratedID)
}

func TestStreamProcessorMultipleFunctionCalls(t *testing.T) {
	var buf strings.Builder
	writer := newSSEEventWriter(log.Log, &buf)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	processor := newStreamProcessor(writer, "test-model", wg)

	resp := &genai.GenerateContentResponse{
		Candidates: []*genai.Candidate{
			{
				Content: &genai.Content{
					Parts: []*genai.Part{
						{
							FunctionCall: &genai.FunctionCall{
								ID:   "call_1",
								Name: "search",
								Args: map[string]any{"query": "foo"},
							},
						},
						{
							FunctionCall: &genai.FunctionCall{
								ID:   "call_2",
								Name: "calculate",
								Args: map[string]any{"expr": "2+2"},
							},
						},
					},
				},
			},
		},
	}

	processor.processGeminiChunk(resp)
	wg.Wait()

	output := buf.String()
	count := strings.Count(output, `"type":"tool_use"`)
	assert.Equal(t, 2, count)
	assert.Contains(t, output, `"name":"search"`)
	assert.Contains(t, output, `"name":"calculate"`)
}

func TestStreamProcessorMidStreamError(t *testing.T) {
	var buf strings.Builder
	writer := newSSEEventWriter(log.Log, &buf)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	processor := newStreamProcessor(writer, "test-model", wg)

	resp := &genai.GenerateContentResponse{
		Candidates: []*genai.Candidate{
			{
				Content: &genai.Content{
					Parts: []*genai.Part{
						{Text: "Starting to respond"},
					},
				},
			},
		},
	}
	processor.processGeminiChunk(resp)
	wg.Wait()

	processor.writeError(fmt.Errorf("connection lost"))

	output := buf.String()
	assert.Contains(t, output, `"type":"error"`)
	assert.Contains(t, output, `"message":"connection lost"`)
	assert.Contains(t, output, `data: [DONE]`)
}

func TestStreamProcessorFinalize(t *testing.T) {
	tests := []struct {
		name             string
		setupProcessor   func(*streamProcessor)
		finishReason     string
		usage            *genai.GenerateContentResponseUsageMetadata
		expectedInOutput []string
		notInOutput      []string
	}{
		{
			name: "finalize with open block",
			setupProcessor: func(p *streamProcessor) {
				resp := &genai.GenerateContentResponse{
					Candidates: []*genai.Candidate{
						{
							Content: &genai.Content{
								Parts: []*genai.Part{
									{Text: "Response text"},
								},
							},
						},
					},
				}
				p.processGeminiChunk(resp)
			},
			finishReason: "end_turn",
			usage: &genai.GenerateContentResponseUsageMetadata{
				PromptTokenCount:     100,
				CandidatesTokenCount: 50,
			},
			expectedInOutput: []string{`"type":"content_block_stop"`, `"stop_reason":"end_turn"`, `"input_tokens":100`, `"output_tokens":50`, `"type":"message_stop"`, `data: [DONE]`},
		},
		{
			name:           "finalize without open block",
			setupProcessor: func(p *streamProcessor) {},
			finishReason:   "end_turn",
			usage: &genai.GenerateContentResponseUsageMetadata{
				PromptTokenCount:     10,
				CandidatesTokenCount: 5,
			},
			expectedInOutput: []string{`"stop_reason":"end_turn"`, `"input_tokens":10`, `"output_tokens":5`, `data: [DONE]`},
			notInOutput:      []string{`"type":"content_block_stop"`},
		},
		{
			name:             "finalize with nil usage",
			setupProcessor:   func(p *streamProcessor) {},
			finishReason:     "end_turn",
			usage:            nil,
			expectedInOutput: []string{`"stop_reason":"end_turn"`, `data: [DONE]`},
			notInOutput:      []string{`"input_tokens"`, `"output_tokens"`},
		},
		{
			name:             "finalize with empty finish reason uses default",
			setupProcessor:   func(p *streamProcessor) {},
			finishReason:     "",
			usage:            nil,
			expectedInOutput: []string{`"stop_reason":"end_turn"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf strings.Builder
			writer := newSSEEventWriter(log.Log, &buf)
			wg := &sync.WaitGroup{}
			wg.Add(1)
			processor := newStreamProcessor(writer, "test-model", wg)

			tt.setupProcessor(processor)
			if processor.firstSend {
				wg.Done()
			} else {
				wg.Wait()
			}

			processor.finalizeGemini(tt.finishReason, tt.usage)

			output := buf.String()
			for _, expected := range tt.expectedInOutput {
				assert.Contains(t, output, expected)
			}
			for _, notExpected := range tt.notInOutput {
				assert.NotContains(t, output, notExpected)
			}
		})
	}
}

func TestStreamProcessorBlockTransitions(t *testing.T) {
	var buf strings.Builder
	writer := newSSEEventWriter(log.Log, &buf)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	processor := newStreamProcessor(writer, "test-model", wg)

	// Open text block
	resp1 := &genai.GenerateContentResponse{
		Candidates: []*genai.Candidate{
			{
				Content: &genai.Content{
					Parts: []*genai.Part{
						{Text: "First"},
					},
				},
			},
		},
	}
	processor.processGeminiChunk(resp1)
	wg.Wait()
	assert.True(t, processor.hasOpenBlock)
	assert.Equal(t, 0, processor.contentBlockIndex)

	// Close with function call
	resp2 := &genai.GenerateContentResponse{
		Candidates: []*genai.Candidate{
			{
				Content: &genai.Content{
					Parts: []*genai.Part{
						{
							FunctionCall: &genai.FunctionCall{
								ID:   "call_1",
								Name: "search",
								Args: map[string]any{},
							},
						},
					},
				},
			},
		},
	}
	processor.processGeminiChunk(resp2)
	assert.False(t, processor.hasOpenBlock)
	assert.Equal(t, 2, processor.contentBlockIndex)

	// Open new text block
	resp3 := &genai.GenerateContentResponse{
		Candidates: []*genai.Candidate{
			{
				Content: &genai.Content{
					Parts: []*genai.Part{
						{Text: "Second"},
					},
				},
			},
		},
	}
	processor.processGeminiChunk(resp3)
	assert.True(t, processor.hasOpenBlock)

	output := buf.String()
	assert.Contains(t, output, `"type":"text_delta"`)
	assert.Contains(t, output, `"type":"content_block_stop"`)
	assert.Contains(t, output, `"type":"tool_use"`)
}

func TestHandleStreamErrorFirstSend(t *testing.T) {
	var buf strings.Builder
	writer := newSSEEventWriter(log.Log, &buf)
	logger := log.Log

	response, shouldReturn := handleStreamError(fmt.Errorf("connection failed"), true, writer, logger, "test-model")

	assert.True(t, shouldReturn)
	assert.NotNil(t, response)
	assert.Equal(t, http.StatusInternalServerError, response.StatusCode)

	// Verify body content
	bodyBytes, err := io.ReadAll(response.Body)
	assert.NoError(t, err)
	assert.Equal(t, "ERROR_FIRST_RESPONSE", string(bodyBytes))

	// Buffer should be empty since error response replaced the fabricated one
	assert.Empty(t, buf.String())
}

func TestHandleStreamErrorSubsequent(t *testing.T) {
	var buf strings.Builder
	writer := newSSEEventWriter(log.Log, &buf)
	logger := log.Log

	response, shouldReturn := handleStreamError(fmt.Errorf("stream interrupted"), false, writer, logger, "test-model")

	assert.True(t, shouldReturn)
	assert.Nil(t, response)

	// Buffer should have error event and done
	output := buf.String()
	assert.Contains(t, output, `"type":"error"`)
	assert.Contains(t, output, `"message":"stream interrupted"`)
	assert.Contains(t, output, `data: [DONE]`)
}

// Helper functions to create mock OpenAI events
func newThoughtDelta(text string) responses.ResponseStreamEventUnion {
	return responses.ResponseStreamEventUnion{
		Type:  "response.reasoning_text.delta",
		Delta: text,
	}
}

func newTextDelta(text string) responses.ResponseStreamEventUnion {
	return responses.ResponseStreamEventUnion{
		Type:  "response.output_text.delta",
		Delta: text,
	}
}

func newFunctionCallStart(id, name string) responses.ResponseStreamEventUnion {
	return responses.ResponseStreamEventUnion{
		Type: "response.output_item.added",
		Item: responses.ResponseOutputItemUnion{
			Type:   "function_call",
			CallID: id,
			Name:   name,
		},
	}
}

func newFunctionArgumentsDelta(jsonContent string) responses.ResponseStreamEventUnion {
	return responses.ResponseStreamEventUnion{
		Type:  "response.function_call_arguments.delta",
		Delta: jsonContent,
	}
}

func newFunctionCallDone() responses.ResponseStreamEventUnion {
	return responses.ResponseStreamEventUnion{
		Type: "response.output_item.done",
	}
}

func createMockUsage(inputTokens, outputTokens int64) responses.ResponseUsage {
	return responses.ResponseUsage{
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
	}
}

func TestProcessOpenAIChunk_ThoughtDelta(t *testing.T) {
	tests := []struct {
		name             string
		events           []responses.ResponseStreamEventUnion
		expectedInOutput []string
		expectedState    map[string]interface{}
	}{
		{
			name: "single thought delta",
			events: []responses.ResponseStreamEventUnion{
				newThoughtDelta("Let me analyze"),
			},
			expectedInOutput: []string{
				`"type":"message_start"`,
				`"type":"content_block_delta"`,
				`"type":"thought_delta"`,
				`"text":"Let me analyze"`,
			},
			expectedState: map[string]interface{}{
				"hasOpenBlock":      true,
				"contentBlockIndex": 0,
				"firstSend":         false,
			},
		},
		{
			name: "multiple thought deltas",
			events: []responses.ResponseStreamEventUnion{
				newThoughtDelta("First thought "),
				newThoughtDelta("second thought"),
			},
			expectedInOutput: []string{
				`"type":"thought_delta"`,
				`"text":"First thought "`,
				`"text":"second thought"`,
			},
			expectedState: map[string]interface{}{
				"hasOpenBlock":      true,
				"contentBlockIndex": 0,
			},
		},
		{
			name: "empty thought delta",
			events: []responses.ResponseStreamEventUnion{
				newThoughtDelta(""),
			},
			expectedInOutput: []string{},
			expectedState: map[string]interface{}{
				"firstSend": true, // Should still be true since no output
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf strings.Builder
			writer := newSSEEventWriter(log.Log, &buf)
			wg := &sync.WaitGroup{}
			wg.Add(1)
			processor := newStreamProcessor(writer, "gpt-4", wg)

			for _, event := range tt.events {
				_, err := processor.processOpenAIChunk(event)
				assert.NoError(t, err)
			}

			output := buf.String()
			for _, expected := range tt.expectedInOutput {
				assert.Contains(t, output, expected)
			}

			// Validate processor state
			if expectedHasOpenBlock, ok := tt.expectedState["hasOpenBlock"].(bool); ok {
				assert.Equal(t, expectedHasOpenBlock, processor.hasOpenBlock)
			}
			if expectedIndex, ok := tt.expectedState["contentBlockIndex"].(int); ok {
				assert.Equal(t, expectedIndex, processor.contentBlockIndex)
			}
			if expectedFirstSend, ok := tt.expectedState["firstSend"].(bool); ok {
				assert.Equal(t, expectedFirstSend, processor.firstSend)
			}
		})
	}
}

func TestProcessOpenAIChunk_TextDelta(t *testing.T) {
	tests := []struct {
		name             string
		events           []responses.ResponseStreamEventUnion
		expectedInOutput []string
		expectedState    map[string]interface{}
	}{
		{
			name: "single text delta",
			events: []responses.ResponseStreamEventUnion{
				newTextDelta("Hello world"),
			},
			expectedInOutput: []string{
				`"type":"message_start"`,
				`"type":"content_block_delta"`,
				`"type":"text_delta"`,
				`"text":"Hello world"`,
			},
			expectedState: map[string]interface{}{
				"hasOpenBlock":      true,
				"contentBlockIndex": 0,
				"firstSend":         false,
			},
		},
		{
			name: "text after thought",
			events: []responses.ResponseStreamEventUnion{
				newThoughtDelta("Thinking..."),
				newTextDelta("Response text"),
			},
			expectedInOutput: []string{
				`"type":"thought_delta"`,
				`"text":"Thinking..."`,
				`"type":"text_delta"`,
				`"text":"Response text"`,
			},
			expectedState: map[string]interface{}{
				"hasOpenBlock":      true,
				"contentBlockIndex": 0, // Should be same block
			},
		},
		{
			name: "special characters in text",
			events: []responses.ResponseStreamEventUnion{
				newTextDelta(`"quoted" and 'single' with\nnewline`),
			},
			expectedInOutput: []string{
				`"type":"text_delta"`,
			},
			expectedState: map[string]interface{}{
				"hasOpenBlock": true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf strings.Builder
			writer := newSSEEventWriter(log.Log, &buf)
			wg := &sync.WaitGroup{}
			wg.Add(1)
			processor := newStreamProcessor(writer, "gpt-4", wg)

			for _, event := range tt.events {
				_, err := processor.processOpenAIChunk(event)
				assert.NoError(t, err)
			}

			output := buf.String()
			for _, expected := range tt.expectedInOutput {
				assert.Contains(t, output, expected)
			}

			// Validate processor state
			if expectedHasOpenBlock, ok := tt.expectedState["hasOpenBlock"].(bool); ok {
				assert.Equal(t, expectedHasOpenBlock, processor.hasOpenBlock)
			}
			if expectedIndex, ok := tt.expectedState["contentBlockIndex"].(int); ok {
				assert.Equal(t, expectedIndex, processor.contentBlockIndex)
			}
		})
	}
}

func TestProcessOpenAIChunk_FunctionCalls(t *testing.T) {
	tests := []struct {
		name             string
		events           []responses.ResponseStreamEventUnion
		expectedInOutput []string
		expectedState    map[string]interface{}
	}{
		{
			name: "function call initialization",
			events: []responses.ResponseStreamEventUnion{
				newFunctionCallStart("call_123", "get_weather"),
			},
			expectedInOutput: []string{
				`"type":"message_start"`,
				`"type":"content_block_start"`,
				`"type":"tool_use"`,
				`"id":"call_123"`,
				`"name":"get_weather"`,
			},
			expectedState: map[string]interface{}{
				"hasOpenBlock":         true,
				"writingOpenAIToolUse": true,
				"contentBlockIndex":    0,
			},
		},
		{
			name: "function call with arguments",
			events: []responses.ResponseStreamEventUnion{
				newFunctionCallStart("call_456", "search"),
				newFunctionArgumentsDelta(`{"query": "test"}`),
			},
			expectedInOutput: []string{
				`"type":"tool_use"`,
				`"name":"search"`,
				`"type":"input_json_delta"`,
				`"partial_json":"{\"query\": \"test\"}"`,
			},
			expectedState: map[string]interface{}{
				"hasOpenBlock":         true,
				"writingOpenAIToolUse": true,
			},
		},
		{
			name: "complete function call sequence",
			events: []responses.ResponseStreamEventUnion{
				newFunctionCallStart("call_789", "calculate"),
				newFunctionArgumentsDelta(`{"a": 5`),
				newFunctionArgumentsDelta(`, "b": 10}`),
				newFunctionCallDone(),
			},
			expectedInOutput: []string{
				`"type":"content_block_start"`,
				`"type":"input_json_delta"`,
				`"partial_json":"{\"a\": 5"`,
				`"partial_json":", \"b\": 10}"`,
				`"type":"content_block_stop"`,
			},
			expectedState: map[string]interface{}{
				"hasOpenBlock":         false,
				"writingOpenAIToolUse": false,
				"contentBlockIndex":    1, // Incremented after done
			},
		},
		{
			name: "text before function call closes block",
			events: []responses.ResponseStreamEventUnion{
				newTextDelta("Here's the result:"),
				newFunctionCallStart("call_abc", "lookup"),
			},
			expectedInOutput: []string{
				`"type":"text_delta"`,
				`"type":"content_block_stop"`,  // Text block closed
				`"type":"content_block_start"`, // Function block started
				`"type":"tool_use"`,
			},
			expectedState: map[string]interface{}{
				"contentBlockIndex": 1, // Moved to next block
			},
		},
		{
			name: "missing call ID generates ID",
			events: []responses.ResponseStreamEventUnion{
				newFunctionCallStart("", "unnamed_func"),
			},
			expectedInOutput: []string{
				`"id":"toolu_0"`, // Generated ID
				`"name":"unnamed_func"`,
			},
			expectedState: map[string]interface{}{
				"hasOpenBlock": true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf strings.Builder
			writer := newSSEEventWriter(log.Log, &buf)
			wg := &sync.WaitGroup{}
			wg.Add(1)
			processor := newStreamProcessor(writer, "gpt-4", wg)

			for _, event := range tt.events {
				_, err := processor.processOpenAIChunk(event)
				assert.NoError(t, err)
			}

			output := buf.String()
			for _, expected := range tt.expectedInOutput {
				assert.Contains(t, output, expected)
			}

			// Validate processor state
			if expectedHasOpenBlock, ok := tt.expectedState["hasOpenBlock"].(bool); ok {
				assert.Equal(t, expectedHasOpenBlock, processor.hasOpenBlock)
			}
			if expectedWriting, ok := tt.expectedState["writingOpenAIToolUse"].(bool); ok {
				assert.Equal(t, expectedWriting, processor.writingOpenAIToolUse)
			}
			if expectedIndex, ok := tt.expectedState["contentBlockIndex"].(int); ok {
				assert.Equal(t, expectedIndex, processor.contentBlockIndex)
			}
		})
	}
}

func TestFinalizeOpenAI(t *testing.T) {
	tests := []struct {
		name             string
		setupEvents      []responses.ResponseStreamEventUnion
		finishReason     string
		usage            responses.ResponseUsage
		expectedInOutput []string
		expectedState    map[string]interface{}
	}{
		{
			name: "with open text block",
			setupEvents: []responses.ResponseStreamEventUnion{
				newTextDelta("Some text"),
			},
			finishReason: "stop",
			usage:        createMockUsage(100, 50),
			expectedInOutput: []string{
				`"type":"content_block_stop"`,
				`"stop_reason":"stop"`,
				`"input_tokens":100`,
				`"output_tokens":50`,
				`"type":"message_stop"`,
				`data: [DONE]`,
			},
			expectedState: map[string]interface{}{
				"hasOpenBlock":      false,
				"contentBlockIndex": 1,
			},
		},
		{
			name: "with open function block",
			setupEvents: []responses.ResponseStreamEventUnion{
				newFunctionCallStart("call_1", "test_func"),
			},
			finishReason: "tool_calls",
			usage:        createMockUsage(200, 75),
			expectedInOutput: []string{
				`"type":"content_block_stop"`,
				`"stop_reason":"tool_calls"`,
				`"input_tokens":200`,
				`"output_tokens":75`,
				`"type":"message_stop"`,
			},
			expectedState: map[string]interface{}{
				"hasOpenBlock":      false,
				"contentBlockIndex": 1,
			},
		},
		{
			name:         "without open blocks",
			setupEvents:  []responses.ResponseStreamEventUnion{},
			finishReason: "end_turn",
			usage:        createMockUsage(50, 25),
			expectedInOutput: []string{
				`"stop_reason":"end_turn"`,
				`"input_tokens":50`,
				`"output_tokens":25`,
				`"type":"message_stop"`,
			},
			expectedState: map[string]interface{}{
				"hasOpenBlock":      false,
				"contentBlockIndex": 0,
			},
		},
		{
			name: "empty finish reason defaults to end_turn",
			setupEvents: []responses.ResponseStreamEventUnion{
				newTextDelta("text"),
			},
			finishReason: "",
			usage:        createMockUsage(10, 10),
			expectedInOutput: []string{
				`"stop_reason":"end_turn"`,
			},
			expectedState: map[string]interface{}{
				"hasOpenBlock": false,
			},
		},
		{
			name: "zero usage is valid",
			setupEvents: []responses.ResponseStreamEventUnion{
				newTextDelta("quick response"),
			},
			finishReason: "stop",
			usage:        createMockUsage(0, 0),
			expectedInOutput: []string{
				`"input_tokens":0`,
				`"output_tokens":0`,
			},
			expectedState: map[string]interface{}{
				"hasOpenBlock": false,
			},
		},
		{
			name: "various finish reasons",
			setupEvents: []responses.ResponseStreamEventUnion{
				newTextDelta("long output"),
			},
			finishReason: "max_tokens",
			usage:        createMockUsage(1000, 4000),
			expectedInOutput: []string{
				`"stop_reason":"max_tokens"`,
			},
			expectedState: map[string]interface{}{
				"hasOpenBlock": false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf strings.Builder
			writer := newSSEEventWriter(log.Log, &buf)
			wg := &sync.WaitGroup{}
			wg.Add(1)
			processor := newStreamProcessor(writer, "gpt-4", wg)

			// Setup: process events to establish state
			for _, event := range tt.setupEvents {
				processor.processOpenAIChunk(event)
			}

			// Execute finalization
			processor.finalizeOpenAI(tt.finishReason, tt.usage)

			output := buf.String()
			for _, expected := range tt.expectedInOutput {
				assert.Contains(t, output, expected)
			}

			// Validate final state
			if expectedHasOpenBlock, ok := tt.expectedState["hasOpenBlock"].(bool); ok {
				assert.Equal(t, expectedHasOpenBlock, processor.hasOpenBlock)
			}
			if expectedIndex, ok := tt.expectedState["contentBlockIndex"].(int); ok {
				assert.Equal(t, expectedIndex, processor.contentBlockIndex)
			}
		})
	}
}

func TestOpenAIHelperFunctions(t *testing.T) {
	t.Run("writeOpenAIFunctionHeader", func(t *testing.T) {
		var buf strings.Builder
		writer := newSSEEventWriter(log.Log, &buf)
		wg := &sync.WaitGroup{}
		wg.Add(1)
		processor := newStreamProcessor(writer, "gpt-4", wg)

		processor.writeOpenAIFunctionHeader("call_xyz", "my_function")

		output := buf.String()
		assert.Contains(t, output, `"type":"content_block_start"`)
		assert.Contains(t, output, `"type":"tool_use"`)
		assert.Contains(t, output, `"id":"call_xyz"`)
		assert.Contains(t, output, `"name":"my_function"`)
		assert.True(t, processor.hasOpenBlock)
		assert.True(t, processor.writingOpenAIToolUse)
	})

	t.Run("writeOpenAIFunctionHeader with empty ID", func(t *testing.T) {
		var buf strings.Builder
		writer := newSSEEventWriter(log.Log, &buf)
		wg := &sync.WaitGroup{}
		wg.Add(1)
		processor := newStreamProcessor(writer, "gpt-4", wg)

		processor.writeOpenAIFunctionHeader("", "unnamed")

		output := buf.String()
		assert.Contains(t, output, `"id":"toolu_0"`) // Generated ID
		assert.Contains(t, output, `"name":"unnamed"`)
	})

	t.Run("writeOpenAIFunctionInput", func(t *testing.T) {
		var buf strings.Builder
		writer := newSSEEventWriter(log.Log, &buf)
		wg := &sync.WaitGroup{}
		wg.Add(1)
		processor := newStreamProcessor(writer, "gpt-4", wg)

		processor.writeOpenAIFunctionHeader("call_1", "test")
		buf.Reset() // Clear header output

		processor.writeOpenAIFunctionInput(`{"key": "value"}`)

		output := buf.String()
		assert.Contains(t, output, `"type":"input_json_delta"`)
		assert.Contains(t, output, `"partial_json":"{\"key\": \"value\"}"`)
	})

	t.Run("writeOpenAIFunctionStop", func(t *testing.T) {
		var buf strings.Builder
		writer := newSSEEventWriter(log.Log, &buf)
		wg := &sync.WaitGroup{}
		wg.Add(1)
		processor := newStreamProcessor(writer, "gpt-4", wg)

		processor.writeOpenAIFunctionHeader("call_1", "test")
		initialIndex := processor.contentBlockIndex

		processor.writeOpenAIFunctionStop()

		output := buf.String()
		assert.Contains(t, output, `"type":"content_block_stop"`)
		assert.False(t, processor.hasOpenBlock)
		assert.False(t, processor.writingOpenAIToolUse)
		assert.Equal(t, initialIndex+1, processor.contentBlockIndex)
	})
}

func TestOpenAIStreamIntegration(t *testing.T) {
	tests := []struct {
		name             string
		events           []responses.ResponseStreamEventUnion
		finishReason     string
		usage            responses.ResponseUsage
		expectedSequence []string
		expectedBlocks   int
	}{
		{
			name: "thought then text sequence",
			events: []responses.ResponseStreamEventUnion{
				newThoughtDelta("Analyzing request..."),
				newThoughtDelta(" considering options"),
				newTextDelta("Here is the answer: "),
				newTextDelta("42"),
			},
			finishReason: "stop",
			usage:        createMockUsage(50, 30),
			expectedSequence: []string{
				`"type":"message_start"`,
				`"type":"content_block_delta"`,
				`"type":"thought_delta"`,
				`"text":"Analyzing request..."`,
				`"text":" considering options"`,
				`"type":"text_delta"`,
				`"text":"Here is the answer: "`,
				`"text":"42"`,
				`"type":"content_block_stop"`,
				`"stop_reason":"stop"`,
				`"type":"message_stop"`,
			},
			expectedBlocks: 1, // All in one block
		},
		{
			name: "text to function transition",
			events: []responses.ResponseStreamEventUnion{
				newTextDelta("Let me look that up"),
				newFunctionCallStart("call_search", "web_search"),
				newFunctionArgumentsDelta(`{"query": "weather"}`),
				newFunctionCallDone(),
			},
			finishReason: "tool_calls",
			usage:        createMockUsage(100, 50),
			expectedSequence: []string{
				`"type":"text_delta"`,
				`"type":"content_block_stop"`,  // Block 0 closed
				`"type":"content_block_start"`, // Block 1 started
				`"type":"tool_use"`,
				`"name":"web_search"`,
				`"type":"input_json_delta"`,
				`"type":"content_block_stop"`, // Block 1 closed
			},
			expectedBlocks: 2,
		},
		{
			name: "multiple functions",
			events: []responses.ResponseStreamEventUnion{
				newFunctionCallStart("call_1", "func1"),
				newFunctionArgumentsDelta(`{"x": 1}`),
				newFunctionCallDone(),
				newFunctionCallStart("call_2", "func2"),
				newFunctionArgumentsDelta(`{"y": 2}`),
				newFunctionCallDone(),
			},
			finishReason: "tool_calls",
			usage:        createMockUsage(200, 100),
			expectedSequence: []string{
				`"name":"func1"`,
				`"partial_json":"{\"x\": 1}"`,
				`"type":"content_block_stop"`,
				`"name":"func2"`,
				`"partial_json":"{\"y\": 2}"`,
				`"type":"content_block_stop"`,
			},
			expectedBlocks: 2,
		},
		{
			name: "mixed content complete flow",
			events: []responses.ResponseStreamEventUnion{
				newThoughtDelta("Planning response"),
				newTextDelta("Based on your request, "),
				newTextDelta("I will use a tool."),
				newFunctionCallStart("call_multi", "process"),
				newFunctionArgumentsDelta(`{"step": 1}`),
				newFunctionCallDone(),
			},
			finishReason: "tool_calls",
			usage:        createMockUsage(150, 80),
			expectedSequence: []string{
				`"type":"message_start"`,
				`"type":"thought_delta"`,
				`"text":"Planning response"`,
				`"type":"text_delta"`,
				`"text":"Based on your request, "`,
				`"text":"I will use a tool."`,
				`"type":"content_block_stop"`,  // Text block closed
				`"type":"content_block_start"`, // Function started
				`"type":"tool_use"`,
				`"name":"process"`,
				`"type":"input_json_delta"`,
				`"type":"content_block_stop"`, // Function closed
				`"stop_reason":"tool_calls"`,
				`"type":"message_stop"`,
				`data: [DONE]`,
			},
			expectedBlocks: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf strings.Builder
			writer := newSSEEventWriter(log.Log, &buf)
			wg := &sync.WaitGroup{}
			wg.Add(1)
			processor := newStreamProcessor(writer, "gpt-4", wg)

			// Process all events
			for _, event := range tt.events {
				_, err := processor.processOpenAIChunk(event)
				assert.NoError(t, err)
			}

			// Finalize
			processor.finalizeOpenAI(tt.finishReason, tt.usage)

			output := buf.String()

			// Verify sequence
			for _, expected := range tt.expectedSequence {
				assert.Contains(t, output, expected)
			}

			// Verify block count
			assert.Equal(t, tt.expectedBlocks, processor.contentBlockIndex)
			assert.False(t, processor.hasOpenBlock)         // Should be closed
			assert.False(t, processor.writingOpenAIToolUse) // Should be cleared
		})
	}
}

func TestExtractReasoning(t *testing.T) {
	tests := []struct {
		name              string
		deltaJSON         string
		expectedReasoning string
		expectedFound     bool
	}{
		{
			name:              "no extra fields",
			deltaJSON:         `{}`,
			expectedReasoning: "",
			expectedFound:     false,
		},
		{
			name:              "unrecognized extra field",
			deltaJSON:         `{"other_field":"value"}`,
			expectedReasoning: "",
			expectedFound:     false,
		},
		{
			name:              "reasoning field",
			deltaJSON:         `{"reasoning":"some thought"}`,
			expectedReasoning: "some thought",
			expectedFound:     true,
		},
		{
			name:              "reasoning_content field",
			deltaJSON:         `{"reasoning_content":"content thought"}`,
			expectedReasoning: "content thought",
			expectedFound:     true,
		},
		{
			name:              "reasoning_summary field",
			deltaJSON:         `{"reasoning_summary":"summary thought"}`,
			expectedReasoning: "summary thought",
			expectedFound:     true,
		},
		{
			name:              "reasoning takes priority over reasoning_content",
			deltaJSON:         `{"reasoning":"first","reasoning_content":"second"}`,
			expectedReasoning: "first",
			expectedFound:     true,
		},
		{
			name:              "reasoning_content takes priority over reasoning_summary",
			deltaJSON:         `{"reasoning_content":"content","reasoning_summary":"summary"}`,
			expectedReasoning: "content",
			expectedFound:     true,
		},
		{
			name:              "empty string reasoning",
			deltaJSON:         `{"reasoning":""}`,
			expectedReasoning: "",
			expectedFound:     false,
		},
		{
			name:              "ignore empty for non-empty fields",
			deltaJSON:         `{"reasoning":"","reasoning_content":"content","reasoning_summary":"summary"}`,
			expectedReasoning: "content",
			expectedFound:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var delta openai.ChatCompletionChunkChoiceDelta
			err := json.Unmarshal([]byte(tt.deltaJSON), &delta)
			assert.NoError(t, err)
			reasoning, found := extractReasoning(delta)
			assert.Equal(t, tt.expectedFound, found)
			assert.Equal(t, tt.expectedReasoning, reasoning)
		})
	}
}
