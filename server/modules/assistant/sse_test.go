package assistant

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/apex/log"
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
				return w.writeContentBlockDelta(0, "text_delta", `"Hello World"`)
			},
			expected: `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello World"}}` + "\n\n",
		},
		{
			name: "writeContentBlockDelta thought",
			writeOp: func(w *sseEventWriter) error {
				return w.writeContentBlockDelta(0, "thought_delta", `"Thinking about it"`)
			},
			expected: `data: {"type":"content_block_delta","index":0,"delta":{"type":"thought_delta","text":"Thinking about it"}}` + "\n\n",
		},
		{
			name: "writeContentBlockDelta with newlines",
			writeOp: func(w *sseEventWriter) error {
				return w.writeContentBlockDelta(1, "text_delta", `"Line 1\nLine 2\tTabbed"`)
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
			writer := newSSEEventWriter(&buf)

			err := tt.writeOp(writer)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, buf.String())
		})
	}

	t.Run("writeContentBlockStart with complex object", func(t *testing.T) {
		var buf strings.Builder
		writer := newSSEEventWriter(&buf)

		block := map[string]any{
			"type":  "tool_use",
			"id":    "toolu_123",
			"name":  "search",
			"input": map[string]any{},
		}

		err := writer.writeContentBlockStart(1, block)
		assert.NoError(t, err)

		result := buf.String()
		assert.Contains(t, result, `"type":"content_block_start"`)
		assert.Contains(t, result, `"index":1`)
		assert.Contains(t, result, `"type":"tool_use"`)
		assert.Contains(t, result, `"id":"toolu_123"`)
		assert.Contains(t, result, `"name":"search"`)
	})

	t.Run("full message sequence with thought and text", func(t *testing.T) {
		var buf strings.Builder
		writer := newSSEEventWriter(&buf)

		// Write a complete message stream
		writer.writeMessageStart("gemini-2.0-flash-exp")
		writer.writeContentBlockDelta(0, "thought_delta", `"Let me think about this..."`)
		writer.writeContentBlockDelta(0, "thought_delta", `" analyzing the request"`)
		writer.writeContentBlockDelta(0, "text_delta", `"Here is the answer: "`)
		writer.writeContentBlockDelta(0, "text_delta", `"42"`)
		writer.writeContentBlockStop(0)
		writer.writeStopReason("end_turn")
		writer.writeUsage(50, 15)
		writer.writeMessageStop()
		writer.writeDone()

		result := buf.String()

		// Verify each event is present in order
		assert.Contains(t, result, `"type":"message_start"`)
		assert.Contains(t, result, `"model":"gemini-2.0-flash-exp"`)

		// Verify thought deltas
		assert.Contains(t, result, `"type":"thought_delta","text":"Let me think about this..."`)
		assert.Contains(t, result, `"type":"thought_delta","text":" analyzing the request"`)

		// Verify text deltas
		assert.Contains(t, result, `"type":"text_delta","text":"Here is the answer: "`)
		assert.Contains(t, result, `"type":"text_delta","text":"42"`)

		// Verify closure
		assert.Contains(t, result, `"type":"content_block_stop","index":0`)
		assert.Contains(t, result, `"stop_reason":"end_turn"`)
		assert.Contains(t, result, `"input_tokens":50,"output_tokens":15`)
		assert.Contains(t, result, `"type":"message_stop"`)
		assert.Contains(t, result, `data: [DONE]`)

		// Verify sequence order
		thoughtIndex := strings.Index(result, "thought_delta")
		textIndex := strings.Index(result, "text_delta")
		stopIndex := strings.Index(result, "content_block_stop")
		doneIndex := strings.Index(result, "[DONE]")

		assert.Less(t, thoughtIndex, textIndex, "thought should come before text")
		assert.Less(t, textIndex, stopIndex, "text should come before stop")
		assert.Less(t, stopIndex, doneIndex, "stop should come before done")
	})

	t.Run("full message sequence with function call", func(t *testing.T) {
		var buf strings.Builder
		writer := newSSEEventWriter(&buf)

		// Write a message with text followed by a function call
		writer.writeMessageStart("gemini-2.0-flash-exp")
		writer.writeContentBlockDelta(0, "text_delta", `"I'll search for that."`)
		writer.writeContentBlockStop(0)

		toolBlock := map[string]any{
			"type":  "tool_use",
			"id":    "toolu_abc123",
			"name":  "web_search",
			"input": map[string]any{},
		}
		writer.writeContentBlockStart(1, toolBlock)
		writer.writeInputJsonDelta(1, `{"query":"test search"}`)
		writer.writeContentBlockStop(1)

		writer.writeStopReason("tool_use")
		writer.writeUsage(30, 25)
		writer.writeMessageStop()
		writer.writeDone()

		result := buf.String()

		// Verify message structure
		assert.Contains(t, result, `"type":"message_start"`)
		assert.Contains(t, result, `"type":"text_delta","text":"I'll search for that."`)
		assert.Contains(t, result, `"type":"content_block_stop","index":0`)

		// Verify function call block
		assert.Contains(t, result, `"type":"content_block_start"`)
		assert.Contains(t, result, `"type":"tool_use"`)
		assert.Contains(t, result, `"id":"toolu_abc123"`)
		assert.Contains(t, result, `"name":"web_search"`)
		assert.Contains(t, result, `"input_json_delta"`)
		assert.Contains(t, result, `"type":"content_block_stop","index":1`)

		// Verify closure with tool_use stop reason
		assert.Contains(t, result, `"stop_reason":"tool_use"`)
		assert.Contains(t, result, `data: [DONE]`)
	})
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
			writer := newSSEEventWriter(&buf)
			wg := &sync.WaitGroup{}
			wg.Add(1)
			processor := newStreamProcessor(writer, "test-model", wg)

			thoughtSigs, reason, err := processor.processChunk(tt.resp)
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
				processor.processChunk(resp2)

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
			writer := newSSEEventWriter(&buf)
			wg := &sync.WaitGroup{}
			wg.Add(1)
			processor := newStreamProcessor(writer, "test-model", wg)

			processor.processChunk(tt.resp)
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
	writer := newSSEEventWriter(&buf)
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
	processor.processChunk(resp1)
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

	thoughtSigs, reason, err := processor.processChunk(resp2)
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
	writer := newSSEEventWriter(&buf)
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

	thoughtSigs, _, err := processor.processChunk(resp)
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
	writer := newSSEEventWriter(&buf)
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

	processor.processChunk(resp)
	wg.Wait()

	output := buf.String()
	count := strings.Count(output, `"type":"tool_use"`)
	assert.Equal(t, 2, count)
	assert.Contains(t, output, `"name":"search"`)
	assert.Contains(t, output, `"name":"calculate"`)
}

func TestStreamProcessorMidStreamError(t *testing.T) {
	var buf strings.Builder
	writer := newSSEEventWriter(&buf)
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
	processor.processChunk(resp)
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
				p.processChunk(resp)
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
			writer := newSSEEventWriter(&buf)
			wg := &sync.WaitGroup{}
			wg.Add(1)
			processor := newStreamProcessor(writer, "test-model", wg)

			tt.setupProcessor(processor)
			if processor.firstSend {
				wg.Done()
			} else {
				wg.Wait()
			}

			processor.finalize(tt.finishReason, tt.usage)

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
	writer := newSSEEventWriter(&buf)
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
	processor.processChunk(resp1)
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
	processor.processChunk(resp2)
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
	processor.processChunk(resp3)
	assert.True(t, processor.hasOpenBlock)

	output := buf.String()
	assert.Contains(t, output, `"type":"text_delta"`)
	assert.Contains(t, output, `"type":"content_block_stop"`)
	assert.Contains(t, output, `"type":"tool_use"`)
}

func TestHandleStreamErrorFirstSend(t *testing.T) {
	var buf strings.Builder
	writer := newSSEEventWriter(&buf)
	logger := log.Log

	response, shouldReturn := handleStreamError(fmt.Errorf("connection failed"), true, writer, logger, "test-model")

	assert.True(t, shouldReturn)
	assert.NotNil(t, response)
	assert.Equal(t, http.StatusInternalServerError, response.StatusCode)

	// Verify body content
	bodyBytes, err := io.ReadAll(response.Body)
	assert.NoError(t, err)
	assert.Equal(t, "ERROR_GEMINI_FIRST_RESPONSE", string(bodyBytes))

	// Buffer should be empty since error response replaced the fabricated one
	assert.Empty(t, buf.String())
}

func TestHandleStreamErrorSubsequent(t *testing.T) {
	var buf strings.Builder
	writer := newSSEEventWriter(&buf)
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
