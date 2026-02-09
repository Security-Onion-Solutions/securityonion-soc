package assistant

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/openai/openai-go/v3/packages/param"
	"github.com/openai/openai-go/v3/responses"
	"github.com/openai/openai-go/v3/shared"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

func init() {
	protocols[(&OpenAIAdapter{}).Protocol()] = NewOpenAIAdapter
}

type OpenAIAdapter struct {
	srv                  *server.Server
	client               OpenAIClient
	healthTimeoutSeconds int
	detections.IOManager
}

func NewOpenAIAdapter(ctx context.Context, srv *server.Server, config map[string]any) (server.AssistantAdapter, error) {
	baseUrl := module.GetStringDefault(config, "baseUrl", "")
	if baseUrl == "" {
		return nil, fmt.Errorf("openai adapter requires baseUrl in config")
	}

	opts := []option.RequestOption{
		option.WithBaseURL(baseUrl),
	}

	apiKey := module.GetStringDefault(config, "apiKey", "")
	if apiKey != "" {
		opts = append(opts, option.WithAPIKey(apiKey))
	}

	healthTimeoutSeconds := module.GetIntDefault(config, "healthTimeoutSeconds", DEFAULT_HEALTH_TIMEOUT_SECONDS)

	return &OpenAIAdapter{
		srv:                  srv,
		healthTimeoutSeconds: healthTimeoutSeconds,
		client:               NewOpenAIClientWrapper(openai.NewClient(opts...)),
		IOManager: &detections.ResourceManager{
			Config: srv.Config,
		},
	}, nil
}

func (a *OpenAIAdapter) Protocol() string {
	return "openai"
}

func (a *OpenAIAdapter) SendMessage(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
	logger := log.FromContext(ctx)

	// Convert history and tools (reuse existing functions)
	history := convertHistoryToOpenAI(req)
	tools := convertToolConfigToOpenAI(req)

	// Build system prompt
	prompt := req.System
	if req.SystemAppend != "" {
		prompt += "\n" + req.SystemAppend
	}

	// Call non-streaming API
	resp, err := a.client.ResponsesNew(ctx, responses.ResponseNewParams{
		Model:        req.Model,
		Input:        history,
		Instructions: openai.String(prompt),
		Tools:        tools,
		MaxToolCalls: openai.Int(1),
		Reasoning: shared.ReasoningParam{
			Summary: "auto",
		},
	})
	if err != nil {
		logger.WithFields(log.Fields{
			"model": req.Model,
		}).WithError(err).Error("error calling OpenAI non-streaming API")
		return nil, err
	}

	// Build model.Message from response
	message := &model.Message{
		Id:            resp.ID,
		Role:          "assistant",
		ContentBlocks: []model.ContentBlock{},
	}

	// Process output items based on Type field (discriminated union)
	for _, item := range resp.Output {
		switch item.Type {
		case "message":
			// Handle text messages
			for _, content := range item.Content {
				if content.Type == "output_text" {
					message.ContentBlocks = append(message.ContentBlocks, model.ContentBlock{
						Type: "text",
						Text: content.Text,
					})
				}
			}

		case "function_call":
			// Handle function calls (tool use)
			toolUseId := item.CallID
			if toolUseId == "" {
				toolUseId = fmt.Sprintf("toolu_%d", len(message.ContentBlocks))
			}

			message.ContentBlocks = append(message.ContentBlocks, model.ContentBlock{
				Type:  "tool_use",
				Id:    toolUseId,
				Name:  item.Name,
				Input: json.RawMessage(item.Arguments),
			})
		}
	}

	// Handle usage metadata
	message.Usage = &model.Usage{
		InputTokens:  int(resp.Usage.InputTokens),
		OutputTokens: int(resp.Usage.OutputTokens),
	}

	// Handle finish reason - check status
	if resp.Status == "completed" {
		stopReason := "end_turn"
		message.StopReason = &stopReason
	} else if resp.Status == "incomplete" {
		// Map incomplete reason to stop reason
		reason := string(resp.IncompleteDetails.Reason)
		if reason != "" {
			message.StopReason = &reason
		}
	}

	return message, nil
}

func (a *OpenAIAdapter) SendMessageStream(ctx context.Context, req *model.ChatRequest) (response *http.Response, _ *model.AuxMessageData, err error) {
	logger := log.FromContext(ctx)

	history := convertHistoryToOpenAI(req)
	tools := convertToolConfigToOpenAI(req)

	prompt := req.System

	if req.SystemAppend != "" {
		prompt += "\n" + req.SystemAppend
	}

	// don't allow a user closing their request connection to cause us to lose the message stream
	noTimeoutContext := context.WithValue(context.Background(), web.ContextKeyRequestId, ctx.Value(web.ContextKeyRequestId))
	noTimeoutContext = context.WithValue(noTimeoutContext, web.ContextKeyRequestorId, ctx.Value(web.ContextKeyRequestorId))

	stream := a.client.ResponsesNewStreaming(noTimeoutContext, responses.ResponseNewParams{
		Model:        req.Model,
		Input:        history,
		Instructions: openai.String(prompt),
		Tools:        tools,
		MaxToolCalls: openai.Int(1),
		Reasoning: shared.ReasoningParam{
			Summary: "auto",
		},
	})

	response, bodyWriter := fabricateResponse(http.StatusOK)

	wg := &sync.WaitGroup{}
	wg.Add(1)

	// Create SSE writer and stream processor
	writer := newSSEEventWriter(bodyWriter)
	processor := newStreamProcessor(writer, req.Model, wg)

	err = stream.Err()
	if err != nil {
		bodyWriter.Close()

		// shouldReturn is ALWAYS true because processor.firstSend is true at this point
		// and handleStreamError will return a replacement response
		replacement, _ := handleStreamError(err, processor.firstSend, writer, logger, req.Model)
		if replacement != nil {
			response = replacement
		}

		return response, nil, err
	}

	go func() {
		defer bodyWriter.Close()

		finishReason := "end_turn"

		for stream.Next() {
			err := stream.Err()
			if err != nil {
				replacement, shouldReturn := handleStreamError(err, processor.firstSend, writer, logger, req.Model)
				if shouldReturn {
					if replacement != nil {
						response = replacement
					}
					return
				}
			}

			cur := stream.Current()
			_, err = processor.processOpenAIChunk(cur)
			if err != nil {
				// Mid-stream error during processing
				processor.writeError(err)
				return
			}
		}
		// Finalization - processor handles closing blocks and writing final events
		processor.finalizeOpenAI(finishReason, stream.Current().Response.Usage)
	}()

	wg.Wait()

	return response, nil, nil
}

func convertHistoryToOpenAI(req *model.ChatRequest) responses.ResponseNewParamsInputUnion {
	history := make([]responses.ResponseInputItemUnionParam, 0, len(req.Messages))

	for _, msg := range req.Messages {
		content := ""

		h := responses.ResponseInputItemUnionParam{}

		// Process each content block in the message
		for _, block := range msg.ContentBlocks {
			if block.Type == "" && block.ToolResult != nil {
				block.Type = "tool_result"
			}

			switch block.Type {
			case "text":
				// Handle text content
				if block.Text != "" {
					content += block.Text
				}
			case "tool_use":
				// Handle tool use (function calls from the model)
				var args map[string]any
				if len(block.Input) > 0 {
					if err := json.Unmarshal(block.Input, &args); err != nil {
						// If unmarshal fails, skip this block
						continue
					}
				}

				h.OfFunctionCall = &responses.ResponseFunctionToolCallParam{
					ID:        openai.String(block.Id),
					Name:      block.Name,
					Arguments: string(block.Input),
				}
			case "tool_result":
				// Handle tool results (responses from user with tool execution results)
				if block.ToolResult != nil && len(block.ToolResult.Content) != 0 {
					if block.ToolResult.IsError {
						h.OfFunctionCallOutput = &responses.ResponseInputItemFunctionCallOutputParam{
							CallID: block.ToolResult.ToolUseId,
							Output: responses.ResponseInputItemFunctionCallOutputOutputUnionParam{
								OfString: openai.String(fmt.Sprintf(`{"error": "%s"}`, block.ToolResult.Content[0].Text)),
							},
							Status: "completed",
						}
					} else {
						jsonBytes, err := json.Marshal(block.ToolResult.Content[0].Json)
						if err != nil {
							jsonBytes = []byte(`{ "error": "failed to marshal tool result content" }`)
						}

						h.OfFunctionCallOutput = &responses.ResponseInputItemFunctionCallOutputParam{
							CallID: block.ToolResult.ToolUseId,
							Output: responses.ResponseInputItemFunctionCallOutputOutputUnionParam{
								OfString: openai.String(string(jsonBytes)),
							},
							Status: "completed",
						}
					}
				}
			default:
				// For any other type, try to use text if available
				if block.Text != "" {
					content += block.Text
				}
			}
		}

		// &nbsp; is necessary for most providers that require every message must
		// contain text, however openai will yell at you for including text (the
		// filler &nbsp;) alongside a function call.
		if content != "" && content != "&nbsp;" {
			h.OfInputMessage = &responses.ResponseInputItemMessageParam{
				Role: msg.Role,
				Content: responses.ResponseInputMessageContentListParam{
					{
						OfInputText: &responses.ResponseInputTextParam{
							Text: content,
						},
					},
				},
			}
		}

		history = append(history, h)
	}

	result := responses.ResponseNewParamsInputUnion{
		OfInputItemList: responses.ResponseInputParam{},
	}

	for i := range history {
		result.OfInputItemList = append(result.OfInputItemList, history[i])
	}

	return result
}

func (a *OpenAIAdapter) GetBalance(ctx context.Context) (*model.BalanceResponse, error) {
	return &model.BalanceResponse{
		Balance: UNUSED_BALANCE,
	}, nil
}

func (a *OpenAIAdapter) GetHealth(ctx context.Context) (*model.HealthResponse, error) {
	healthCtx, cancel := context.WithTimeout(a.srv.Context, time.Second*time.Duration(a.healthTimeoutSeconds))
	defer cancel()

	status := "unhealthy"

	res, err := a.client.ModelsList(healthCtx)
	if err == nil && len(res.Data) > 0 {
		status = "healthy"
	}

	return &model.HealthResponse{
		Status: status,
	}, nil
}

func convertToolConfigToOpenAI(req *model.ChatRequest) []responses.ToolUnionParam {
	if req.ToolConfig == nil {
		return nil
	}

	var toolConfig model.ToolConfig
	if err := json.Unmarshal(req.ToolConfig, &toolConfig); err != nil {
		return nil
	}

	if len(toolConfig.Tools) == 0 {
		return nil
	}

	// Convert tool specifications to OpenAI function parameters
	tools := make([]responses.ToolUnionParam, 0, len(toolConfig.Tools))

	for _, toolSpec := range toolConfig.Tools {
		if toolSpec.Spec.InputSchema.Json == nil {
			continue
		}

		parameters := convertJSONSchemaToOpenAI(toolSpec.Spec.InputSchema.Json)

		// Build optional description
		var description param.Opt[string]
		if toolSpec.Spec.Description != "" {
			description = openai.String(toolSpec.Spec.Description)
		}

		// Create tool parameter with manual construction
		toolParam := responses.ToolUnionParam{
			OfFunction: &responses.FunctionToolParam{
				Name:        toolSpec.Spec.Name,
				Parameters:  parameters,
				Description: description,
				Strict:      openai.Bool(true),
			},
		}

		tools = append(tools, toolParam)
	}

	// Return nil if all tools were filtered out
	if len(tools) == 0 {
		return nil
	}

	return tools
}

func convertPropertyToOpenAI(prop *model.ToolSchemaProperty) map[string]any {
	result := map[string]any{
		"type": prop.Type,
	}

	if prop.Description != "" {
		result["description"] = prop.Description
	}

	if prop.Default != nil {
		result["default"] = prop.Default
	}

	// Handle nested items (arrays and nested objects)
	if len(prop.Items) > 0 {
		if prop.Type == "object" {
			items := make(map[string]any)
			for itemName, itemSchema := range prop.Items {
				items[itemName] = convertPropertyToOpenAI(&itemSchema)
			}
			result["properties"] = items
		} else if prop.Type == "array" {
			for _, itemSchema := range prop.Items {
				result["items"] = convertPropertyToOpenAI(&itemSchema)
				break // Use first item as schema
			}
		}
	}

	return result
}

func convertJSONSchemaToOpenAI(schema *model.ToolSchema) map[string]any {
	if schema == nil {
		return nil
	}

	result := map[string]any{
		"type": schema.Type,
	}

	if len(schema.Properties) > 0 {
		properties := make(map[string]any)
		for propName, propSchema := range schema.Properties {
			properties[propName] = convertPropertyToOpenAI(&propSchema)
		}
		result["properties"] = properties
	}

	if len(schema.Required) > 0 {
		result["required"] = schema.Required
	}

	return result
}
