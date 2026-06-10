package assistant

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/packages/param"
	"github.com/openai/openai-go/v3/responses"
	"github.com/openai/openai-go/v3/shared"
)

func init() {
	protocols[(&OpenAIResponsesAdapter{}).Protocol()] = NewOpenAIResponsesAdapter
}

type OpenAIResponsesAdapter struct {
	srv                  *server.Server
	client               OpenAIClient
	healthTimeoutSeconds int
	detections.IOManager
}

func NewOpenAIResponsesAdapter(ctx context.Context, srv *server.Server, config map[string]any) (server.AssistantAdapter, error) {
	apiUrl := module.GetStringDefault(config, "apiUrl", "")
	if apiUrl == "" {
		return nil, fmt.Errorf("openai adapter requires apiUrl in config")
	}

	apiKey := module.GetStringDefault(config, "apiKey", "")
	opts, err := buildOpenAIClientOptions(apiUrl, apiKey)
	if err != nil {
		return nil, fmt.Errorf("openai adapter config error: %w", err)
	}

	healthTimeoutSeconds := module.GetIntDefault(config, "healthTimeoutSeconds", DEFAULT_HEALTH_TIMEOUT_SECONDS)

	return &OpenAIResponsesAdapter{
		srv:                  srv,
		healthTimeoutSeconds: healthTimeoutSeconds,
		client:               NewOpenAIClientWrapper(openai.NewClient(opts...)),
		IOManager: &detections.ResourceManager{
			Config: srv.Config,
		},
	}, nil
}

func (a *OpenAIResponsesAdapter) Protocol() string {
	return "openai_responses"
}

func (a *OpenAIResponsesAdapter) SendMessage(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
	logger := log.FromContext(ctx)

	// Convert history and tools (reuse existing functions)
	history := convertHistoryToOpenAI(logger, req)
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
				Input: json.RawMessage([]byte(item.AsFunctionCall().Arguments)),
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

func (a *OpenAIResponsesAdapter) SendMessageStream(ctx context.Context, req *model.ChatRequest) (response *http.Response, _ *model.AuxMessageData, err error) {
	logger := log.FromContext(ctx)

	history := convertHistoryToOpenAI(logger, req)
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

	// Create SSE writer and stream processor
	writer := newSSEEventWriter(logger, bodyWriter)
	processor := newStreamProcessor(writer, req.Model, wg)

	err = stream.Err()
	if err != nil {
		bodyWriter.Close()

		logger.WithError(err).Error("error before first response from OpenAI streaming API")

		// shouldReturn is ALWAYS true because processor.firstSend is true at this point
		// and handleStreamError will return a replacement response
		replacement, _ := handleStreamError(err, processor.firstSend, writer, logger, req.Model)
		if replacement != nil {
			response = replacement
		}

		return response, nil, err
	}

	wg.Add(1)

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
		// Check if the stream ended due to an error
		if err := stream.Err(); err != nil {
			replacement, shouldReturn := handleStreamError(err, processor.firstSend, writer, logger, req.Model)
			if shouldReturn {
				if replacement != nil {
					response = replacement
				}
				return
			}
		}

		// Finalization - processor handles closing blocks and writing final events
		processor.finalizeOpenAI(finishReason, stream.Current().Response.Usage)
	}()

	wg.Wait()

	return response, nil, nil
}

func convertHistoryToOpenAI(logger log.Interface, req *model.ChatRequest) responses.ResponseNewParamsInputUnion {
	history := make([]responses.ResponseInputItemUnionParam, 0, len(req.Messages))

	for _, msg := range req.Messages {
		content := ""
		items := make([]responses.ResponseInputItemUnionParam, 0)

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
						logger.WithError(err).Error("failed to unmarshal tool use input")
						continue
					}
				}

				items = append(items, responses.ResponseInputItemUnionParam{
					OfFunctionCall: &responses.ResponseFunctionToolCallParam{
						CallID:    block.Id,
						Name:      block.Name,
						Arguments: string(block.Input),
					},
				})
			case "tool_result":
				// Handle tool results (responses from user with tool execution results)
				if block.ToolResult != nil && len(block.ToolResult.Content) != 0 {
					if block.ToolResult.IsError {
						errText, _ := json.Marshal(block.ToolResult.Content[0].Text)
						items = append(items, responses.ResponseInputItemUnionParam{
							OfFunctionCallOutput: &responses.ResponseInputItemFunctionCallOutputParam{
								CallID: block.ToolResult.ToolUseId,
								Output: responses.ResponseInputItemFunctionCallOutputOutputUnionParam{
									OfString: openai.String(fmt.Sprintf(`{"error": %s}`, string(errText))),
								},
								Status: "completed",
							},
						})
					} else {
						jsonBytes, err := json.Marshal(block.ToolResult.Content[0].Json)
						if err != nil {
							jsonBytes = []byte(`{ "error": "failed to marshal tool result content" }`)
						}

						items = append(items, responses.ResponseInputItemUnionParam{
							OfFunctionCallOutput: &responses.ResponseInputItemFunctionCallOutputParam{
								CallID: block.ToolResult.ToolUseId,
								Output: responses.ResponseInputItemFunctionCallOutputOutputUnionParam{
									OfString: openai.String(string(jsonBytes)),
								},
								Status: "completed",
							},
						})
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
			var textItem responses.ResponseInputItemUnionParam
			if msg.Role == "user" {
				textItem = responses.ResponseInputItemUnionParam{
					OfInputMessage: &responses.ResponseInputItemMessageParam{
						Role: msg.Role,
						Content: responses.ResponseInputMessageContentListParam{
							{
								OfInputText: &responses.ResponseInputTextParam{
									Text: content,
								},
							},
						},
					},
				}
			} else {
				textItem = responses.ResponseInputItemUnionParam{
					OfOutputMessage: &responses.ResponseOutputMessageParam{
						Content: []responses.ResponseOutputMessageContentUnionParam{
							{
								OfOutputText: &responses.ResponseOutputTextParam{
									Text: content,
								},
							},
						},
					},
				}
			}
			// Prepend text before tool items to preserve natural ordering
			items = append([]responses.ResponseInputItemUnionParam{textItem}, items...)
		}

		history = append(history, items...)
	}

	result := responses.ResponseNewParamsInputUnion{
		OfInputItemList: responses.ResponseInputParam{},
	}

	for i := range history {
		result.OfInputItemList = append(result.OfInputItemList, history[i])
	}

	return result
}

func (a *OpenAIResponsesAdapter) GetBalance(ctx context.Context) (*model.BalanceResponse, error) {
	return &model.BalanceResponse{
		Balance: UNUSED_BALANCE,
	}, nil
}

func (a *OpenAIResponsesAdapter) GetHealth(ctx context.Context) (*model.HealthResponse, error) {
	return checkOpenAIHealth(ctx, a.client, a.healthTimeoutSeconds)
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
		"type": []string{prop.Type},
	}

	if strings.EqualFold(prop.Type, "object") {
		result["additionalProperties"] = false
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
			names := make([]string, 0, len(prop.Items))
			for itemName, itemSchema := range prop.Items {
				names = append(names, itemName)
				child := convertPropertyToOpenAI(&itemSchema)
				// strict mode lists every property in `required`; the schema model
				// can't express per-field optionality at the nested level, so make
				// each field nullable to keep optional fields satisfiable.
				child["type"] = append(child["type"].([]string), "null")
				items[itemName] = child
			}
			slices.Sort(names)
			result["properties"] = items
			result["required"] = names
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

	allPropNames := make([]string, 0, len(schema.Properties))

	if len(schema.Properties) > 0 {
		properties := make(map[string]any)
		for propName, propSchema := range schema.Properties {
			allPropNames = append(allPropNames, propName)
			prop := convertPropertyToOpenAI(&propSchema)
			if !slices.Contains(schema.Required, propName) {
				prop["type"] = append(prop["type"].([]string), "null")
			}
			properties[propName] = prop
		}
		result["properties"] = properties
	}

	slices.Sort(allPropNames)
	result["required"] = allPropNames

	result["additionalProperties"] = false

	return result
}
