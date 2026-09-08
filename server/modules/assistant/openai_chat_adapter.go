// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/packages/param"
)

func init() {
	protocols[(&OpenAIChatAdapter{}).Protocol()] = NewOpenAIChatAdapter
}

type OpenAIChatAdapter struct {
	srv                  *server.Server
	client               OpenAIClient
	healthTimeoutSeconds int
	detections.IOManager
}

func NewOpenAIChatAdapter(ctx context.Context, srv *server.Server, config map[string]any) (server.AssistantAdapter, error) {
	apiUrl := module.GetStringDefault(config, "apiUrl", "")
	if apiUrl == "" {
		return nil, fmt.Errorf("openai_chat adapter requires apiUrl in config")
	}

	apiKey := module.GetStringDefault(config, "apiKey", "")
	opts, err := buildOpenAIClientOptions(apiUrl, apiKey)
	if err != nil {
		return nil, fmt.Errorf("openai_chat adapter config error: %w", err)
	}

	healthTimeoutSeconds := module.GetIntDefault(config, "healthTimeoutSeconds", DEFAULT_HEALTH_TIMEOUT_SECONDS)

	return &OpenAIChatAdapter{
		srv:                  srv,
		healthTimeoutSeconds: healthTimeoutSeconds,
		client:               NewOpenAIClientWrapper(openai.NewClient(opts...)),
		IOManager: &detections.ResourceManager{
			Config: srv.Config,
		},
	}, nil
}

func (a *OpenAIChatAdapter) Protocol() string {
	return "openai_chat"
}

func (a *OpenAIChatAdapter) Embed(ctx context.Context, req *model.EmbeddingRequest) (*model.EmbeddingResponse, error) {
	return nil, ErrEmbeddingsUnsupported
}

func (a *OpenAIChatAdapter) SupportsEmbeddings() bool {
	return false
}

func (a *OpenAIChatAdapter) SendMessage(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
	logger := log.FromContext(ctx)

	// Convert history and tools
	messages := convertHistoryToChatCompletions(logger, req)
	tools := convertToolConfigToChatCompletions(req)

	params := openai.ChatCompletionNewParams{
		Model:    req.Model,
		Messages: messages,
	}

	// MaxTokens (when set, e.g. by a per-sub-session budget) caps output tokens.
	if req.MaxTokens > 0 {
		params.MaxCompletionTokens = openai.Int(int64(req.MaxTokens))
	}

	if tools != nil {
		params.Tools = tools
	}

	// Call non-streaming API
	resp, err := a.client.ChatCompletionsNew(ctx, params)
	if err != nil {
		logger.WithFields(log.Fields{
			"model": req.Model,
		}).WithError(err).Error("error calling OpenAI ChatCompletions API")
		return nil, err
	}

	// Build model.Message from first choice
	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("no choices in response")
	}

	choice := resp.Choices[0]
	message := &model.Message{
		Id:            resp.ID,
		Role:          "assistant",
		ContentBlocks: []model.ContentBlock{},
	}

	// Process text content
	if choice.Message.Content != "" {
		message.ContentBlocks = append(message.ContentBlocks, model.ContentBlock{
			Type: "text",
			Text: choice.Message.Content,
		})
	}

	// Process tool calls
	for _, toolCall := range choice.Message.ToolCalls {
		// Tool calls have Type field indicating "function" or "custom"
		if toolCall.Type == "function" {
			message.ContentBlocks = append(message.ContentBlocks, model.ContentBlock{
				Type:  "tool_use",
				Id:    toolCall.ID,
				Name:  toolCall.Function.Name,
				Input: json.RawMessage(toolCall.Function.Arguments),
			})
		}
	}

	// Handle usage metadata
	message.Usage = &model.Usage{
		InputTokens:  int(resp.Usage.PromptTokens),
		OutputTokens: int(resp.Usage.CompletionTokens),
	}

	// Handle finish reason
	finishReason := string(choice.FinishReason)
	if finishReason == "stop" {
		finishReason = "end_turn"
	}
	message.StopReason = &finishReason

	return message, nil
}

func (a *OpenAIChatAdapter) SendMessageStream(ctx context.Context, req *model.ChatRequest) (*http.Response, *model.AuxMessageData, error) {
	logger := log.FromContext(ctx)

	messages := convertHistoryToChatCompletions(logger, req)
	tools := convertToolConfigToChatCompletions(req)

	params := openai.ChatCompletionNewParams{
		Model:    req.Model,
		Messages: messages,
		StreamOptions: openai.ChatCompletionStreamOptionsParam{
			IncludeUsage: openai.Bool(true),
		},
	}

	// MaxTokens (when set, e.g. by a per-sub-session budget) caps output tokens.
	if req.MaxTokens > 0 {
		params.MaxCompletionTokens = openai.Int(int64(req.MaxTokens))
	}

	if tools != nil {
		params.Tools = tools
	}

	// Use noTimeout context like Responses adapter
	noTimeoutContext := context.WithValue(context.Background(), web.ContextKeyRequestId, ctx.Value(web.ContextKeyRequestId))
	noTimeoutContext = context.WithValue(noTimeoutContext, web.ContextKeyRequestorId, ctx.Value(web.ContextKeyRequestorId))

	stream := a.client.ChatCompletionsNewStreaming(noTimeoutContext, params)

	response, bodyWriter := fabricateResponse(http.StatusOK)

	wg := &sync.WaitGroup{}
	writer := newSSEEventWriter(logger, bodyWriter)
	processor := newStreamProcessor(writer, req.Model, wg)

	err := stream.Err()
	if err != nil {
		bodyWriter.Close()
		logger.WithError(err).Error("error before first response from OpenAI ChatCompletions streaming API")

		replacement, _ := handleStreamError(err, processor.firstSend, writer, logger, req.Model)
		if replacement != nil {
			response = replacement
		}

		return response, nil, err
	}

	wg.Add(1)

	go func() {
		defer bodyWriter.Close()
		defer processor.releaseCaller()

		var finishReason string
		var usage openai.CompletionUsage

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

			chunk := stream.Current()

			err = processor.processChatCompletionChunk(chunk)
			if err != nil {
				processor.writeError(err)
				return
			}

			// Capture finish reason and usage from chunks
			if len(chunk.Choices) > 0 {
				if chunk.Choices[0].FinishReason != "" {
					finishReason = chunk.Choices[0].FinishReason
				}
			}

			// Update usage if present (it comes in the final chunk)
			if chunk.Usage.PromptTokens > 0 || chunk.Usage.CompletionTokens > 0 {
				usage = chunk.Usage
			}
		}

		processor.finalizeChatCompletion(finishReason, &usage)
	}()

	wg.Wait()

	return response, nil, nil
}

func (a *OpenAIChatAdapter) GetBalance(ctx context.Context) (*model.BalanceResponse, error) {
	return &model.BalanceResponse{
		Balance: UNUSED_BALANCE,
	}, nil
}

func (a *OpenAIChatAdapter) GetHealth(ctx context.Context) (*model.HealthResponse, error) {
	return checkOpenAIHealth(ctx, a.client, a.healthTimeoutSeconds)
}

func convertHistoryToChatCompletions(logger log.Interface, req *model.ChatRequest) []openai.ChatCompletionMessageParamUnion {
	messages := make([]openai.ChatCompletionMessageParamUnion, 0, len(req.Messages)+1)

	// 1. FIRST: Add system message if present
	prompt := req.System
	if req.SystemAppend != "" {
		prompt += "\n" + req.SystemAppend
	}
	if prompt != "" {
		messages = append(messages, openai.ChatCompletionMessageParamUnion{
			OfSystem: &openai.ChatCompletionSystemMessageParam{
				Content: openai.ChatCompletionSystemMessageParamContentUnion{
					OfString: openai.String(prompt),
				},
			},
		})
	}

	// 2. Convert message history
	for _, msg := range req.Messages {
		content := ""
		var toolCalls []openai.ChatCompletionMessageToolCallUnionParam
		var toolMessages []openai.ChatCompletionMessageParamUnion

		for _, block := range msg.ContentBlocks {
			if block.Type == "" && block.ToolResult != nil {
				block.Type = "tool_result"
			}

			switch block.Type {
			case "text":
				content += block.Text

			case "tool_use":
				// Assistant made a function call
				var args map[string]any
				if len(block.Input) > 0 {
					if err := json.Unmarshal(block.Input, &args); err != nil {
						logger.WithError(err).Error("failed to unmarshal tool use input")
						continue
					}
				}

				toolCall := openai.ChatCompletionMessageToolCallUnionParam{
					OfFunction: &openai.ChatCompletionMessageFunctionToolCallParam{
						ID: block.Id,
						Function: openai.ChatCompletionMessageFunctionToolCallFunctionParam{
							Name:      block.Name,
							Arguments: string(block.Input),
						},
					},
				}
				toolCalls = append(toolCalls, toolCall)

			case "tool_result":
				// User provided tool result
				if block.ToolResult != nil && len(block.ToolResult.Content) != 0 {
					var resultContent string
					if block.ToolResult.IsError {
						resultContent = fmt.Sprintf(`{"error": "%s"}`, block.ToolResult.Content[0].Text)
					} else {
						jsonBytes, err := json.Marshal(block.ToolResult.Content[0].Json)
						if err != nil {
							jsonBytes = []byte(`{"error": "failed to marshal tool result content"}`)
						}
						resultContent = string(jsonBytes)
					}

					toolMsg := openai.ChatCompletionMessageParamUnion{
						OfTool: &openai.ChatCompletionToolMessageParam{
							Content: openai.ChatCompletionToolMessageParamContentUnion{
								OfString: openai.String(resultContent),
							},
							ToolCallID: block.ToolResult.ToolUseId,
						},
					}
					toolMessages = append(toolMessages, toolMsg)
				}
			}
		}

		// Build message based on role and content type
		if msg.Role == "user" {
			if content != "" && content != "&nbsp;" {
				messages = append(messages, openai.ChatCompletionMessageParamUnion{
					OfUser: &openai.ChatCompletionUserMessageParam{
						Content: openai.ChatCompletionUserMessageParamContentUnion{
							OfString: openai.String(content),
						},
					},
				})
			}
		} else if msg.Role == "assistant" {
			assistantMsg := &openai.ChatCompletionAssistantMessageParam{}

			if content != "" && content != "&nbsp;" {
				assistantMsg.Content = openai.ChatCompletionAssistantMessageParamContentUnion{
					OfString: openai.String(content),
				}
			}

			if len(toolCalls) > 0 {
				assistantMsg.ToolCalls = toolCalls
			}

			messages = append(messages, openai.ChatCompletionMessageParamUnion{
				OfAssistant: assistantMsg,
			})
		}

		// Add tool messages after the assistant message
		messages = append(messages, toolMessages...)
	}

	return messages
}

func convertToolConfigToChatCompletions(req *model.ChatRequest) []openai.ChatCompletionToolUnionParam {
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

	tools := make([]openai.ChatCompletionToolUnionParam, 0, len(toolConfig.Tools))

	for _, toolSpec := range toolConfig.Tools {
		if toolSpec.Spec.InputSchema.Json == nil {
			continue
		}

		parameters := convertJSONSchemaToOpenAI(toolSpec.Spec.InputSchema.Json)

		var description param.Opt[string]
		if toolSpec.Spec.Description != "" {
			description = openai.String(toolSpec.Spec.Description)
		}

		toolParam := openai.ChatCompletionToolUnionParam{
			OfFunction: &openai.ChatCompletionFunctionToolParam{
				Function: openai.FunctionDefinitionParam{
					Name:        toolSpec.Spec.Name,
					Parameters:  openai.FunctionParameters(parameters),
					Description: description,
					Strict:      openai.Bool(true),
				},
			},
		}

		tools = append(tools, toolParam)
	}

	if len(tools) == 0 {
		return nil
	}

	return tools
}
