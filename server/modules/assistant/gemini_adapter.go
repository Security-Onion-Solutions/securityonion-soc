// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"google.golang.org/genai"
)

type GeminiAdapter struct {
	srv    *server.Server
	client *genai.Client
	detections.IOManager
}

func NewGeminiAdapter(ctx context.Context, srv *server.Server, apiKey string) *GeminiAdapter {
	client, err := buildClientFromApiKey(ctx, apiKey)
	if err != nil {
		panic(err)
	}

	return &GeminiAdapter{
		srv:    srv,
		client: client,
		IOManager: &detections.ResourceManager{
			Config: srv.Config,
		},
	}
}

func buildClientFromApiKey(ctx context.Context, apikey string) (client *genai.Client, err error) {
	cfg := &genai.ClientConfig{
		APIKey:  apikey,
		Backend: genai.BackendGeminiAPI,
	}

	client, err = genai.NewClient(ctx, cfg)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (a *GeminiAdapter) Name() string {
	return "gemini"
}

func (a *GeminiAdapter) SendMessage(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
	return nil, nil
}

func (a *GeminiAdapter) SendMessageStream(ctx context.Context, req *model.ChatRequest) (*http.Response, error) {
	// %s = model
	const msgStart = `data: {"type":"message_start","message":{"id":"assistant","type":"message","role":"assistant","content":[],"model":"%s","stop_reason":null,"stop_sequence":null}}` + "\n\n"
	// %s = model tokens
	const contentBlockDelta = `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"%s"}}` + "\n\n"
	const contentBlockStop = `data: {"type":"content_block_stop","index":0}` + "\n\n"
	// %d = index, %s = content block JSON
	const contentBlockStart = `data: {"type":"content_block_start","index":%d,"content_block":%s}` + "\n\n"
	// %d = index, %s = partial JSON as string
	const inputJsonDelta = `data: {"type":"content_block_delta","index":%d,"delta":{"type":"input_json_delta","partial_json":"%s"}}` + "\n\n"
	// %d = index
	const contentBlockStopIndexed = `data: {"type":"content_block_stop","index":%d}` + "\n\n"
	// %s = stop reason
	const stopReason = `data: {"type":"message_delta","delta":{"stop_reason":"%s","stop_sequence":null}}` + "\n\n"
	// %d = input tokens, %d = output tokens
	const usage = `data: {"type":"message_delta","usage":{"input_tokens":%d,"output_tokens":%d}}` + "\n\n"
	const msgStop = `data: {"type":"message_stop"}` + "\n\n"
	const done = `data: [DONE]`

	history := convertHistory(req)
	tools, toolConfig := convertToolConfig(req)

	latest := history[len(history)-1]
	history = history[:len(history)-1]

	session, err := a.client.Chats.Create(ctx, req.Model, &genai.GenerateContentConfig{
		SystemInstruction: &genai.Content{
			Parts: []*genai.Part{
				{Text: req.SystemAppend},
			},
		},
		Tools:      tools,
		ToolConfig: toolConfig,
	}, history)
	if err != nil {
		return nil, err
	}

	bodyReader, bodyWriter := io.Pipe()

	res := &http.Response{
		StatusCode: http.StatusOK,
		Body:       bodyReader,
		Header:     make(http.Header),
	}

	res.Header.Add("Content-Type", "text/event-stream")

	go func() {
		defer bodyWriter.Close()

		// don't start writing the response until the first bit of content is received
		firstSend := true
		contentBlockIndex := 0
		hasOpenBlock := false

		var finalResp *genai.GenerateContentResponse
		finishReason := "end_turn"

		thoughtSignatures := map[string][]byte{}

		// don't allow a user closing their request connection to cause us to lose the message stream
		noTimeoutContext := context.WithValue(context.Background(), web.ContextKeyRequestId, ctx.Value(web.ContextKeyRequestId))
		noTimeoutContext = context.WithValue(noTimeoutContext, web.ContextKeyRequestorId, ctx.Value(web.ContextKeyRequestorId))

		for resp, err := range session.SendMessageStream(noTimeoutContext, *latest.Parts[0]) {
			if err != nil {
				panic(err)
			}
			_, _, _ = tools, toolConfig, history

			finalResp = resp

			if firstSend {
				firstSend = false
				fmt.Fprintf(bodyWriter, msgStart, req.Model)
			}

			// Handle text content
			text := resp.Text()
			if text != "" {
				// escape quotes, but remove surrounding quotes added by strconv.Quote
				escapedText := strings.TrimSuffix(strings.TrimPrefix(strconv.Quote(text), "\""), "\"")
				fmt.Fprintf(bodyWriter, contentBlockDelta, escapedText)
				hasOpenBlock = true
			}

			// Handle function calls
			functionCalls := resp.FunctionCalls()
			if len(functionCalls) > 0 {
				// Close text content block if it was open
				if hasOpenBlock {
					fmt.Fprint(bodyWriter, contentBlockStop)
					contentBlockIndex++
					hasOpenBlock = false
				}

				for _, cand := range resp.Candidates {
					for _, part := range cand.Content.Parts {
						if part.FunctionCall != nil {
							// Record thought signature for this tool use
							toolUseId := part.FunctionCall.ID
							if toolUseId == "" {
								toolUseId = fmt.Sprintf("toolu_%d", contentBlockIndex)
							}
							thoughtSignatures[toolUseId] = part.ThoughtSignature
						}
					}

					if cand.FinishReason != "" {
						finishReason = string(cand.FinishReason)
					}
				}

				// Process each function call
				for _, fc := range functionCalls {
					toolUseId := fc.ID
					if toolUseId == "" {
						toolUseId = fmt.Sprintf("toolu_%d", contentBlockIndex)
					}

					toolUseBlock := map[string]any{
						"type":              "tool_use",
						"id":                toolUseId,
						"name":              fc.Name,
						"input":             map[string]any{},
						"thought_signature": thoughtSignatures[toolUseId],
					}
					toolUseJSON, _ := json.Marshal(toolUseBlock)
					fmt.Fprintf(bodyWriter, contentBlockStart, contentBlockIndex, string(toolUseJSON))

					// Send function arguments as input_json_delta
					if len(fc.Args) > 0 {
						argsJSON, err := json.Marshal(fc.Args)
						if err == nil {
							// escape quotes in the JSON
							escapedJSON := strings.TrimSuffix(strings.TrimPrefix(strconv.Quote(string(argsJSON)), "\""), "\"")
							fmt.Fprintf(bodyWriter, inputJsonDelta, contentBlockIndex, escapedJSON)
						}
					}

					fmt.Fprintf(bodyWriter, contentBlockStopIndexed, contentBlockIndex)
					contentBlockIndex++
				}
			}
		}

		// Close any remaining open text block
		if hasOpenBlock {
			fmt.Fprint(bodyWriter, contentBlockStop)
		}

		if finishReason == "" {
			finishReason = "end_turn"
		}

		fmt.Fprintf(bodyWriter, stopReason, finishReason)
		if finalResp.UsageMetadata != nil {
			fmt.Fprintf(bodyWriter, usage, finalResp.UsageMetadata.PromptTokenCount, finalResp.UsageMetadata.CandidatesTokenCount)
		}
		fmt.Fprint(bodyWriter, msgStop)
		fmt.Fprint(bodyWriter, done)
	}()

	return res, nil
}

func (a *GeminiAdapter) GetBalance(ctx context.Context) (*model.BalanceResponse, error) {
	return &model.BalanceResponse{
		Balance: 100,
	}, nil
}

func (a *GeminiAdapter) GetHealth(ctx context.Context) (*model.HealthResponse, error) {
	return &model.HealthResponse{
		Status: "healthy",
	}, nil
}

func convertHistory(req *model.ChatRequest) []*genai.Content {
	history := make([]*genai.Content, 0, len(req.Messages))

	prevToolName := ""

	for _, msg := range req.Messages {
		parts := make([]*genai.Part, 0, len(msg.ContentBlocks))

		// Process each content block in the message
		for _, block := range msg.ContentBlocks {
			if block.Type == "" && block.ToolResult != nil {
				block.Type = "tool_result"
			}

			switch block.Type {
			case "text":
				// Handle text content
				if block.Text != "" {
					parts = append(parts, &genai.Part{
						Text: block.Text,
					})
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

				parts = append(parts, &genai.Part{
					FunctionCall: &genai.FunctionCall{
						ID:   block.Id,
						Name: block.Name,
						Args: args,
					},
					ThoughtSignature: block.ThoughtSignature,
				})

				prevToolName = block.Name
			case "tool_result":
				// Handle tool results (responses from user with tool execution results)
				if block.ToolResult != nil {
					// Combine all content into a single response
					var responseText string
					for _, content := range block.ToolResult.Content {
						if content.Text != "" {
							responseText += content.Text
						}
						if content.Json != nil {
							jsonBytes, err := json.Marshal(content.Json)
							if err == nil {
								responseText += string(jsonBytes)
							}
						}
					}

					name := block.ToolResult.Name
					if name == "" {
						name = prevToolName
					}

					parts = append(parts, &genai.Part{
						FunctionResponse: &genai.FunctionResponse{
							ID:       block.ToolResult.ToolUseId,
							Name:     name,
							Response: map[string]any{"result": responseText},
						},
					})
				}
			default:
				// For any other type, try to use text if available
				if block.Text != "" {
					parts = append(parts, &genai.Part{
						Text: block.Text,
					})
				}
			}
		}

		// Only add to history if we have parts
		if len(parts) > 0 {
			role := genai.RoleUser
			if msg.Role == "assistant" {
				role = genai.RoleModel
			}

			history = append(history, &genai.Content{
				Role:  role,
				Parts: parts,
			})
		}
	}

	return history
}

func convertToolConfig(req *model.ChatRequest) ([]*genai.Tool, *genai.ToolConfig) {
	if req.ToolConfig == nil {
		return nil, nil
	}

	var toolConfig model.ToolConfig
	if err := json.Unmarshal(req.ToolConfig, &toolConfig); err != nil {
		return nil, nil
	}

	if len(toolConfig.Tools) == 0 {
		return nil, nil
	}

	// Convert tool specifications to Gemini function declarations
	tools := make([]*genai.Tool, 0, len(toolConfig.Tools))

	for _, toolSpec := range toolConfig.Tools {
		if toolSpec.Spec.InputSchema == (model.JSONSchema{}) {
			continue
		}

		inputSchema := convertJSONSchemaToGemini(toolSpec.Spec.InputSchema.Json)

		funcDecl := &genai.FunctionDeclaration{
			Name:        toolSpec.Spec.Name,
			Description: toolSpec.Spec.Description,
			Parameters:  inputSchema,
		}

		t := &genai.Tool{
			FunctionDeclarations: []*genai.FunctionDeclaration{funcDecl},
		}

		tools = append(tools, t)
	}

	// Configure function calling mode
	toolConfigResult := &genai.ToolConfig{
		FunctionCallingConfig: &genai.FunctionCallingConfig{
			Mode: genai.FunctionCallingConfigModeAuto,
		},
	}

	return tools, toolConfigResult
}

func convertJSONSchemaToGemini(schema *model.ToolSchema) *genai.Schema {
	if schema == nil {
		return nil
	}

	geminiSchema := &genai.Schema{
		Type:       convertTypeToGemini(schema.Type),
		Properties: make(map[string]*genai.Schema),
		Required:   schema.Required,
	}

	for propName, propSchema := range schema.Properties {
		geminiSchema.Properties[propName] = convertPropertyToGemini(&propSchema)
	}

	return geminiSchema
}

func convertPropertyToGemini(prop *model.ToolSchemaProperty) *genai.Schema {
	schema := &genai.Schema{
		Type:        convertTypeToGemini(prop.Type),
		Description: prop.Description,
	}

	if prop.Default != nil {
		schema.Default = prop.Default
	}

	// Handle nested properties for object types
	if len(prop.Items) > 0 {
		if schema.Type == genai.TypeObject {
			schema.Properties = map[string]*genai.Schema{}
			for itemName, itemSchema := range prop.Items {
				schema.Properties[itemName] = convertPropertyToGemini(&itemSchema)
			}
		} else {
			for _, itemSchema := range prop.Items {
				schema.Items = convertPropertyToGemini(&itemSchema)
			}
		}
	}

	return schema
}

func convertTypeToGemini(typeStr string) genai.Type {
	switch typeStr {
	case "string":
		return genai.TypeString
	case "integer":
		return genai.TypeInteger
	case "number":
		return genai.TypeNumber
	case "boolean":
		return genai.TypeBoolean
	case "object":
		return genai.TypeObject
	case "array":
		return genai.TypeArray
	default:
		return genai.TypeString
	}
}
