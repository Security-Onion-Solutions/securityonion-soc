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
	"sync"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/tidwall/gjson"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/genai"
)

func init() {
	adapters[(&GeminiAdapter{}).Name()] = NewGeminiAdapter
}

type GeminiAdapter struct {
	srv    *server.Server
	client GeminiClient
	detections.IOManager
}

func NewGeminiAdapter(ctx context.Context, srv *server.Server, config map[string]any) (server.AssistantAdapter, error) {
	var client *genai.Client
	var err error

	serviceAccountJSON := module.GetStringDefault(config, "serviceAccountJSON", "")
	serviceAccountLocation := module.GetStringDefault(config, "serviceAccountLocation", "")

	if serviceAccountJSON != "" && serviceAccountLocation != "" {
		client, err = BuildClientServiceAccount(ctx, serviceAccountJSON, serviceAccountLocation)
	} else {
		apiKey := module.GetStringDefault(config, "apiKey", "")
		client, err = buildClientFromApiKey(ctx, apiKey)
	}
	if err != nil {
		return nil, err
	}

	return &GeminiAdapter{
		srv:    srv,
		client: NewGeminiClientWrapper(client),
		IOManager: &detections.ResourceManager{
			Config: srv.Config,
		},
	}, nil
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

func BuildClientServiceAccount(ctx context.Context, servAccountJSON string, location string) (*genai.Client, error) {
	const scopeCloudPlatform = "https://www.googleapis.com/auth/cloud-platform"

	gjRes := gjson.Get(servAccountJSON, "project_id")
	if !gjRes.Exists() {
		return nil, fmt.Errorf("service account json does not contain project_id")
	}
	projID := gjRes.Str

	// 1) Explicitly load credentials from the JSON you were given.
	// The Google auth library owns token URLs/endpoints and any future changes.
	creds, err := google.CredentialsFromJSON(ctx, []byte(servAccountJSON), scopeCloudPlatform)
	if err != nil {
		return nil, err
	}

	// 2) Explicitly construct an HTTP client that uses that TokenSource.
	authHTTPClient := oauth2.NewClient(ctx, creds.TokenSource)

	// 3) Use your authenticated HTTP client with the GenAI client.
	return genai.NewClient(ctx, &genai.ClientConfig{
		Project:    projID,
		Location:   location,
		Backend:    genai.BackendVertexAI,
		HTTPClient: authHTTPClient,
	})
}

func (a *GeminiAdapter) Name() string {
	return "gemini"
}

func (a *GeminiAdapter) SendMessage(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
	logger := log.FromContext(ctx)

	history := convertHistory(req)
	tools, toolConfig := convertToolConfig(req)

	latest := history[len(history)-1]
	history = history[:len(history)-1]

	prompt := make([]*genai.Part, 0, 2)
	if req.System != "" {
		prompt = append(prompt, &genai.Part{Text: req.System})
	}
	if req.SystemAppend != "" {
		prompt = append(prompt, &genai.Part{Text: req.SystemAppend})
	}

	session, err := a.client.CreateSession(ctx, req.Model, &genai.GenerateContentConfig{
		SystemInstruction: &genai.Content{
			Parts: prompt,
		},
		Tools:      tools,
		ToolConfig: toolConfig,
		ThinkingConfig: &genai.ThinkingConfig{
			IncludeThoughts: true,
		},
	}, history)
	if err != nil {
		return nil, err
	}

	// Send message (non-streaming)
	resp, err := session.SendMessage(ctx, *latest.Parts[0])
	if err != nil {
		logger.WithFields(log.Fields{
			"model": req.Model,
		}).WithError(err).Error("error sending message to gemini")
		return nil, err
	}

	// Convert response to model.Message
	message := &model.Message{
		Id:            "assistant",
		Role:          "assistant",
		ContentBlocks: []model.ContentBlock{},
	}

	// Get text content
	text := resp.Text()
	if text != "" {
		message.ContentBlocks = append(message.ContentBlocks, model.ContentBlock{
			Type: "text",
			Text: text,
		})
	}

	// Get function calls
	functionCalls := resp.FunctionCalls()
	for _, fc := range functionCalls {
		inputJSON, err := json.Marshal(fc.Args)
		if err != nil {
			logger.WithError(err).WithField("functionCall", fc).Error("failed to marshal function call args")
			continue
		}

		toolUseId := fc.ID
		if toolUseId == "" {
			toolUseId = fmt.Sprintf("toolu_%d", len(message.ContentBlocks))
		}

		// Find thought signature for this tool use
		var thoughtSignature []byte
		for _, cand := range resp.Candidates {
			for _, part := range cand.Content.Parts {
				if part.FunctionCall != nil && part.FunctionCall.ID == fc.ID {
					thoughtSignature = part.ThoughtSignature
					break
				}
			}
		}

		message.ContentBlocks = append(message.ContentBlocks, model.ContentBlock{
			Type:             "tool_use",
			Id:               toolUseId,
			Name:             fc.Name,
			Input:            inputJSON,
			ThoughtSignature: thoughtSignature,
		})
	}

	// Set stop reason
	for _, cand := range resp.Candidates {
		if cand.FinishReason != "" {
			stopReason := string(cand.FinishReason)
			message.StopReason = &stopReason
			break
		}
	}

	// Set usage metadata
	if resp.UsageMetadata != nil {
		message.Usage = &model.Usage{
			InputTokens:  int(resp.UsageMetadata.PromptTokenCount),
			OutputTokens: int(resp.UsageMetadata.CandidatesTokenCount),
		}
	}

	return message, nil
}

func (a *GeminiAdapter) SendMessageStream(ctx context.Context, req *model.ChatRequest) (response *http.Response, aux *model.AuxMessageData, err error) {
	logger := log.FromContext(ctx)

	history := convertHistory(req)
	tools, toolConfig := convertToolConfig(req)

	latest := history[len(history)-1]
	history = history[:len(history)-1]

	prompt := make([]*genai.Part, 0, 2)
	if req.System != "" {
		prompt = append(prompt, &genai.Part{Text: req.System})
	}
	if req.SystemAppend != "" {
		prompt = append(prompt, &genai.Part{Text: req.SystemAppend})
	}

	session, err := a.client.CreateSession(ctx, req.Model, &genai.GenerateContentConfig{
		SystemInstruction: &genai.Content{
			Parts: prompt,
		},
		Tools:      tools,
		ToolConfig: toolConfig,
		ThinkingConfig: &genai.ThinkingConfig{
			IncludeThoughts: true,
		},
	}, history)
	if err != nil {
		return nil, nil, err
	}

	response, bodyWriter := fabricateResponse(http.StatusOK)

	aux = &model.AuxMessageData{
		ThoughtSignatures: map[string][]byte{},
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)

	// Create SSE writer and stream processor
	writer := newSSEEventWriter(bodyWriter)
	processor := newStreamProcessor(writer, req.Model, wg)

	go func() {
		defer bodyWriter.Close()

		finishReason := "end_turn"
		var finalResp *genai.GenerateContentResponse

		// don't allow a user closing their request connection to cause us to lose the message stream
		noTimeoutContext := context.WithValue(context.Background(), web.ContextKeyRequestId, ctx.Value(web.ContextKeyRequestId))
		noTimeoutContext = context.WithValue(noTimeoutContext, web.ContextKeyRequestorId, ctx.Value(web.ContextKeyRequestorId))

		for resp, err := range session.SendMessageStream(noTimeoutContext, *latest.Parts[0]) {
			if err != nil {
				replacement, shouldReturn := handleStreamError(err, processor.firstSend, writer, logger, req.Model)
				if shouldReturn {
					if replacement != nil {
						response = replacement
					}
					return
				}
			}

			// Process chunk - automatically handles first send on first delta
			thoughtSigs, reason, err := processor.processChunk(resp)
			if err != nil {
				// Mid-stream error during processing
				processor.writeError(err)
				return
			}

			// Collect thought signatures into aux
			for toolId, sig := range thoughtSigs {
				aux.ThoughtSignatures[toolId] = sig
			}

			// Track finish reason and final response
			if reason != "" {
				finishReason = reason
			}
			finalResp = resp
		}

		var usage *genai.GenerateContentResponseUsageMetadata
		if finalResp != nil && finalResp.UsageMetadata != nil {
			usage = finalResp.UsageMetadata
		}

		// Finalization - processor handles closing blocks and writing final events
		processor.finalize(finishReason, usage)
	}()

	wg.Wait()

	return response, aux, nil
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
	// Collect all function declarations into a single Tool object for Vertex AI compatibility
	functionDeclarations := make([]*genai.FunctionDeclaration, 0, len(toolConfig.Tools))

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

		functionDeclarations = append(functionDeclarations, funcDecl)
	}

	// Create a single Tool with all function declarations
	// This works with both Gemini API and Vertex AI backends
	tools := []*genai.Tool{
		{
			FunctionDeclarations: functionDeclarations,
		},
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

func getThought(resp *genai.GenerateContentResponse) (thought string) {
	for _, cand := range resp.Candidates {
		for _, part := range cand.Content.Parts {
			if part.Thought {
				thought += part.Text
			}
		}
	}

	return thought
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
		// No response sent to client yet - fabricate error response
		logger.WithFields(log.Fields{
			"model": model,
		}).WithError(err).Error("first response error from gemini")

		var body *io.PipeWriter
		response, body := fabricateResponse(http.StatusInternalServerError)

		// Write to pipe in goroutine to avoid blocking
		go func() {
			fmt.Fprint(body, "ERROR_GEMINI_FIRST_RESPONSE")
			body.Close()
		}()

		return response, true
	}

	// Error after partial response sent to client
	logger.WithFields(log.Fields{
		"model": model,
	}).WithError(err).Error("subsequent response error from gemini")

	writer.writeError(err.Error())
	writer.writeDone()

	return nil, true
}
