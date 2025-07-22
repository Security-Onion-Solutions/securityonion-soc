// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"

	"github.com/google/uuid"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	modcontext "github.com/security-onion-solutions/securityonion-soc/server/modules/context"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
)

const (
	DEFAULT_APIKEY = ""
	DEFAULT_APIURL = "https://b7cdq33i55t73bzisq7gplzd340mvxgo.lambda-url.us-east-2.on.aws/"
	DEFAULT_MODEL  = "claude-sonnet"
)

var (
	ErrToolNotFound = errors.New("tool not found")
)

type AssistantCoordinator struct {
	srv       *server.Server
	apiKey    string
	apiUrl    string
	model     string
	isRunning bool

	FunctionLibrary map[string]Tool
	toolConfig      json.RawMessage

	detections.IOManager
}

func NewAssistantManager(srv *server.Server) *AssistantCoordinator {
	return &AssistantCoordinator{
		srv:       srv,
		IOManager: &detections.ResourceManager{Config: srv.Config},
	}
}

func (ac *AssistantCoordinator) PrerequisiteModules() []string {
	return nil
}

func (ac *AssistantCoordinator) Init(config module.ModuleConfig) (err error) {
	ac.srv.AssistantManager = ac
	ac.FunctionLibrary = knownTools

	ac.apiKey = module.GetStringDefault(config, "apiKey", DEFAULT_APIKEY)
	ac.apiUrl = module.GetStringDefault(config, "apiUrl", DEFAULT_APIURL)
	ac.model = module.GetStringDefault(config, "model", DEFAULT_MODEL)

	ac.toolConfig, err = buildToolConfig(ac.FunctionLibrary)

	return err
}

func buildToolConfig(functions map[string]Tool) (json.RawMessage, error) {
	keys := []string{}
	for key := range functions {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	toolSpecs := make([]*model.ToolSpec, 0, len(keys))

	for _, key := range keys {
		tool := functions[key]

		toolSpecs = append(toolSpecs, &model.ToolSpec{
			Spec: model.ToolDefinition{
				Name:        tool.GetName(),
				Description: tool.GetDescription(),
				InputSchema: tool.GetSchema(),
			},
		})
	}

	tc := &model.ToolConfig{
		Tools: toolSpecs,
		ToolChoice: map[string]any{
			"auto": map[string]any{},
		},
	}

	result, err := json.Marshal(tc)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (ac *AssistantCoordinator) Start() error {
	ac.isRunning = true

	return nil
}

func (ac *AssistantCoordinator) Stop() error {
	ac.isRunning = false

	return nil
}

func (ac *AssistantCoordinator) IsRunning() bool {
	return ac.isRunning
}

func (ac *AssistantCoordinator) Chat(ctx context.Context, messages []*model.ChatMessage, opts ...model.ChatOpt) (*model.ChatResponse, error) {
	logger := log.FromContext(ctx)
	userID := ctx.Value(web.ContextKeyRequestorId).(string)
	config := model.ApplyChatOpts(opts...)

	req := &model.ChatRequest{
		Messages:   messages,
		UserUUID:   userID,
		ToolConfig: ac.toolConfig,
	}

	u, err := url.Parse(ac.apiUrl)
	if err != nil {
		logger.WithError(err).WithField("apiUrl", ac.apiUrl).Error("unable to parse apiUrl")

		return nil, err
	}

	u.Path = path.Join(u.Path, "/api/chat")
	endpoint := u.String()

	var buf bytes.Buffer

	err = json.NewEncoder(&buf).Encode(req)
	if err != nil {
		logger.WithError(err).WithField("chatrequest", req).Error("unable to encode ChatRequest")
		return nil, err
	}

	httpReq, err := http.NewRequest(http.MethodPost, endpoint, &buf)
	if err != nil {
		logger.WithError(err).WithField("apiEndpoint", endpoint).Error("unable to make request object")

		return nil, err
	}

	httpReq.Header.Add("Content-Type", "application/json")
	httpReq.Header.Add("x-api-key", ac.apiKey)

	res, err := ac.MakeRequest(httpReq, false)
	if err != nil {
		logger.WithError(err).Error("unable to execute request")

		return nil, err
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		logger.WithError(err).Error("unable to read response body")

		return nil, err
	}

	logger.WithField("rawChatResponseBody", string(resBody)).Debug("chat response received")

	response := &model.ChatResponse{}

	err = json.Unmarshal(resBody, response)
	if err != nil {
		logger.WithError(err).WithField("rawChatResponseBody", string(resBody)).Error("unable to unmarhsal JSON response")
		return nil, err
	}

	// Check if Claude made any tool use requests and handle based on config
	if config.AutoExecuteTools {
		for _, content := range response.Content {
			if content.Type == "tool_use" {
				// Execute the tool and add result back to conversation
				result, err := ac.ExecuteTool(ctx, content.Name, string(content.Input))
				if err != nil {
					logger.WithError(err).WithField("toolName", content.Name).Error("failed to execute tool")
					continue
				}

				// Create tool result message to add to conversation history
				toolResultJSON, err := json.Marshal(result.Result)
				if err != nil {
					logger.WithError(err).WithField("toolResult", result.Result).Error("failed to marshal tool result")
					continue
				}

				// Note: This would typically be added to the messages array for the next request
				// The calling code should handle appending this to the conversation
				logger.WithFields(log.Fields{
					"toolName":   content.Name,
					"toolId":     content.ID,
					"toolResult": string(toolResultJSON),
				}).Info("tool executed successfully for chat response")

				// append to message history and recurse to send the tool result back with context
				messages = append(messages, &model.ChatMessage{
					Role:       "user",
					ToolUseID:  content.ID,
					ToolResult: toolResultJSON,
				})

				toolResponse, err := ac.Chat(ctx, messages, model.WithAutoExecuteTools(true))
				if err != nil {
					logger.WithError(err).Error("failed to chat with assistant after tool execution")
					return nil, err
				}

				response = toolResponse
			}
		}
	}

	return response, nil
}

func (ac *AssistantCoordinator) ChatStream(ctx context.Context, messages []*model.ChatMessage) (*http.Response, error) {
	logger := log.FromContext(ctx)
	userID := ctx.Value(web.ContextKeyRequestorId).(string)

	req := &model.ChatRequest{
		Messages:   messages,
		UserUUID:   userID,
		Stream:     true,
		ToolConfig: ac.toolConfig,
	}

	u, err := url.Parse(ac.apiUrl)
	if err != nil {
		logger.WithError(err).WithField("apiUrl", ac.apiUrl).Error("unable to parse apiUrl")

		return nil, err
	}

	u.Path = path.Join(u.Path, "/api/chat")
	endpoint := u.String()

	var buf bytes.Buffer

	err = json.NewEncoder(&buf).Encode(req)
	if err != nil {
		logger.WithError(err).WithField("chatrequest", req).Error("unable to encode ChatRequest")
		return nil, err
	}

	httpReq, err := http.NewRequest(http.MethodPost, endpoint, &buf)
	if err != nil {
		logger.WithError(err).WithField("apiEndpoint", endpoint).Error("unable to make request object")

		return nil, err
	}

	httpReq.Header.Add("Content-Type", "application/json")
	httpReq.Header.Add("x-api-key", ac.apiKey)
	httpReq.Header.Add("Accept", "text/event-stream")

	res, err := ac.MakeRequest(httpReq, true)
	if err != nil {
		logger.WithError(err).Error("unable to execute request")

		return nil, err
	}

	return res, nil
}

func (ac *AssistantCoordinator) ExecuteTool(ctx context.Context, toolName string, params string) (*model.ToolResult, error) {

	logger := log.FromContext(ctx).WithFields(log.Fields{
		"toolName":  toolName,
		"toolUseId": uuid.New().String(),
	})

	tool, ok := ac.FunctionLibrary[toolName]
	if !ok {
		logger.Error("tool not found")
		return nil, ErrToolNotFound
	}

	assistantCtx := modcontext.WriteIsAssistant(ctx, true)
	assistantCtx = log.NewContext(assistantCtx, logger)

	userID := ctx.Value(web.ContextKeyRequestorId).(string)
	logger.WithFields(log.Fields{
		"toolName": toolName,
		"userId":   userID,
	}).Info("executing tool for assistant")

	result, err := tool.Execute(assistantCtx, ac.srv, params)
	if err != nil {
		logger.WithError(err).Error("error executing tool")
		return nil, err
	}

	logger.WithFields(log.Fields{
		"result": result,
	}).Info("tool executed successfully")

	return result, nil
}

func (ac *AssistantCoordinator) Balance(ctx context.Context) (*model.BalanceResponse, error) {
	logger := log.FromContext(ctx)

	u, err := url.Parse(ac.apiUrl)
	if err != nil {
		logger.WithError(err).WithField("apiUrl", ac.apiUrl).Error("unable to parse apiUrl")

		return nil, err
	}

	u.Path = path.Join(u.Path, "/api/balance")
	endpoint := u.String()

	httpReq, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		logger.WithError(err).Error("unable to make request object")

		return nil, err
	}

	httpReq.Header.Add("x-api-key", ac.apiKey)

	res, err := ac.MakeRequest(httpReq, false)
	if err != nil {
		logger.WithError(err).WithField("apiEndpoint", endpoint).Error("unable to execute request")

		return nil, err
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		logger.WithError(err).Error("unable to read response body")

		return nil, err
	}

	logger.WithField("rawBalanceResponseBody", string(resBody)).Debug("balance response received")

	response := &model.BalanceResponse{}

	err = json.Unmarshal(resBody, response)
	if err != nil {
		logger.WithError(err).WithField("rawBalanceResponseBody", string(resBody)).Error("unable to unmarhsal JSON response")
		return nil, err
	}

	return response, nil
}
