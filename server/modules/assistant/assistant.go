// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	modcontext "github.com/security-onion-solutions/securityonion-soc/server/modules/context"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/google/uuid"
)

const (
	DEFAULT_APIURL                            = "https://onionai.securityonion.net/"
	DEFAULT_HEALTH_TIMEOUT_SECONDS            = 3
	DEFAULT_SYSTEM_PROMPT_ADDENDUM            = ""
	DEFAULT_SYSTEM_PROMPT_ADDENDUM_MAX_LENGTH = 50000
)

var (
	ErrToolNotFound = errors.New("tool not found")
)

type AssistantCoordinator struct {
	srv                  *server.Server
	apiKey               string
	apiUrl               string
	healthTimeoutSeconds int
	systemPromptAddendum string
	isRunning            bool

	FunctionLibrary map[string]Tool
	toolConfig      json.RawMessage

	detections.IOManager
}

func NewAssistantCoordinator(srv *server.Server) *AssistantCoordinator {
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

	ac.apiUrl = module.GetStringDefault(config, "apiUrl", DEFAULT_APIURL)
	ac.healthTimeoutSeconds = module.GetIntDefault(config, "healthTimeoutSeconds", DEFAULT_HEALTH_TIMEOUT_SECONDS)
	ac.systemPromptAddendum = module.GetStringDefault(config, "systemPromptAddendum", DEFAULT_SYSTEM_PROMPT_ADDENDUM)

	maxLength := module.GetIntDefault(config, "systemPromptAddendumMaxLength", DEFAULT_SYSTEM_PROMPT_ADDENDUM_MAX_LENGTH)
	if len(ac.systemPromptAddendum) > maxLength {
		ac.systemPromptAddendum = ac.systemPromptAddendum[:maxLength]
	}

	ac.toolConfig, err = buildToolConfig(ac.FunctionLibrary)

	ac.apiKey = buildApiKey()

	return err
}

func buildApiKey() string {
	key := licensing.GetLicenseKey()
	hash := sha256.Sum256([]byte(key.Signature))

	return fmt.Sprintf("sk-%s", hex.EncodeToString(hash[:]))
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

func (ac *AssistantCoordinator) Chat(ctx context.Context, messages []*model.Message, opts ...model.ChatOpt) ([]*model.Message, error) {
	logger := log.FromContext(ctx)
	userID := ctx.Value(web.ContextKeyRequestorId).(string)
	config := model.ApplyChatOpts(opts...)

	msgs := cleanupMessages(messages)

	req := &model.ChatRequest{
		Messages:     msgs,
		ToolConfig:   ac.toolConfig,
		UserId:       userID,
		SystemAppend: ac.systemPromptAddendum,
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
	ac.prepareRequestHeaders(httpReq)

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

	response := &model.Message{}

	err = json.Unmarshal(resBody, response)
	if err != nil {
		logger.WithError(err).WithField("rawChatResponseBody", string(resBody)).Error("unable to unmarhsal JSON response")
		return nil, err
	}

	newMessages := []*model.Message{response}

	// Check if Claude made any tool use requests and handle based on config
	if config.AutoExecuteTools {
		responses := []*model.Message{response}
		for i := 0; i < len(responses); i++ {
			for _, content := range responses[i].ContentBlocks {
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
						"toolUseId":  content.Id,
						"toolResult": string(toolResultJSON),
					}).Info("tool executed successfully for chat response")

					toolMsg := &model.Message{
						Id:   uuid.NewString(),
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{
								Type: "text",
								Text: fmt.Sprintf("ToolUseId: %s, Result: %s", content.Id, string(toolResultJSON)),
							},
						},
					}

					newMessages = append(newMessages, toolMsg)

					err = ac.srv.Assistantstore.SaveChat(ctx, toolMsg.PrepareForStorage("", []string{"tool_result"}))
					if err != nil {
						logger.WithError(err).Error("unable to save tool result message")
						return nil, err
					}

					// append to message history and recurse to send the tool result back with context
					messages = append(messages, toolMsg)

					toolResponse, err := ac.Chat(ctx, messages, model.WithAutoExecuteTools(true))
					if err != nil {
						logger.WithError(err).Error("failed to chat with assistant after tool execution")
						return nil, err
					}

					newMessages = append(newMessages, toolResponse...)
					responses = append(responses, toolResponse...)
				}
			}
		}
	}

	return newMessages, nil
}

func (ac *AssistantCoordinator) ChatStream(ctx context.Context, messages []*model.Message) (*http.Response, error) {
	logger := log.FromContext(ctx)
	userID := ctx.Value(web.ContextKeyRequestorId).(string)

	// copy and modify
	msgs := cleanupMessages(messages)

	req := &model.ChatRequest{
		Messages:     msgs,
		Stream:       true,
		ToolConfig:   ac.toolConfig,
		UserId:       userID,
		SystemAppend: ac.systemPromptAddendum,
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

	logger.WithField("outgoingChatBodySize", buf.Len()).Info("outgoing chat request body")

	httpReq, err := http.NewRequest(http.MethodPost, endpoint, &buf)
	if err != nil {
		logger.WithError(err).WithField("apiEndpoint", endpoint).Error("unable to make request object")

		return nil, err
	}

	httpReq.Header.Add("Content-Type", "application/json")
	httpReq.Header.Add("Accept", "text/event-stream")
	ac.prepareRequestHeaders(httpReq)

	res, err := ac.MakeRequest(httpReq, true)
	if err != nil {
		logger.WithError(err).Error("unable to execute request")

		return nil, err
	}

	return res, nil
}

func (ac *AssistantCoordinator) ExecuteTool(ctx context.Context, toolName string, params string) (*model.ToolResponse, error) {
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
		"toolResult": result,
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

	ac.prepareRequestHeaders(httpReq)

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

func (ac *AssistantCoordinator) Health(ctx context.Context) (*model.HealthResponse, error) {
	logger := log.FromContext(ctx)

	u, err := url.Parse(ac.apiUrl)
	if err != nil {
		logger.WithError(err).WithField("apiUrl", ac.apiUrl).Error("unable to parse apiUrl")

		return nil, err
	}

	u.Path = path.Join(u.Path, "/health")
	endpoint := u.String()

	shortLived, cancel := context.WithTimeout(ctx, time.Second*time.Duration(ac.healthTimeoutSeconds))
	defer cancel()

	httpReq, err := http.NewRequestWithContext(shortLived, http.MethodGet, endpoint, nil)
	if err != nil {
		logger.WithError(err).Error("unable to make request object")

		return nil, err
	}

	ac.prepareRequestHeaders(httpReq)

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

	logger.WithField("rawHealthResponseBody", string(resBody)).Debug("health response received")

	response := &model.HealthResponse{}

	err = json.Unmarshal(resBody, response)
	if err != nil {
		logger.WithError(err).WithField("rawHealthResponseBody", string(resBody)).Error("unable to unmarhsal JSON response")
		return nil, err
	}

	return response, nil
}

func (ac *AssistantCoordinator) prepareRequestHeaders(httpReq *http.Request) {
	httpReq.Header.Add("x-api-key", ac.apiKey)
	httpReq.Header.Add("x-so-version", ac.srv.Host.Version)
}

func cleanupMessages(messages []*model.Message) []*model.Message {
	msgs := make([]*model.Message, 0, len(messages))
	for _, msg := range messages {
		m := *msg
		m.StopReason = nil
		m.StopSequence = nil
		m.Usage = nil

		// ToolUse-only messages, while given out by the AI, are not accepted by the AI
		// add text to the ToolUse body to placate the AI's validation.
		if m.Role == "assistant" && len(m.ContentBlocks) == 1 && m.ContentBlocks[0].Type == "tool_use" {
			m.ContentBlocks = append([]model.ContentBlock{
				{
					Type: "text",
					Text: "ToolUse",
				},
			}, m.ContentBlocks...)
		}

		msgs = append(msgs, &m)
	}

	return msgs
}
