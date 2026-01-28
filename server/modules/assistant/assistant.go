// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	modcontext "github.com/security-onion-solutions/securityonion-soc/server/modules/context"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/google/uuid"
)

type AdapterConstructor func(context.Context, *server.Server, map[string]any) (server.AssistantAdapter, error)

var adapters = map[string]AdapterConstructor{}

var (
	ErrToolNotFound = errors.New("ERROR_ASSISTANT_TOOL_NOT_FOUND")
)

type AssistantCoordinator struct {
	srv       *server.Server
	isRunning bool

	FunctionLibrary map[string]Tool
	toolConfig      json.RawMessage

	adapters map[string]server.AssistantAdapter

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
	logger := log.FromContext(ac.srv.Context)

	ac.srv.AssistantManager = ac
	ac.FunctionLibrary = knownTools

	ac.toolConfig, err = buildToolConfig(ac.FunctionLibrary)

	ac.adapters = map[string]server.AssistantAdapter{}

	adapterConfig, ok := config["adapters"].(map[string]any)
	if ok && adapterConfig != nil {
		for name, ctor := range adapters {
			config, ok := adapterConfig[name].(map[string]any)
			if ok {
				adapter, err := ctor(ac.srv.Context, ac.srv, config)
				if err != nil {
					logger.WithError(err).WithFields(log.Fields{
						"adapter": name,
					}).Error("unable to initialize adapter")

					continue
				}

				ac.adapters[name] = adapter
			} else {
				logger.WithField("adapter", name).Warn("known adapter missing config, not loading adapter")
			}
		}
	} else {
		log.Log.Warn("no adapter config, no adapters loaded")
	}

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
		ToolChoice: map[string]model.JSONSchema{
			"auto": {},
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

func (ac *AssistantCoordinator) selectAdapter(aiModel string) server.AssistantAdapter {
	models := ac.srv.Config.ClientParams.AssistantParams.AvailableModels
	for _, m := range models {
		if !m.Enabled {
			continue
		}

		if strings.EqualFold(m.ID, aiModel) {
			if m.Adapter != "" {
				return ac.adapters[m.Adapter]
			} else {
				return ac.adapters["securityonion_ai_cloud"]
			}
		}
	}

	return ac.adapters["securityonion_ai_cloud"]
}

func (ac *AssistantCoordinator) Chat(ctx context.Context, aiModel string, messages []*model.Message, opts ...model.ChatOpt) ([]*model.Message, error) {
	logger := log.FromContext(ctx)
	userID := ctx.Value(web.ContextKeyRequestorId).(string)
	config := model.ApplyChatOpts(opts...)

	msgs := cleanupMessages(messages)

	req := &model.ChatRequest{
		Messages:   msgs,
		ToolConfig: ac.toolConfig,
		UserId:     userID,
		Model:      aiModel,
	}

	adapter := ac.selectAdapter(aiModel)

	response, err := adapter.SendMessage(ctx, req)
	if err != nil {
		logger.WithError(err).Error("unable to send message to assistant")
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
					result, err := ac.ExecuteTool(ctx, content.Name, string(content.Input), "")
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

					toolResponse, err := ac.Chat(ctx, aiModel, messages, model.WithAutoExecuteTools(true))
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

func (ac *AssistantCoordinator) ChatStream(ctx context.Context, aiModel string, messages []*model.Message) (*http.Response, *model.AuxMessageData, error) {
	userID := ctx.Value(web.ContextKeyRequestorId).(string)

	// copy and modify
	msgs := cleanupMessages(messages)

	req := &model.ChatRequest{
		Messages:   msgs,
		Stream:     true,
		ToolConfig: ac.toolConfig,
		UserId:     userID,
		Model:      aiModel,
	}

	adapter := ac.selectAdapter(aiModel)

	res, aux, err := adapter.SendMessageStream(ctx, req)
	if err != nil {
		return nil, nil, err
	}

	return res, aux, nil
}

func (ac *AssistantCoordinator) ExecuteTool(ctx context.Context, toolName string, params string, auxData string) (*model.ToolResponse, error) {
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

	result, err := tool.Execute(assistantCtx, ac.srv, params, auxData)
	if err != nil {
		logger.WithError(err).Error("error executing tool")
		return nil, err
	}

	logger.WithFields(log.Fields{
		"toolResult": result,
	}).Info("tool executed successfully")

	return result, nil
}

func (ac *AssistantCoordinator) Balance(ctx context.Context, aiModel string) (*model.BalanceResponse, error) {
	adapter := ac.selectAdapter(aiModel)

	response, err := adapter.GetBalance(ctx)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (ac *AssistantCoordinator) Health(ctx context.Context, aiModel string) (*model.HealthResponse, error) {
	adapter := ac.selectAdapter(aiModel)

	response, err := adapter.GetHealth(ctx)
	if err != nil {
		return nil, err
	}

	return response, nil
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
					Text: "&nbsp;",
				},
			}, m.ContentBlocks...)
		}

		msgs = append(msgs, &m)
	}

	return msgs
}
