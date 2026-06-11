// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	modcontext "github.com/security-onion-solutions/securityonion-soc/server/modules/context"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/google/uuid"
)

type ProtocolConstructor func(context.Context, *server.Server, map[string]any) (server.AssistantAdapter, error)

var protocols = map[string]ProtocolConstructor{}

var (
	ErrToolNotFound    = errors.New("ERROR_ASSISTANT_TOOL_NOT_FOUND")
	ErrRequestTooLarge = errors.New("ERROR_ASSISTANT_REQUEST_TOO_LARGE")
	ErrInvalidModel    = errors.New("ERROR_ASSISTANT_INVALID_MODEL")
)

const (
	DEFAULT_SYSTEM_PROMPT_ADDENDUM            = ""
	DEFAULT_SYSTEM_PROMPT_ADDENDUM_MAX_LENGTH = 50000

	// DEFAULT_MAX_SUBSESSION_TOKENS is the default per-sub-session output-token
	// budget. 0 disables the budget (sub-sessions are uncapped) unless an operator
	// configures "maxSubSessionTokens".
	DEFAULT_MAX_SUBSESSION_TOKENS = 0
)

//go:embed SOSystemPrompt.bin
var embeddedSystemPrompt []byte

type AssistantCoordinator struct {
	srv       *server.Server
	isRunning bool

	FunctionLibrary   map[string]Tool
	DelegationLibrary map[string]Tool
	toolConfig        json.RawMessage
	adapters          map[string]server.AssistantAdapter
	isAgentic         bool

	systemPrompt         string
	systemPromptAddendum string

	// maxSubSessionTokens is the per-sub-session output-token budget. 0 disables it.
	maxSubSessionTokens int

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
	ac.DelegationLibrary = map[string]Tool{}

	ac.toolConfig, err = buildToolConfig(ac.FunctionLibrary, nil, nil, nil)

	systemPromptAddendum := module.GetStringDefault(config, "systemPromptAddendum", DEFAULT_SYSTEM_PROMPT_ADDENDUM)
	ac.isAgentic = module.GetBoolDefault(config, "agentic", false)

	maxLength := module.GetIntDefault(config, "systemPromptAddendumMaxLength", DEFAULT_SYSTEM_PROMPT_ADDENDUM_MAX_LENGTH)
	if len(systemPromptAddendum) > maxLength {
		systemPromptAddendum = systemPromptAddendum[:maxLength]
	}

	ac.systemPromptAddendum = systemPromptAddendum
	ac.maxSubSessionTokens = module.GetIntDefault(config, "maxSubSessionTokens", DEFAULT_MAX_SUBSESSION_TOKENS)
	ac.adapters = map[string]server.AssistantAdapter{}

	adapterConfig, ok := config["adapters"].([]any)
	if ok && adapterConfig != nil {
		adapterArray := make([]model.AdapterParameters, 0, len(adapterConfig))
		for i, adapterInter := range adapterConfig {
			adapterEntry, ok := adapterInter.(map[string]any)
			if !ok {
				logger.Errorf("adapter entry at index %d is not a valid object, skipping", i)
				continue
			}

			name, err := module.GetString(adapterEntry, "name")
			if err != nil {
				logger.WithError(err).Errorf("adapter entry at index %d missing name field, skipping", i)
				continue
			}

			protocol, err := module.GetString(adapterEntry, "protocol")
			if err != nil {
				logger.WithError(err).WithField("adapter", name).Warn("adapter missing protocol field, skipping")
				continue
			}

			ctor, ok := protocols[protocol]
			if !ok {
				logger.WithField("protocol", protocol).Warn("unknown protocol, skipping")
				continue
			}

			adapt, err := ctor(ac.srv.Context, ac.srv, adapterEntry)
			if err != nil {
				logger.WithError(err).WithFields(log.Fields{
					"adapter":  name,
					"protocol": protocol,
				}).Error("unable to initialize adapter")

				continue
			}

			ac.adapters[name] = adapt
			logger.WithFields(log.Fields{
				"adapter":  name,
				"protocol": protocol,
			}).Info("loaded assistant adapter")

			adapterArray = append(adapterArray, model.AdapterParameters{
				Name:     name,
				Protocol: protocol,
			})
		}

		ac.srv.Config.ClientParams.AssistantParams.AvailableAdapters = adapterArray
	} else {
		logger.Warn("no adapter config, no adapters loaded")
		ac.srv.Config.ClientParams.AssistantParams.AvailableAdapters = []model.AdapterParameters{}
	}

	if ac.isAgentic {
		ac.setupAgentic()
	}

	ac.validateModelSelectors()

	if ac.isAgentic {
		ac.registerDelegateTools()
	}

	ac.getPrompt()

	return err
}

// registerDelegateTools creates a delegate tool for every enabled agentic
// model, registered in the DelegationLibrary under both its canonical selector
// and its tool name. A model whose selector or sanitized tool name is already
// claimed is skipped with an error log (first registration wins), enforcing
// the duplicate policy reported by validateModelSelectors.
func (ac *AssistantCoordinator) registerDelegateTools() {
	logger := log.FromContext(ac.srv.Context)

	for _, m := range ac.srv.Config.ClientParams.AssistantParams.AvailableModels {
		if m.Enabled && m.IsAgentic {
			selector := m.Selector()
			delegate := NewDelegateTool(selector, m.DisplayName, m.AgentDescription)
			toolName := delegate.GetName()

			if _, exists := ac.DelegationLibrary[selector]; exists {
				logger.WithFields(log.Fields{
					"agent":   selector,
					"modelId": m.ID,
					"adapter": m.Adapter,
				}).Error("duplicate agent selector; skipping delegate registration")
				continue
			}

			if _, exists := ac.DelegationLibrary[toolName]; exists {
				logger.WithFields(log.Fields{
					"agent":    selector,
					"toolName": toolName,
				}).Error("delegate tool name collides with an already-registered delegate; skipping registration")
				continue
			}

			ac.DelegationLibrary[selector] = delegate
			ac.DelegationLibrary[toolName] = delegate

			logger.WithFields(log.Fields{
				"agent":   selector,
				"modelId": m.ID,
				"adapter": m.Adapter,
			}).Info("created delegate tool for agentic model")
		}
	}
}

// buildToolConfig assembles the tool spec sent to the adapter from the function
// and delegation libraries. The filters are tri-state: a nil filter includes
// every tool in that library, while a non-nil filter (including an empty,
// non-nil slice) includes only the named tools — so an empty slice means "expose
// none". This lets a non-agentic caller pass nil for all tools while an agent
// scopes itself to an explicit (possibly empty) allow-list.
func buildToolConfig(functions map[string]Tool, delegates map[string]Tool, toolFilter []string, delegateFilter []string) (json.RawMessage, error) {
	keys := []string{}
	for key := range functions {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	toolSpecs := make([]*model.ToolSpec, 0, len(keys))

	for _, key := range keys {
		tool := functions[key]
		name := tool.GetName()

		if toolFilter == nil || slices.Contains(toolFilter, name) {
			toolSpecs = append(toolSpecs, &model.ToolSpec{
				Spec: model.ToolDefinition{
					Name:        name,
					Description: tool.GetDescription(),
					InputSchema: tool.GetSchema(),
				},
			})
		}
	}

	keys = []string{}
	for key := range delegates {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	// Each delegate is registered under multiple keys (selector and tool name),
	// so dedupe by tool name to avoid sending the same tool spec twice.
	seenDelegates := map[string]struct{}{}
	for _, key := range keys {
		if delegateFilter == nil || slices.Contains(delegateFilter, key) {
			tool := delegates[key]

			_, ok := seenDelegates[tool.GetName()]
			if ok {
				continue
			}
			seenDelegates[tool.GetName()] = struct{}{}

			toolSpecs = append(toolSpecs, &model.ToolSpec{
				Spec: model.ToolDefinition{
					Name:        tool.GetName(),
					Description: tool.GetDescription(),
					InputSchema: tool.GetSchema(),
				},
			})
		}
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

func (ac *AssistantCoordinator) getPrompt() {
	if len(embeddedSystemPrompt) > 0 {
		// Gunzip the prompt bytes
		reader, err := gzip.NewReader(bytes.NewReader(embeddedSystemPrompt))
		if err != nil {
			log.FromContext(ac.srv.Context).WithError(err).Error("unable to gunzip system prompt, no prompt loaded")
			return
		}
		defer reader.Close()

		raw, err := io.ReadAll(reader)
		if err != nil {
			log.FromContext(ac.srv.Context).WithError(err).Error("unable to read gunzipped system prompt, no prompt loaded")
			return
		}

		if !utf8.Valid(raw) {
			log.FromContext(ac.srv.Context).Error("gunzipped system prompt must be in UTF-8 encoding, no prompt loaded")
			return
		}

		ac.systemPrompt = string(raw)
		return
	}

	logger := log.FromContext(ac.srv.Context)

	path := os.Getenv("SO_AI_SYSTEM_PROMPT_PATH")
	if path == "" {
		logger.Warn("no prompt loaded")
		return
	}

	raw, err := ac.ReadFile(path)
	if err != nil {
		logger.WithError(err).WithField("path", path).Error("unable to read system prompt from file, no prompt loaded")
		return
	}

	if !utf8.Valid(raw) {
		logger.WithError(err).WithField("path", path).Error("system prompt must be in UTF-8 encoding, no prompt loaded")
		return
	}

	ac.systemPrompt = string(raw)
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

func splitModelAdapter(aiModel string) (string, string) {
	parts := strings.SplitN(aiModel, "@", 2)
	if len(parts) == 1 {
		parts = append(parts, "SOAI")
	}

	return parts[0], parts[1]
}

func estimateRequestChars(req *model.ChatRequest) int {
	total := len(req.System) + len(req.SystemAppend) + len(req.ToolConfig)
	for _, msg := range req.Messages {
		total += len(msg.ContentStr)
		for _, block := range msg.ContentBlocks {
			total += len(block.Text) + len(block.Input)
			if block.ToolResult != nil {
				for _, c := range block.ToolResult.Content {
					total += len(c.Text)
				}
			}
		}
	}
	return total
}

// validateModelSelectors logs configuration problems with model selectors at
// startup. Policy is log-and-continue, matching how bad adapter config is
// handled above: the first model to claim a selector wins (resolveModel is
// first-match) and its duplicates are skipped during delegate registration;
// nothing here prevents the module from loading.
func (ac *AssistantCoordinator) validateModelSelectors() {
	logger := log.FromContext(ac.srv.Context)
	models := ac.srv.Config.ClientParams.AssistantParams.AvailableModels

	seen := map[string]string{}
	for i := range models {
		m := &models[i]
		if !m.Enabled {
			continue
		}

		if strings.Contains(m.DisplayName, "@") {
			logger.WithField("displayName", m.DisplayName).Warn("model displayName contains '@', which is ambiguous with the legacy id@adapter selector format")
		}

		selector := m.Selector()
		if owner, dup := seen[selector]; dup {
			logger.WithFields(log.Fields{
				"selector":      selector,
				"firstModel":    owner,
				"shadowedModel": m.LegacySelector(),
			}).Error("duplicate model selector; the first configured model wins and this one is unreachable")
			continue
		}
		seen[selector] = m.LegacySelector()

		// A DisplayName matching another model's legacy id@adapter selector
		// shadows that model's stored sessions (canonical resolution wins).
		if m.DisplayName != "" {
			for j := range models {
				if i != j && models[j].Enabled && m.DisplayName == models[j].LegacySelector() {
					logger.WithFields(log.Fields{
						"displayName":   m.DisplayName,
						"shadowedModel": models[j].LegacySelector(),
					}).Warn("model displayName matches another model's legacy id@adapter selector and will shadow it")
				}
			}
		}
	}
}

// resolveModel resolves a client-supplied model selector to its configured
// parameters. The canonical selector is the model's DisplayName; the legacy
// "id@adapter" form (stored in old sessions and browser settings) is resolved
// as a fallback so existing conversations keep working. Returns nil when
// nothing matches; callers must handle the nil case (a model may have a
// registered adapter without an AvailableModels entry).
func (ac *AssistantCoordinator) resolveModel(selector string) *model.ModelParameters {
	models := ac.srv.Config.ClientParams.AssistantParams.AvailableModels

	// Pass 1: canonical selector (DisplayName, or id@adapter when DisplayName is
	// empty). Runs before any splitting so a DisplayName containing "@" resolves.
	for i := range models {
		if models[i].Selector() == selector {
			return &models[i]
		}
	}

	// Pass 2: legacy id@adapter.
	modelId, adapterName := splitModelAdapter(selector)
	for i := range models {
		if models[i].ID == modelId && models[i].Adapter == adapterName {
			return &models[i]
		}
	}

	return nil
}

// resolveAdapterName returns the adapter a selector routes to. Selectors that
// resolve to no configured model fall back to the legacy split so a registered
// adapter without an AvailableModels entry can still answer (Balance/Health).
func (ac *AssistantCoordinator) resolveAdapterName(selector string) string {
	if params := ac.resolveModel(selector); params != nil {
		return params.Adapter
	}

	_, adapterName := splitModelAdapter(selector)

	return adapterName
}

func (ac *AssistantCoordinator) checkRequestSize(req *model.ChatRequest, params *model.ModelParameters) error {
	if params == nil || params.CharsPerTokenEstimate <= 0 {
		return nil
	}

	contextLimit := params.ContextLimitLarge
	if contextLimit <= 0 {
		contextLimit = params.ContextLimitSmall
	}
	if contextLimit <= 0 {
		return nil
	}

	maxChars := float64(contextLimit) * params.CharsPerTokenEstimate * 1.1
	usedChars := float64(estimateRequestChars(req))
	if usedChars >= maxChars {
		return ErrRequestTooLarge
	}
	return nil
}

func (ac *AssistantCoordinator) Send(ctx context.Context, aiModel string, messages []*model.Message, opts ...model.ChatOpt) ([]*model.Message, error) {
	logger := log.FromContext(ctx)
	userID := ctx.Value(web.ContextKeyRequestorId).(string)
	config := model.ApplyChatOpts(opts...)

	msgs := cleanupMessages(messages)

	modelParams := ac.resolveModel(aiModel)
	if modelParams == nil {
		// The requested model is not configured; there is no sensible fallback, so
		// surface it as a client error (mapped to HTTP 400 by the handler).
		logger.WithField("model", aiModel).Error("requested model is not configured")
		return nil, ErrInvalidModel
	}

	req := &model.ChatRequest{
		Messages:  msgs,
		UserId:    userID,
		Model:     modelParams.ID,
		MaxTokens: config.MaxTokens,
	}

	if err := ac.checkRequestSize(req, modelParams); err != nil {
		logger.WithFields(log.Fields{"modelId": modelParams.ID, "adapterName": modelParams.Adapter, "estimatedChars": estimateRequestChars(req)}).Error("request exceeds estimated context limit")
		return nil, err
	}

	adapter, ok := ac.adapters[modelParams.Adapter]
	if !ok {
		logger.WithField("adapterName", modelParams.Adapter).Error("assistant adapter not found")
		return nil, fmt.Errorf("assistant adapter not found: %s", modelParams.Adapter)
	}

	if ac.isAgentic && modelParams.IsAgentic {
		err := ac.setupAgent(req, modelParams)
		if err != nil {
			return nil, err
		}
	} else {
		req.ToolConfig = ac.toolConfig
		req.System = ac.systemPrompt
		req.SystemAppend = ac.systemPromptAddendum
	}

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
					result, err := ac.ExecuteTool(ctx, content.Name, &model.ToolRequest{Params: content.Input, Model: aiModel})
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

					err = ac.srv.Assistantstore.SaveChat(ctx, toolMsg.PrepareForStorage("", []string{"tool_result"}, aiModel))
					if err != nil {
						logger.WithError(err).Error("unable to save tool result message")
						return nil, err
					}

					// append to message history and recurse to send the tool result back with context
					messages = append(messages, toolMsg)

					toolResponse, err := ac.Send(ctx, aiModel, messages, model.WithAutoExecuteTools(true))
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

func (ac *AssistantCoordinator) SendStream(ctx context.Context, aiModel string, messages []*model.Message, opts ...model.ChatOpt) (*http.Response, *model.AuxMessageData, error) {
	logger := log.FromContext(ctx)
	userID := ctx.Value(web.ContextKeyRequestorId).(string)
	config := model.ApplyChatOpts(opts...)

	// copy and modify
	msgs := cleanupMessages(messages)

	modelParams := ac.resolveModel(aiModel)
	if modelParams == nil {
		// The requested model is not configured; there is no sensible fallback, so
		// surface it as a client error (mapped to HTTP 400 by the handler).
		logger.WithField("model", aiModel).Error("requested model is not configured")
		return nil, nil, ErrInvalidModel
	}

	req := &model.ChatRequest{
		Messages:  msgs,
		Stream:    true,
		UserId:    userID,
		Model:     modelParams.ID,
		MaxTokens: config.MaxTokens,
	}

	if err := ac.checkRequestSize(req, modelParams); err != nil {
		logger.WithFields(log.Fields{"modelId": modelParams.ID, "adapterName": modelParams.Adapter, "estimatedChars": estimateRequestChars(req)}).Error("request exceeds estimated context limit")
		return nil, nil, err
	}

	adapter, ok := ac.adapters[modelParams.Adapter]
	if !ok {
		logger.WithField("adapterName", modelParams.Adapter).Error("assistant adapter not found")
		return nil, nil, fmt.Errorf("assistant adapter not found: %s", modelParams.Adapter)
	}

	if ac.isAgentic && modelParams.IsAgentic {
		err := ac.setupAgent(req, modelParams)
		if err != nil {
			return nil, nil, err
		}
	} else {
		req.ToolConfig = ac.toolConfig
		req.System = ac.systemPrompt
		req.SystemAppend = ac.systemPromptAddendum
	}

	res, aux, err := adapter.SendMessageStream(ctx, req)
	if err != nil {
		return nil, nil, err
	}

	return res, aux, nil
}

func (ac *AssistantCoordinator) ExecuteTool(ctx context.Context, toolName string, toolReq *model.ToolRequest) (*model.ToolResponse, error) {
	logger := log.FromContext(ctx).WithFields(log.Fields{
		"toolName":  toolName,
		"toolUseId": uuid.New().String(),
	})

	tool, ok := ac.FunctionLibrary[toolName]
	if !ok {
		tool, ok = ac.DelegationLibrary[toolName]
		if !ok {
			logger.Error("tool not found")
			return nil, ErrToolNotFound
		}
	}

	assistantCtx := modcontext.WriteIsAssistant(ctx, true)
	assistantCtx = log.NewContext(assistantCtx, logger)

	userID := ctx.Value(web.ContextKeyRequestorId).(string)
	logger.WithFields(log.Fields{
		"toolName": toolName,
		"userId":   userID,
	}).Info("executing tool for assistant")

	result, err := tool.Execute(assistantCtx, ac.srv, toolReq)
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
	adapterName := ac.resolveAdapterName(aiModel)

	adapter, ok := ac.adapters[adapterName]
	if !ok {
		logger := log.FromContext(ctx)
		logger.WithField("adapterName", adapterName).Error("assistant adapter not found")

		return nil, fmt.Errorf("assistant adapter not found: %s", adapterName)
	}

	response, err := adapter.GetBalance(ctx)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (ac *AssistantCoordinator) Health(ctx context.Context, aiModel string) (*model.HealthResponse, error) {
	adapterName := ac.resolveAdapterName(aiModel)

	adapter, ok := ac.adapters[adapterName]
	if !ok {
		logger := log.FromContext(ctx)
		logger.WithField("adapterName", adapterName).Error("assistant adapter not found")

		return nil, fmt.Errorf("assistant adapter not found: %s", adapterName)
	}

	response, err := adapter.GetHealth(ctx)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// ToolInSession is the non-streaming counterpart to ToolStreamInSession. It runs
// the requested tool, then drives the resulting turn — and any delegated
// sub-agent turns it triggers — synchronously to a stopping point, returning the
// assistant response messages for the handler to write back to the requester.
//
// The stopping point mirrors the streaming chaining loop (see PostTool): a turn
// that requests a tool is returned for approval (parking the session), while a
// text-only turn from a sub-agent is folded back into its parent's delegate
// tool_use and the parent is resumed, repeating until a top-level turn completes
// or a tool needs approval. Nothing is streamed; the whole chain runs in one call.
func (ac *AssistantCoordinator) ToolInSession(ctx context.Context, toolReq *model.ToolRequest, toolName string) ([]*model.Message, error) {
	logger := log.FromContext(ctx)

	result, toolErr := ac.ExecuteTool(ctx, toolName, toolReq)
	if toolErr != nil {
		logger.WithError(toolErr).Error("unable to execute tool")
	}

	if result == nil && toolErr == nil {
		// async tool with neither a result nor an error
		return nil, nil
	}

	// Build the initial turn. A delegation kickoff starts the sub-agent's session
	// and runs its first turn; any other tool result is folded into the current
	// session and the assistant's continuation is run.
	var response []*model.Message
	var sessionId string
	var err error

	if kickoff, ok := delegationKickoff(result); ok {
		response, sessionId, err = ac.startDelegationSync(ctx, toolReq, kickoff)
	} else {
		// A tool error (nil result, non-nil error) is wrapped as an error tool_result
		// so the conversation can continue.
		toolMsg := buildToolResultMessage(toolReq.ToolUseId, result, toolErr)
		// Continue on the session's own model rather than the client-supplied model.
		sessionId = toolReq.SessionId
		aiModel := ac.sessionModel(ctx, toolReq.SessionId, toolReq.Model)
		response, err = ac.continueWithToolResultSync(ctx, sessionId, aiModel, toolMsg)
	}
	if err != nil {
		return nil, err
	}

	// Chain turns while a delegated sub-agent finishes (text-only) and its result
	// folds back into the parent. Stop when a turn needs tool approval or a
	// top-level turn completes. This is the non-streaming twin of the PostTool loop.
	for {
		last := response[len(response)-1]
		if messageHasToolUse(last) {
			// A tool request hands control back to the client (approve and POST again).
			// This legitimately parks a (sub-)agent mid-task, so do not resolve here.
			return response, nil
		}

		sess := ac.loadSession(ctx, sessionId)
		if sess == nil || sess.ParentSessionId == "" {
			// Top-level conversation completed (or the session can't be loaded, in
			// which case we can't tell it's a sub-agent, so we stop chaining).
			return response, nil
		}

		// The session that just finished is a delegated sub-agent. Resolve it into its
		// parent and continue with the parent's turn.
		response, sessionId, err = ac.resolveDelegationSync(ctx, sess, messageText(last))
		if err != nil {
			return nil, err
		}
	}
}

// continueWithToolResultSync is the non-streaming twin of continueWithToolResult.
// It appends a tool_result (or delegation result) message to the given session,
// dispatches the conversation to Send, persists the tool_result, and persists and
// returns the assistant's response messages.
func (ac *AssistantCoordinator) continueWithToolResultSync(ctx context.Context, sessionId, aiModel string, toolMsg *model.Message) ([]*model.Message, error) {
	logger := log.FromContext(ctx)

	// A full delegation chains several sequential model calls in one request, so
	// run free of the per-request timeout like the streaming path does.
	noTimeOutCtx := buildNoTimeoutCtx(ctx)

	// Enforce the per-sub-session output-token budget (see continueWithToolResult).
	isSub, remaining := ac.subSessionOutputBudget(noTimeOutCtx, sessionId)
	if isSub && remaining <= 0 {
		return ac.haltSubSessionSync(noTimeOutCtx, sessionId, aiModel, toolMsg)
	}

	messages, _, err := ac.loadHistory(noTimeOutCtx, sessionId)
	if err != nil {
		return nil, err
	}
	messages = append(messages, toolMsg)

	var sendOpts []model.ChatOpt
	if isSub {
		sendOpts = append(sendOpts, model.WithMaxTokens(remaining))
	}

	response, err := ac.Send(noTimeOutCtx, aiModel, messages, sendOpts...)
	if err != nil {
		return nil, err
	}

	toolStored := toolMsg.PrepareForStorage(sessionId, []string{"tool_result"}, aiModel)
	if err := ac.srv.Assistantstore.SaveChat(noTimeOutCtx, toolStored); err != nil {
		logger.WithError(err).Error("unable to save tool result message for non-streaming chat")
		return nil, err
	}

	for _, msg := range response {
		stored := msg.PrepareForStorage(sessionId, nil, aiModel)
		if err := ac.srv.Assistantstore.SaveChat(noTimeOutCtx, stored); err != nil {
			logger.WithError(err).Error("unable to save tool result response message (non-streaming)")
			return nil, err
		}
	}

	return response, nil
}

// ToolStreamInSession is the streaming counterpart to ToolInSession. It runs the
// requested tool and returns the resulting streamed turn. When the tool is a
// delegation kickoff it instead starts the sub-agent's session and streams its
// first turn (leaving the parent's delegate tool_use parked); otherwise it folds
// the tool result into the session and streams the assistant's continuation.
func (ac *AssistantCoordinator) ToolStreamInSession(ctx context.Context, toolReq *model.ToolRequest, toolName string) (*model.StreamedTurn, error) {
	logger := log.FromContext(ctx)

	result, toolErr := ac.ExecuteTool(ctx, toolName, toolReq)
	if toolErr != nil {
		logger.WithError(toolErr).Error("unable to execute tool")
	}

	// Delegation kickoff: start the sub-agent's session instead of resolving the
	// parent's delegate tool_use. The parent stays parked until the sub-agent
	// finishes and the backend folds its result back in (see ResolveDelegationStream).
	if result != nil {
		if kickoff, ok := result.Result.(model.DelegationKickoff); ok {
			return ac.startDelegation(ctx, toolReq, kickoff)
		}
	}

	toolMsg := buildToolResultMessage(toolReq.ToolUseId, result, toolErr)

	// Resume on the session's own model (Hunter's model for a sub-agent session),
	// not the client-supplied model, so the right agent/prompt continues the turn.
	aiModel := ac.sessionModel(ctx, toolReq.SessionId, toolReq.Model)

	return ac.continueWithToolResult(ctx, toolReq.SessionId, aiModel, toolMsg)
}

// continueWithToolResult appends a tool_result (or delegation result) message to
// the given session, dispatches the conversation to SendStream, persists the
// tool_result, and returns the streamed turn with a finalize callback that
// persists the assistant's response once streaming completes.
func (ac *AssistantCoordinator) continueWithToolResult(ctx context.Context, sessionId, aiModel string, toolMsg *model.Message) (*model.StreamedTurn, error) {
	logger := log.FromContext(ctx)

	// Enforce the per-sub-session output-token budget. When a sub-agent has spent
	// its budget, halt it instead of running another model turn; otherwise cap this
	// turn's output at the remaining budget.
	isSub, remaining := ac.subSessionOutputBudget(ctx, sessionId)
	if isSub && remaining <= 0 {
		return ac.haltSubSessionStream(ctx, sessionId, aiModel, toolMsg)
	}

	messages, _, err := ac.loadHistory(ctx, sessionId)
	if err != nil {
		return nil, err
	}
	messages = append(messages, toolMsg)

	noTimeOutCtx := buildNoTimeoutCtx(ctx)

	var sendOpts []model.ChatOpt
	if isSub {
		sendOpts = append(sendOpts, model.WithMaxTokens(remaining))
	}

	response, aux, err := ac.SendStream(noTimeOutCtx, aiModel, messages, sendOpts...)
	if err != nil {
		return nil, err
	}

	toolStored := toolMsg.PrepareForStorage(sessionId, []string{"tool_result"}, aiModel)
	if err := ac.srv.Assistantstore.SaveChat(noTimeOutCtx, toolStored); err != nil {
		logger.WithError(err).Error("unable to save tool result message before streaming response")
		return nil, err
	}

	finalize := func(rawResponse []byte) error {
		msg, err := server.UnstreamResponse(noTimeOutCtx, string(rawResponse), aux)
		if err != nil {
			return err
		}
		if msg == nil {
			return nil
		}
		return ac.srv.Assistantstore.SaveChat(noTimeOutCtx, msg.PrepareForStorage(sessionId, nil, aiModel))
	}

	return &model.StreamedTurn{
		Response:  response,
		Aux:       aux,
		Finalize:  finalize,
		SessionId: sessionId,
		Model:     aiModel,
	}, nil
}

// sessionModel returns the model/adapter a session runs on, derived from the
// session record itself rather than trusting a client-supplied value. Legacy
// sessions saved before AssistantSession.Model existed (or a session that can't
// be loaded) fall back to the provided model so existing conversations keep
// working unchanged.
func (ac *AssistantCoordinator) sessionModel(ctx context.Context, sessionId, fallback string) string {
	sessions, err := ac.srv.Assistantstore.GetSessions(ctx, model.GetSessionsWithSessionId(sessionId))
	if err != nil || len(sessions) == 0 {
		return fallback
	}
	if sessions[0].Model == "" {
		return fallback
	}
	return sessions[0].Model
}

// subSessionOutputBudget reports the per-sub-session output-token budget state for
// a session: whether it is a delegated sub-agent and, if so, how many output
// tokens remain (the configured limit minus output tokens already generated in the
// sub-session). remaining can be <= 0 once the budget is spent. For top-level
// sessions, when no budget is configured, or when usage can't be determined,
// isSub is false and remaining is 0 (no cap).
func (ac *AssistantCoordinator) subSessionOutputBudget(ctx context.Context, sessionId string) (isSub bool, remaining int) {
	if ac.maxSubSessionTokens <= 0 || sessionId == "" {
		return false, 0
	}

	sessions, err := ac.srv.Assistantstore.GetSessions(ctx,
		model.GetSessionsWithSessionId(sessionId),
		model.GetSessionsWithUsage(true),
	)
	if err != nil || len(sessions) == 0 {
		// Can't determine usage; don't cap rather than risk truncating a turn.
		return false, 0
	}

	sess := sessions[0]
	if sess.ParentSessionId == "" {
		return false, 0 // top-level conversation; the budget applies only to sub-agents
	}

	used := 0
	if sess.Usage != nil {
		used = sess.Usage.TotalOutputTokens
	}

	return true, ac.maxSubSessionTokens - used
}

// subSessionStartOpts returns the chat options that cap a sub-agent's first turn
// at the full per-sub-session budget (none has been spent yet). It returns no
// options when the budget is disabled.
func (ac *AssistantCoordinator) subSessionStartOpts() []model.ChatOpt {
	if ac.maxSubSessionTokens <= 0 {
		return nil
	}
	return []model.ChatOpt{model.WithMaxTokens(ac.maxSubSessionTokens)}
}

// subSessionBudgetNotice is the text returned to the parent when a sub-agent is
// halted for exhausting its output-token budget.
func subSessionBudgetNotice(limit int) string {
	return fmt.Sprintf("This delegated sub-agent was halted because it reached its output-token budget (%d tokens) for this delegation. Returning with the work completed so far.", limit)
}

// haltSubSessionStream terminates a sub-agent that has exhausted its output-token
// budget without running another model turn. It persists the pending tool result
// for a clean history, then synthesizes a text-only streamed turn carrying the
// halt notice (reusing the SSE machinery the adapters use) so the existing chaining
// loop streams it and folds it back into the parent as the delegation's result.
func (ac *AssistantCoordinator) haltSubSessionStream(ctx context.Context, sessionId, aiModel string, toolMsg *model.Message) (*model.StreamedTurn, error) {
	logger := log.FromContext(ctx)
	noTimeOutCtx := buildNoTimeoutCtx(ctx)

	logger.WithFields(log.Fields{
		"sessionId": sessionId,
		"budget":    ac.maxSubSessionTokens,
	}).Info("sub-session output-token budget exhausted; halting")

	if toolMsg != nil {
		toolStored := toolMsg.PrepareForStorage(sessionId, []string{"tool_result"}, aiModel)
		if err := ac.srv.Assistantstore.SaveChat(noTimeOutCtx, toolStored); err != nil {
			logger.WithError(err).Error("unable to save tool result before halting sub-session")
			return nil, err
		}
	}

	notice := subSessionBudgetNotice(ac.maxSubSessionTokens)

	response, bodyWriter := fabricateResponse(http.StatusOK)
	aux := &model.AuxMessageData{ThoughtSignatures: map[string][]byte{}}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	processor := newStreamProcessor(newSSEEventWriter(logger, bodyWriter), aiModel, wg)

	go func() {
		defer bodyWriter.Close()
		processor.ensureFirstSend()
		processor.writeText(notice)
		processor.finalizeGemini("end_turn", nil)
	}()
	wg.Wait()

	finalize := func(rawResponse []byte) error {
		msg, err := server.UnstreamResponse(noTimeOutCtx, string(rawResponse), aux)
		if err != nil {
			return err
		}
		if msg == nil {
			return nil
		}
		return ac.srv.Assistantstore.SaveChat(noTimeOutCtx, msg.PrepareForStorage(sessionId, []string{"subsession_halted"}, aiModel))
	}

	return &model.StreamedTurn{
		Response:  response,
		Aux:       aux,
		Finalize:  finalize,
		SessionId: sessionId,
		Model:     aiModel,
	}, nil
}

// haltSubSessionSync is the non-streaming twin of haltSubSessionStream. It persists
// the pending tool result and a synthetic halt notice as the sub-agent's final
// turn, returning the notice so the chaining loop resolves it into the parent.
func (ac *AssistantCoordinator) haltSubSessionSync(ctx context.Context, sessionId, aiModel string, toolMsg *model.Message) ([]*model.Message, error) {
	logger := log.FromContext(ctx)
	noTimeOutCtx := buildNoTimeoutCtx(ctx)

	logger.WithFields(log.Fields{
		"sessionId": sessionId,
		"budget":    ac.maxSubSessionTokens,
	}).Info("sub-session output-token budget exhausted; halting")

	if toolMsg != nil {
		toolStored := toolMsg.PrepareForStorage(sessionId, []string{"tool_result"}, aiModel)
		if err := ac.srv.Assistantstore.SaveChat(noTimeOutCtx, toolStored); err != nil {
			logger.WithError(err).Error("unable to save tool result before halting sub-session")
			return nil, err
		}
	}

	stopReason := "end_turn"
	notice := &model.Message{
		Id:   uuid.NewString(),
		Role: "assistant",
		ContentBlocks: []model.ContentBlock{
			{Type: "text", Text: subSessionBudgetNotice(ac.maxSubSessionTokens)},
		},
		StopReason: &stopReason,
	}

	if err := ac.srv.Assistantstore.SaveChat(noTimeOutCtx, notice.PrepareForStorage(sessionId, []string{"subsession_halted"}, aiModel)); err != nil {
		logger.WithError(err).Error("unable to save halt notice for sub-session")
		return nil, err
	}

	return []*model.Message{notice}, nil
}

// startDelegation creates the linked child session for a delegation, seeds the
// objective as the child's first user message, and streams the sub-agent's first
// turn. The returned turn carries a delegation_start marker so the UI nests the
// sub-agent's output under the parent's delegate tool block. The parent's
// delegate tool_use is intentionally left unresolved here.
func (ac *AssistantCoordinator) startDelegation(ctx context.Context, toolReq *model.ToolRequest, kickoff model.DelegationKickoff) (*model.StreamedTurn, error) {
	logger := log.FromContext(ctx)
	noTimeOutCtx := buildNoTimeoutCtx(ctx)

	session := ac.newDelegationSession(noTimeOutCtx, toolReq, kickoff)
	if err := ac.srv.Assistantstore.CreateSession(noTimeOutCtx, session); err != nil {
		logger.WithError(err).Error("unable to create delegated child session")
		return nil, err
	}

	userMsg := newUserMessage(kickoff.Objective)
	if err := ac.srv.Assistantstore.SaveChat(noTimeOutCtx, userMsg.PrepareForStorage(kickoff.ChildSessionId, nil, kickoff.ChildModel)); err != nil {
		logger.WithError(err).Error("unable to save delegated objective message")
		return nil, err
	}

	// The child's first turn has spent none of its budget; cap it at the full
	// per-sub-session limit (a no-op when the budget is disabled).
	response, aux, err := ac.SendStream(noTimeOutCtx, kickoff.ChildModel, []*model.Message{userMsg}, ac.subSessionStartOpts()...)
	if err != nil {
		return nil, err
	}

	finalize := func(rawResponse []byte) error {
		msg, err := server.UnstreamResponse(noTimeOutCtx, string(rawResponse), aux)
		if err != nil {
			return err
		}
		if msg == nil {
			return nil
		}
		return ac.srv.Assistantstore.SaveChat(noTimeOutCtx, msg.PrepareForStorage(kickoff.ChildSessionId, nil, kickoff.ChildModel))
	}

	return &model.StreamedTurn{
		Response:  response,
		Aux:       aux,
		Finalize:  finalize,
		SessionId: kickoff.ChildSessionId,
		Model:     kickoff.ChildModel,
		Marker: &model.DelegationMarker{
			Type:            model.DelegationMarkerStart,
			ChildSessionId:  kickoff.ChildSessionId,
			ParentToolUseId: toolReq.ToolUseId,
			AgentName:       kickoff.AgentName,
		},
	}, nil
}

// ResolveDelegationStream is called when a delegated sub-agent has finished (its
// turn came back text-only). It folds the sub-agent's final answer into a
// tool_result for the parent's delegate tool_use, resumes the parent session, and
// returns the parent's streamed turn carrying a delegation_resolved marker so the
// UI un-nests and renders the parent's continuation.
func (ac *AssistantCoordinator) ResolveDelegationStream(ctx context.Context, childSession *model.AssistantSession, childFinalText string) (*model.StreamedTurn, error) {
	toolMsg := buildDelegationResultMessage(childSession.ParentToolUseId, childFinalText)

	// Prefer the parent session's live stored model; fall back to the snapshot
	// taken at delegation time for legacy children created before Model existed.
	parentModel := ac.sessionModel(ctx, childSession.ParentSessionId, childSession.ParentModel)

	turn, err := ac.continueWithToolResult(ctx, childSession.ParentSessionId, parentModel, toolMsg)
	if err != nil {
		return nil, err
	}

	turn.Marker = &model.DelegationMarker{
		Type:            model.DelegationMarkerResolved,
		ParentSessionId: childSession.ParentSessionId,
		ParentToolUseId: childSession.ParentToolUseId,
	}

	return turn, nil
}

// newDelegationSession builds the linked child session record for a delegation,
// shared by the streaming and non-streaming kickoff paths.
func (ac *AssistantCoordinator) newDelegationSession(ctx context.Context, toolReq *model.ToolRequest, kickoff model.DelegationKickoff) *model.AssistantSession {
	return &model.AssistantSession{
		SessionId:       kickoff.ChildSessionId,
		Title:           kickoff.Objective,
		Type:            "delegation",
		Model:           kickoff.ChildModel,
		DelegateAgent:   kickoff.AgentName,
		ParentSessionId: toolReq.SessionId,
		ParentToolUseId: toolReq.ToolUseId,
		// Snapshot the parent's own stored model (not the client-supplied model) so
		// the parent resumes on the right agent even if the user switched models
		// while the sub-agent was running.
		ParentModel: ac.sessionModel(ctx, toolReq.SessionId, toolReq.Model),
	}
}

// startDelegationSync is the non-streaming twin of startDelegation. It creates the
// linked child session, seeds the objective as the child's first user message,
// runs the sub-agent's first turn via Send, persists it, and returns the child's
// response messages together with the child session id so the caller can drive
// the delegation chain. The parent's delegate tool_use is left unresolved here.
func (ac *AssistantCoordinator) startDelegationSync(ctx context.Context, toolReq *model.ToolRequest, kickoff model.DelegationKickoff) ([]*model.Message, string, error) {
	logger := log.FromContext(ctx)
	noTimeOutCtx := buildNoTimeoutCtx(ctx)

	session := ac.newDelegationSession(noTimeOutCtx, toolReq, kickoff)
	if err := ac.srv.Assistantstore.CreateSession(noTimeOutCtx, session); err != nil {
		logger.WithError(err).Error("unable to create delegated child session")
		return nil, "", err
	}

	userMsg := newUserMessage(kickoff.Objective)
	if err := ac.srv.Assistantstore.SaveChat(noTimeOutCtx, userMsg.PrepareForStorage(kickoff.ChildSessionId, nil, kickoff.ChildModel)); err != nil {
		logger.WithError(err).Error("unable to save delegated objective message")
		return nil, "", err
	}

	// The child's first turn has spent none of its budget; cap it at the full
	// per-sub-session limit (a no-op when the budget is disabled).
	response, err := ac.Send(noTimeOutCtx, kickoff.ChildModel, []*model.Message{userMsg}, ac.subSessionStartOpts()...)
	if err != nil {
		return nil, "", err
	}

	for _, msg := range response {
		stored := msg.PrepareForStorage(kickoff.ChildSessionId, nil, kickoff.ChildModel)
		if err := ac.srv.Assistantstore.SaveChat(noTimeOutCtx, stored); err != nil {
			logger.WithError(err).Error("unable to save delegated sub-agent response (non-streaming)")
			return nil, "", err
		}
	}

	return response, kickoff.ChildSessionId, nil
}

// resolveDelegationSync is the non-streaming twin of ResolveDelegationStream. It
// folds a finished sub-agent's final answer into a tool_result for the parent's
// delegate tool_use, resumes the parent session via Send, and returns the
// parent's response messages together with the parent session id.
func (ac *AssistantCoordinator) resolveDelegationSync(ctx context.Context, childSession *model.AssistantSession, childFinalText string) ([]*model.Message, string, error) {
	toolMsg := buildDelegationResultMessage(childSession.ParentToolUseId, childFinalText)

	// Prefer the parent session's live stored model; fall back to the snapshot
	// taken at delegation time for legacy children created before Model existed.
	parentModel := ac.sessionModel(ctx, childSession.ParentSessionId, childSession.ParentModel)

	response, err := ac.continueWithToolResultSync(ctx, childSession.ParentSessionId, parentModel, toolMsg)
	if err != nil {
		return nil, "", err
	}

	return response, childSession.ParentSessionId, nil
}

// buildDelegationResultMessage wraps a sub-agent's final answer as the tool_result
// for the parent's delegate tool_use. An empty answer becomes an error result so
// the parent can react rather than continue on nothing.
func buildDelegationResultMessage(parentToolUseId, childFinalText string) *model.Message {
	if strings.TrimSpace(childFinalText) == "" {
		return buildToolResultMessage(parentToolUseId, nil, errors.New("ERROR_DELEGATION_NO_RESULT"))
	}
	resp := &model.ToolResponse{
		ToolName: "delegation",
		Result:   childFinalText,
	}
	return buildToolResultMessage(parentToolUseId, resp, nil)
}

// delegationKickoff returns the DelegationKickoff carried by a tool result, if any.
func delegationKickoff(result *model.ToolResponse) (model.DelegationKickoff, bool) {
	if result == nil {
		return model.DelegationKickoff{}, false
	}
	kickoff, ok := result.Result.(model.DelegationKickoff)
	return kickoff, ok
}

// messageHasToolUse reports whether an assistant turn requested a tool.
func messageHasToolUse(msg *model.Message) bool {
	for _, cb := range msg.ContentBlocks {
		if cb.Type == "tool_use" {
			return true
		}
	}
	return false
}

// messageText concatenates the text content of an assistant turn, used as the
// delegated sub-agent's final answer when resolving a delegation.
func messageText(msg *model.Message) string {
	var b strings.Builder
	for _, cb := range msg.ContentBlocks {
		if cb.Text != "" {
			b.WriteString(cb.Text)
		}
	}
	return b.String()
}

// loadSession returns the session with the given id, or nil if it can't be found.
func (ac *AssistantCoordinator) loadSession(ctx context.Context, sessionId string) *model.AssistantSession {
	sessions, err := ac.srv.Assistantstore.GetSessions(ctx, model.GetSessionsWithSessionId(sessionId))
	if err != nil || len(sessions) == 0 {
		return nil
	}
	return sessions[0]
}

func buildToolResultMessage(toolUseId string, result *model.ToolResponse, toolErr error) *model.Message {
	var toolResult *model.ToolResult
	if toolErr != nil {
		toolResult = &model.ToolResult{
			ToolUseId: toolUseId,
			Status:    "error",
			IsError:   true,
			Content: []model.ToolResultContent{
				{Text: toolErr.Error()},
			},
		}
	} else {
		var res any
		var name string
		if result != nil {
			res = map[string]any{
				"result": result.Result,
			}
			name = result.ToolName
		}
		toolResult = &model.ToolResult{
			Name:      name,
			ToolUseId: toolUseId,
			Content: []model.ToolResultContent{
				{Json: res},
			},
		}
	}

	return &model.Message{
		Id:   uuid.NewString(),
		Role: "user",
		ContentBlocks: []model.ContentBlock{
			{ToolResult: toolResult},
		},
	}
}

func (ac *AssistantCoordinator) setupAgent(req *model.ChatRequest, modelParams *model.ModelParameters) (err error) {
	req.System = modelParams.AgentPrompt // build system prompt for this agent
	req.SystemAppend = ""

	req.ToolConfig, err = buildToolConfig(ac.FunctionLibrary, ac.DelegationLibrary, modelParams.AllowedTools, modelParams.CanDelegateTo) // build tools for this agent
	if err != nil {
		return err
	}

	return nil
}

// HistoryToContext converts stored message history into the message list sent
// as context to the model. Messages preceding a context-compression marker are
// dropped so only the compressed summary and what follows it are kept.
func HistoryToContext(history []*model.StoredMessage) []*model.Message {
	messages := make([]*model.Message, 0, len(history))
	for _, msg := range history {
		if slices.Contains(msg.Tags, model.MessageTagContextCompression) {
			messages = messages[:0]
		}

		messages = append(messages, msg.Message)
	}

	return messages
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
