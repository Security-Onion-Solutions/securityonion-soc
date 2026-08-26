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
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/assistant/database"
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
	ErrInvalidAgent    = errors.New("ERROR_ASSISTANT_INVALID_AGENT")
	ErrNoDatabase      = errors.New("no database configured")
)

const (
	DEFAULT_SYSTEM_PROMPT_ADDENDUM            = ""
	DEFAULT_SYSTEM_PROMPT_ADDENDUM_MAX_LENGTH = 50000

	// DEFAULT_MAX_SUBSESSION_TOKENS is the default per-sub-session output-token
	// budget. 0 disables the budget (sub-sessions are uncapped) unless an operator
	// configures "maxSubSessionTokens".
	DEFAULT_MAX_SUBSESSION_TOKENS = 0

	// DEFAULT_MAX_DELEGATION_DEPTH is the default maximum delegation nesting depth
	// for sub-sessions. 0 disables the limit (delegation depth is unbounded) unless
	// an operator configures "maxDelegationDepth".
	DEFAULT_MAX_DELEGATION_DEPTH = 0

	// DEFAULT_TOOL_USE_TURN_ATTEMPTS and DEFAULT_TOOL_USE_TURN_DELAY_MS bound
	// awaitToolUseTurn's polling for an asynchronously-persisted tool_use turn,
	// unless an operator configures "toolUseTurnAttempts" / "toolUseTurnDelayMs".
	DEFAULT_TOOL_USE_TURN_ATTEMPTS = 10
	DEFAULT_TOOL_USE_TURN_DELAY_MS = 150

	DEFAULT_USE_MEMORY_SCANNER           = false
	DEFAULT_MEMORY_SCAN_INTERVAL_SECONDS = 300

	DEFAULT_MEMORY_TO_MEMORY_PROXIMITY_THRESHOLD  = 0.8
	DEFAULT_MEMORY_TO_MESSAGE_PROXIMITY_THRESHOLD = 0.5

	DEFAULT_MAX_USER_MEMORIES_TO_INCLUDE   = 5
	DEFAULT_MAX_GLOBAL_MEMORIES_TO_INCLUDE = 5

	DEFAULT_MAX_USER_MEMORIES_TO_RECONCILE   = 20
	DEFAULT_MAX_GLOBAL_MEMORIES_TO_RECONCILE = 20
)

//go:embed SOSystemPrompt.bin
var embeddedSystemPrompt []byte

type AssistantCoordinator struct {
	srv       *server.Server
	isRunning bool

	FunctionLibrary map[string]Tool
	SkillLibrary    map[string]model.Skill
	toolConfig      json.RawMessage
	adapters        map[string]server.AssistantAdapter
	isAgentic       bool

	// agentMu guards the agentic configuration that can be hot-reloaded from a
	// config setting change: agents, agentMapping, and DelegationLibrary. Readers
	// (request handlers) take RLock; a reload rebuilds the whole set under Lock.
	agentMu           sync.RWMutex
	DelegationLibrary map[string]Tool
	agents            map[string]model.Agent
	agentMapping      map[string]string // map[agentName]modelSelector ("id@adapter" or bare id)

	// The system-provided sets, captured at setup and never mutated after. A reload
	// merges stored overrides onto these, so what an admin cannot edit survives a save.
	builtinAgents       map[string]model.Agent
	builtinAgentMapping map[string]string
	builtinSkills       map[string]model.Skill

	// Serializes the read-modify-write of the agent/skill settings so concurrent
	// saves merge instead of overwriting each other.
	configWriteMu sync.Mutex

	systemPrompt         string
	systemPromptAddendum string

	// maxSubSessionTokens is the per-sub-session output-token budget. 0 disables it.
	// Atomic so it can be hot-reloaded without racing per-request readers.
	maxSubSessionTokens atomic.Int64

	// maxDelegationDepth is the maximum delegation nesting depth. 0 disables it.
	// Atomic so it can be hot-reloaded without racing per-request readers.
	maxDelegationDepth atomic.Int64

	// toolUseTurnAttempts and toolUseTurnDelay bound awaitToolUseTurn's polling for
	// the asynchronously-persisted assistant turn that requested a tool: up to
	// toolUseTurnAttempts reloads, with toolUseTurnDelay backoff between them.
	toolUseTurnAttempts int
	toolUseTurnDelay    time.Duration

	// sessionLocks serializes a session's tool-turn continuation so that exactly one
	// request continues the LLM's turn when several parallel tool results land.
	sessionLocks sessionLocks

	store                        *database.Store
	useMemory                    bool
	useMemoryScanner             bool
	maxUserMemoriesToInclude     int
	maxGlobalMemoriesToInclude   int
	maxUserMemoriesToReconcile   int
	maxGlobalMemoriesToReconcile int
	terminateMemory              context.CancelCauseFunc
	memoryScanInterval           time.Duration
	mem2memProximityThreshold    float64
	mem2msgProximityThreshold    float64
	memoryAgents                 map[string]model.Agent // "Memory"/"Embed"/"Reconcile" prompt holders, kept out of ac.agents
	memoryMapping                map[string]string      // map[roleName]modelSelector from the memoryModel/embedModel/reconcileModel config keys

	detections.IOManager
}

// Configuration setting IDs the coordinator subscribes to for live reloads. These
// must match the setting IDs defined in the config annotations (salt).
const (
	// ConfigSettingAgents holds the full agent definition set (name, role, model,
	// skills, delegation, persona) as a structured, DB-stored config value. It also
	// drives the agent->model mapping (each agent carries its model). These IDs sit
	// under the assistant module's config namespace, alongside the other assistant
	// module settings (adapters, systemPromptAddendum, ...).
	ConfigSettingAgents = "soc.config.server.modules.assistant.agents"
	// AgenticUpdateKind is the websocket message kind carrying agentic parameter
	// changes to connected browsers.
	AgenticUpdateKind = "assistant:agentic"
	// Skill definitions, in the same structured form as the agents setting.
	ConfigSettingSkills = "soc.config.server.modules.assistant.skills"
	// ConfigSettingMaxDelegationDepth / ConfigSettingMaxSubSessionTokens are scalar
	// limits that can be hot-reloaded.
	ConfigSettingMaxDelegationDepth  = "soc.config.server.modules.assistant.maxDelegationDepth"
	ConfigSettingMaxSubSessionTokens = "soc.config.server.modules.assistant.maxSubSessionTokens"
)

// getMaxSubSessionTokens returns the current per-sub-session output-token budget.
func (ac *AssistantCoordinator) getMaxSubSessionTokens() int {
	return int(ac.maxSubSessionTokens.Load())
}

// getMaxDelegationDepth returns the current maximum delegation nesting depth.
func (ac *AssistantCoordinator) getMaxDelegationDepth() int {
	return int(ac.maxDelegationDepth.Load())
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
	ac.DelegationLibrary = map[string]Tool{}

	ac.toolConfig, err = buildToolConfig(ac.FunctionLibrary, nil, nil, nil)

	systemPromptAddendum := module.GetStringDefault(config, "systemPromptAddendum", DEFAULT_SYSTEM_PROMPT_ADDENDUM)
	ac.isAgentic = module.GetBoolDefault(config, "agentic", false)

	maxLength := module.GetIntDefault(config, "systemPromptAddendumMaxLength", DEFAULT_SYSTEM_PROMPT_ADDENDUM_MAX_LENGTH)
	if len(systemPromptAddendum) > maxLength {
		systemPromptAddendum = systemPromptAddendum[:maxLength]
	}

	ac.systemPromptAddendum = systemPromptAddendum
	ac.maxSubSessionTokens.Store(int64(module.GetIntDefault(config, "maxSubSessionTokens", DEFAULT_MAX_SUBSESSION_TOKENS)))
	ac.maxDelegationDepth.Store(int64(module.GetIntDefault(config, "maxDelegationDepth", DEFAULT_MAX_DELEGATION_DEPTH)))
	ac.toolUseTurnAttempts = max(module.GetIntDefault(config, "toolUseTurnAttempts", DEFAULT_TOOL_USE_TURN_ATTEMPTS), 1)
	ac.toolUseTurnDelay = time.Duration(module.GetIntDefault(config, "toolUseTurnDelayMs", DEFAULT_TOOL_USE_TURN_DELAY_MS)) * time.Millisecond

	ac.useMemory = module.GetBoolDefault(config, "useMemory", false)
	ac.useMemoryScanner = module.GetBoolDefault(config, "useMemoryScanner", DEFAULT_USE_MEMORY_SCANNER)
	ac.maxUserMemoriesToInclude = module.GetIntDefault(config, "maxUserMemoriesToInclude", DEFAULT_MAX_USER_MEMORIES_TO_INCLUDE)
	ac.maxGlobalMemoriesToInclude = module.GetIntDefault(config, "maxGlobalMemoriesToInclude", DEFAULT_MAX_GLOBAL_MEMORIES_TO_INCLUDE)
	ac.maxUserMemoriesToReconcile = module.GetIntDefault(config, "maxUserMemoriesToReconcile", DEFAULT_MAX_USER_MEMORIES_TO_RECONCILE)
	ac.maxGlobalMemoriesToReconcile = module.GetIntDefault(config, "maxGlobalMemoriesToReconcile", DEFAULT_MAX_GLOBAL_MEMORIES_TO_RECONCILE)
	ac.mem2memProximityThreshold = module.GetFloatDefault(config, "memoryProximityThreshold", DEFAULT_MEMORY_TO_MEMORY_PROXIMITY_THRESHOLD)
	ac.mem2msgProximityThreshold = module.GetFloatDefault(config, "messageProximityThreshold", DEFAULT_MEMORY_TO_MESSAGE_PROXIMITY_THRESHOLD)

	memScanInterval := module.GetIntDefault(config, "memoryScanIntervalSeconds", DEFAULT_MEMORY_SCAN_INTERVAL_SECONDS)
	if memScanInterval > 0 {
		ac.memoryScanInterval = time.Second * time.Duration(memScanInterval)
	} else if err == nil && ac.useMemoryScanner {
		err = fmt.Errorf("memoryScanInterval must be > 0")
	}

	ac.loadAdapters(config)

	ac.validateModelSelectors()

	ac.srv.Config.ClientParams.AssistantParams.Agentic = ac.isAgentic

	if ac.isAgentic || ac.useMemory || ac.useMemoryScanner {
		prompts := ac.unzipAndUnmarshal(allPrompts)

		if ac.isAgentic {
			ac.setupAgentic(prompts)
			ac.agentMapping = ac.loadAgentMapping(config)

			ac.builtinAgentMapping = make(map[string]string, len(ac.agentMapping))
			for name, selector := range ac.agentMapping {
				ac.builtinAgentMapping[name] = selector
			}

			ac.validateAgentMappings()
			ac.registerDelegateTools()
			ac.exposeAgents()
		}

		if ac.useMemory || ac.useMemoryScanner {
			ac.setupMemoryAgents(prompts)
			ac.memoryMapping = map[string]string{
				"Memory":    module.GetStringDefault(config, "memoryModel", ""),
				"Embed":     module.GetStringDefault(config, "embedModel", ""),
				"Reconcile": module.GetStringDefault(config, "reconcileModel", ""),
			}
			ac.validateMemoryMappings()
		}
	}

	ac.getPrompt()

	return err
}

func (ac *AssistantCoordinator) loadAdapters(config module.ModuleConfig) {
	ac.adapters = map[string]server.AssistantAdapter{}
	logger := log.FromContext(ac.srv.Context)

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
}

// registerDelegateTools creates a delegate tool for every validated agent,
// registered in the DelegationLibrary under both the agent name and its
// sanitized tool name. An agent whose name or tool name is already claimed is
// skipped with an error log (first registration wins). Runs after
// validateAgentMappings, so ac.agents holds only agents with a valid model.
func (ac *AssistantCoordinator) registerDelegateTools() {
	logger := log.FromContext(ac.srv.Context)

	// Stable iteration order so first-wins on any collision is deterministic.
	names := make([]string, 0, len(ac.agents))
	for name := range ac.agents {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		agent := ac.agents[name]

		// Not a delegation target, so no other agent can hand work to it.
		if !agent.Enabled {
			continue
		}

		delegate := NewDelegateTool(name, name, agent.Description)
		toolName := delegate.GetName()

		if _, exists := ac.DelegationLibrary[name]; exists {
			logger.WithField("agent", name).Error("duplicate agent name; skipping delegate registration")
			continue
		}

		if _, exists := ac.DelegationLibrary[toolName]; exists {
			logger.WithFields(log.Fields{
				"agent":    name,
				"toolName": toolName,
			}).Error("delegate tool name collides with an already-registered delegate; skipping registration")
			continue
		}

		ac.DelegationLibrary[name] = delegate
		ac.DelegationLibrary[toolName] = delegate

		logger.WithField("agent", name).Info("created delegate tool for agent")
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

	if len(toolSpecs) == 0 {
		return nil, nil
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

func (ac *AssistantCoordinator) decompressPrompt(compressed []byte) string {
	logger := log.FromContext(ac.srv.Context)

	if len(compressed) > 0 {
		// Gunzip the prompt bytes
		reader, err := gzip.NewReader(bytes.NewReader(compressed))
		if err != nil {
			logger.WithError(err).Error("unable to gunzip prompt, no prompt loaded")
			return ""
		}
		defer reader.Close()

		raw, err := io.ReadAll(reader)
		if err != nil {
			logger.WithError(err).Error("unable to read gunzipped prompt, no prompt loaded")
			return ""
		}

		if !utf8.Valid(raw) {
			logger.Error("gunzipped prompt must be in UTF-8 encoding, no prompt loaded")
			return ""
		}

		return string(raw)
	}

	return ""
}

func (ac *AssistantCoordinator) getPrompt() {
	systemPrompt := ac.decompressPrompt(embeddedSystemPrompt)
	if systemPrompt != "" {
		ac.systemPrompt = systemPrompt
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

	if ac.srv != nil && ac.srv.DB != nil {
		store, err := database.New(context.Background(), ac.srv.DB)
		if err != nil {
			log.WithError(err).Error("assistant: database init failed")
			return err
		}
		ac.store = store
	}

	// Agent definitions and limits can be managed as config settings (some
	// DB-stored, e.g. "assistant.agents") that do not arrive through the module's
	// Init config. Start runs after every module's Init, so the Configstore is
	// available now. Subscribe to the relevant settings and pull their current
	// values on top of the Init defaults.
	if ac.isAgentic {
		ac.registerConfigCallbacks()
		ac.reloadAgentConfiguration(ac.srv.Context)
	}

	if ac.useMemoryScanner {
		var memCtx context.Context
		memCtx, ac.terminateMemory = context.WithCancelCause(ac.srv.Context)

		go ac.memoryWorker(memCtx)
	}

	return nil
}

// registerConfigCallbacks subscribes the coordinator to changes of the config
// settings that drive agentic behavior. It is a no-op when the configured
// Configstore does not support callbacks (e.g. in-memory store used by tests).
func (ac *AssistantCoordinator) registerConfigCallbacks() {
	registrar, ok := ac.srv.Configstore.(server.ConfigSettingCallbackRegistrar)
	if !ok {
		log.FromContext(ac.srv.Context).Debug("configstore does not support setting callbacks; agent config will not hot-reload")
		return
	}

	for _, id := range []string{
		ConfigSettingAgents,
		ConfigSettingSkills,
		ConfigSettingMaxDelegationDepth,
		ConfigSettingMaxSubSessionTokens,
	} {
		registrar.RegisterConfigSettingCallback(id, ac)
	}
}

// OnConfigSettingUpdated implements server.ConfigSettingCallbackHandler. When one
// of the subscribed settings changes, the coordinator re-reads the full agentic
// configuration so its in-memory state and the client-facing parameters stay
// consistent.
func (ac *AssistantCoordinator) OnConfigSettingUpdated(ctx context.Context, setting *model.Setting, removed bool) {
	if !ac.isAgentic || setting == nil {
		return
	}

	switch setting.Id {
	case ConfigSettingAgents, ConfigSettingSkills, ConfigSettingMaxDelegationDepth, ConfigSettingMaxSubSessionTokens:
		log.FromContext(ctx).WithField("setting", setting.Id).Info("reloading agentic configuration after config change")
		ac.reloadAgentConfiguration(ctx)
	}
}

func (ac *AssistantCoordinator) Stop() error {
	ac.isRunning = false

	if ac.terminateMemory != nil {
		ac.terminateMemory(nil)
	}

	return nil
}

func (ac *AssistantCoordinator) IsRunning() bool {
	return ac.isRunning
}

// splitModelAdapter splits an "id@adapter" selector; hasAdapter reports
// whether an explicit "@adapter" was present.
func splitModelAdapter(aiModel string) (id string, adapter string, hasAdapter bool) {
	id, adapter, hasAdapter = strings.Cut(aiModel, "@")
	return id, adapter, hasAdapter
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

// validateModelSelectors logs configuration problems with model selectors
// ("id@adapter") at startup. Policy is log-and-continue, matching how bad
// adapter config is handled above: the first model to claim a selector wins
// (resolveModel is first-match); nothing here prevents the module from loading.
func (ac *AssistantCoordinator) validateModelSelectors() {
	logger := log.FromContext(ac.srv.Context)
	models := ac.srv.Config.ClientParams.AssistantParams.AvailableModels

	seen := map[string]struct{}{}
	seenID := map[string]string{}
	for i := range models {
		m := &models[i]
		if !m.Enabled {
			continue
		}

		// Two enabled models with the same id@adapter pair are indistinguishable;
		// checked before the bare-id warning so an exact duplicate logs only this.
		selector := m.Selector()
		if _, dup := seen[selector]; dup {
			logger.WithField("selector", selector).Error("duplicate model selector; the first configured model will be used")
			continue
		}
		seen[selector] = struct{}{}

		// Two enabled models sharing an id make bare-id resolution ambiguous.
		if owner, dup := seenID[m.ID]; dup {
			logger.WithFields(log.Fields{
				"modelId":    m.ID,
				"firstModel": owner,
				"alsoModel":  selector,
			}).Warn("multiple enabled models share an id; bare-id selectors (e.g. agent mappings) resolve to the first configured one")
		} else {
			seenID[m.ID] = selector
		}
	}
}

// resolveModel resolves a client-supplied model selector to its configured
// parameters. The canonical selector is "id@adapter" (matches both fields); a
// bare id matches on ID alone and uses that model's own adapter. Prefers an
// enabled model; a not-enabled match is returned only when no enabled model
// matches, so stored sessions on a since-disabled model still resolve. Returns
// nil when nothing matches.
func (ac *AssistantCoordinator) resolveModel(selector string) *model.ModelParameters {
	models := ac.srv.Config.ClientParams.AssistantParams.AvailableModels

	modelId, adapterName, hasAdapter := splitModelAdapter(selector)
	var fallback *model.ModelParameters
	for i := range models {
		if models[i].ID != modelId {
			continue
		}
		if hasAdapter && models[i].Adapter != adapterName {
			continue
		}
		if models[i].Enabled {
			return &models[i]
		}
		if fallback == nil {
			fallback = &models[i]
		}
	}

	return fallback
}

// resolveAgent resolves an agent name to its definition and the model that
// executes it. The model is found by mapping the agent name through
// ac.agentMapping to a model selector ("id@adapter" or bare id) and then
// resolveModel. Returns ErrInvalidAgent when the agent is unknown, disabled, or
// its mapped model is missing; callers surface this as a client error. Only
// meaningful in agentic mode.
func (ac *AssistantCoordinator) resolveAgent(name string) (*model.Agent, *model.ModelParameters, error) {
	ac.agentMu.RLock()
	agent, ok := ac.agents[name]
	modelSelector, mapped := ac.agentMapping[name]
	ac.agentMu.RUnlock()

	// A disabled agent is published but must not execute, even for a stored session.
	if !ok || !mapped || !agent.Enabled {
		return nil, nil, ErrInvalidAgent
	}

	modelParams := ac.resolveModel(modelSelector)
	if modelParams == nil {
		return nil, nil, ErrInvalidAgent
	}

	return &agent, modelParams, nil
}

// resolveMemoryAgent resolves an internal memory role (Memory, Embed,
// Reconcile) to its prompt-holding definition and the model that executes it,
// configured via the memoryModel/embedModel/reconcileModel module config keys.
func (ac *AssistantCoordinator) resolveMemoryAgent(name string) (*model.Agent, *model.ModelParameters, error) {
	agent, ok := ac.memoryAgents[name]
	if !ok {
		return nil, nil, ErrInvalidAgent
	}

	modelParams := ac.resolveModel(ac.memoryMapping[name])
	if modelParams == nil {
		return nil, nil, ErrInvalidAgent
	}

	return &agent, modelParams, nil
}

// resolveSelector resolves a client-supplied selector string. In agentic mode
// the string is first tried as an agent name; a string that is not an agent
// (or any string in non-agentic mode) is tried as a model selector
// ("id@adapter" or bare id). agentParams is non-nil only when an agent
// matched; modelParams is nil when nothing matched.
func (ac *AssistantCoordinator) resolveSelector(selector string) (*model.Agent, *model.ModelParameters) {
	if ac.isAgentic {
		if agentParams, modelParams, err := ac.resolveAgent(selector); err == nil {
			return agentParams, modelParams
		}
	}

	return nil, ac.resolveModel(selector)
}

// resolveAdapterName returns the adapter a selector routes to.
func (ac *AssistantCoordinator) resolveAdapterName(selector string) string {
	if _, params := ac.resolveSelector(selector); params != nil {
		return params.Adapter
	}

	// No model matched: honor an explicit "@adapter" (a registered adapter with
	// no AvailableModels entry); otherwise return the selector verbatim so the
	// caller reports it rather than falling back to a phantom default adapter.
	if _, adapterName, hasAdapter := splitModelAdapter(selector); hasAdapter {
		return adapterName
	}

	return selector
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

// prepareChatRequest performs the request setup shared by Send and SendStream:
// requestor lookup, message cleanup, model resolution, request construction and
// size validation, adapter lookup, and agentic (or default) prompt/tool setup.
func (ac *AssistantCoordinator) prepareChatRequest(ctx context.Context, aiModel string, messages []*model.Message, stream bool, config *model.ChatConfig) (*model.ChatRequest, server.AssistantAdapter, error) {
	logger := log.FromContext(ctx)

	userID, ok := ctx.Value(web.ContextKeyRequestorId).(string)
	if !ok {
		// Every HTTP caller is authenticated before reaching here; a missing
		// requestor means a programming error on a new call path. Fail rather
		// than panic.
		logger.Error("missing requestor id in context")
		return nil, nil, errors.New("missing requestor id in context")
	}

	// The selector is an agent name (agentic mode only, checked first) or a
	// model selector ("id@adapter" or bare id). agentParams is non-nil only
	// when an agent matched.
	agentParams, modelParams := ac.resolveSelector(aiModel)
	if modelParams == nil {
		// The requested selector matches no configured agent or model; there is
		// no sensible fallback, so surface it as a client error (mapped to HTTP
		// 400 by the handler).
		logger.WithField("model", aiModel).Error("requested selector matches no configured agent or model")
		return nil, nil, ErrInvalidModel
	}

	clean := cleanupMessages(messages)

	req := &model.ChatRequest{
		Messages:  clean,
		Stream:    stream,
		UserId:    userID,
		Model:     modelParams.ID,
		MaxTokens: config.MaxTokens,
	}

	adapter, ok := ac.adapters[modelParams.Adapter]
	if !ok {
		logger.WithField("adapterName", modelParams.Adapter).Error("assistant adapter not found")
		return nil, nil, fmt.Errorf("assistant adapter not found: %s", modelParams.Adapter)
	}

	if agentParams != nil {
		if err := ac.setupAgent(ctx, req, agentParams); err != nil {
			logger.WithFields(log.Fields{
				"agentName": agentParams.Name,
			}).WithError(err).Error("unable to setup agent")

			return nil, nil, err
		}
	} else {
		req.ToolConfig = ac.toolConfig
		req.System = ac.systemPrompt
		req.SystemAppend = ac.systemPromptAddendum
	}

	if ac.useMemory && config.IncludeMemories && len(clean) != 0 {
		latest := clean[len(clean)-1]
		if strings.EqualFold(latest.Role, "user") {
			content := messageText(latest)
			if content != "" {
				ac.addMemoriesToPrompt(ctx, req, content, config.MemorySessionId)
			}
		}
	}

	if err := ac.checkRequestSize(req, modelParams); err != nil {
		logger.WithFields(log.Fields{"modelId": modelParams.ID, "adapterName": modelParams.Adapter, "estimatedChars": estimateRequestChars(req)}).Error("request exceeds estimated context limit")
		return nil, nil, err
	}

	return req, adapter, nil
}

func (ac *AssistantCoordinator) addMemoriesToPrompt(ctx context.Context, req *model.ChatRequest, content string, sourceSessionId string) {
	logger := log.FromContext(ctx)

	user, global, err := ac.fetchMemoriesForPrompt(ctx, content, sourceSessionId)
	if err != nil {
		// log error but send request without memories
		logger.WithError(err).Warnf("failed to fetch memories for prompt, sending without memories")
		return
	}

	memPrompt := strings.Builder{}
	ids := make([]string, 0, len(user)+len(global))

	if len(user) > 0 {
		memPrompt.WriteString("\n\nMemories specific to this user:")
		for _, m := range user {
			memPrompt.WriteString(fmt.Sprintf("\n * %s", m.Memory.MemoryText))
			ids = append(ids, m.Memory.Id)
		}
	}

	if len(global) > 0 {
		memPrompt.WriteString("\n\nMemories specific to this SOC installation:")
		for _, m := range global {
			memPrompt.WriteString(fmt.Sprintf("\n * %s", m.Memory.MemoryText))
			ids = append(ids, m.Memory.Id)
		}
	}

	go func() {
		noCancelCtx := context.WithoutCancel(ctx)
		noCancelCtx, cancel := context.WithTimeout(noCancelCtx, time.Second*10)
		defer cancel()

		err := ac.store.CountMemoryUsage(noCancelCtx, ids)
		if err != nil {
			logger.WithError(err).WithField("memoryIds", ids).Error("unable to update usage count for memories")
		}
	}()

	logger.WithFields(log.Fields{
		"userMemoriesAdded":   len(user),
		"globalMemoriesAdded": len(global),
	}).Info("adding memories to message")

	req.SystemAppend += memPrompt.String()
}

func (ac *AssistantCoordinator) Send(ctx context.Context, aiModel string, messages []*model.Message, opts ...model.ChatOpt) ([]*model.Message, error) {
	logger := log.FromContext(ctx)
	config := model.ApplyChatOpts(opts...)

	req, adapter, err := ac.prepareChatRequest(ctx, aiModel, messages, false, config)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"model": aiModel,
		}).Error("problem while preparing chat request")

		return nil, err
	}

	response, err := adapter.SendMessage(ctx, req)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"model":           aiModel,
			"adapterProtocol": adapter.Protocol(),
			"streaming":       false,
		}).Error("unable to send message to assistant")
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
	config := model.ApplyChatOpts(opts...)

	req, adapter, err := ac.prepareChatRequest(ctx, aiModel, messages, true, config)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"model": aiModel,
		}).Error("problem while preparing chat request")

		return nil, nil, err
	}

	res, aux, err := adapter.SendMessageStream(ctx, req)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"model":           aiModel,
			"adapterProtocol": adapter.Protocol(),
			"streaming":       true,
		}).Error("unable to send message to assistant")

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
		ac.agentMu.RLock()
		tool, ok = ac.DelegationLibrary[toolName]
		ac.agentMu.RUnlock()
		if !ok {
			logger.Error("tool not found")
			return nil, ErrToolNotFound
		}
	}

	assistantCtx := modcontext.WriteIsAssistant(ctx, true)
	assistantCtx = log.NewContext(assistantCtx, logger)

	userID := ctx.Value(web.ContextKeyRequestorId).(string)
	logger.WithFields(log.Fields{
		"userId": userID,
	}).Info("executing tool for assistant")

	result, err := tool.Execute(assistantCtx, ac.srv, toolReq)
	if err != nil {
		logger.WithError(err).Error("error executing tool")
		return nil, err
	}

	logger.Info("tool executed successfully")

	return result, nil
}

func (ac *AssistantCoordinator) Balance(ctx context.Context, aiModel string) (*model.BalanceResponse, error) {
	logger := log.FromContext(ctx)
	adapterName := ac.resolveAdapterName(aiModel)

	adapter, ok := ac.adapters[adapterName]
	if !ok {
		logger.WithField("adapterName", adapterName).Error("assistant adapter not found")
		return nil, fmt.Errorf("assistant adapter not found: %s", adapterName)
	}

	response, err := adapter.GetBalance(ctx)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"model":           aiModel,
			"adapterName":     adapterName,
			"adapterProtocol": adapter.Protocol(),
		})

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

// Embed resolves the given model selector to its adapter and generates a vector
// embedding for each input. It mirrors the model->adapter resolution used by
// Balance/Health but also needs the model id to pass to the provider.
func (ac *AssistantCoordinator) Embed(ctx context.Context, aiModel string, input []string) (*model.EmbeddingResponse, error) {
	logger := log.FromContext(ctx)

	modelParams := ac.resolveModel(aiModel)
	if modelParams == nil {
		logger.WithField("model", aiModel).Error("requested embedding model is not configured")
		return nil, ErrInvalidModel
	}

	adapter, ok := ac.adapters[modelParams.Adapter]
	if !ok {
		logger.WithField("adapterName", modelParams.Adapter).Error("assistant adapter not found")
		return nil, fmt.Errorf("assistant adapter not found: %s", modelParams.Adapter)
	}

	return adapter.Embed(ctx, &model.EmbeddingRequest{
		Model: modelParams.ID,
		Input: input,
	})
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

	// Detach for the whole turn
	ctx = buildNoTimeoutCtx(ctx)

	// Gate the turn behind the session lock and validate the request under it (see
	// beginClientToolTurn). The lock is held across execution and the direct
	// continuation, then released before the delegation-resolution loop below (which
	// re-acquires this or an ancestor session's lock via resolveDelegationSync's
	// waitForLock continuation).
	sess, history, releaseLock, err := ac.beginClientToolTurn(ctx, toolReq, toolName)
	if err != nil {
		return nil, err
	}
	defer releaseLock()

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
	// session and the assistant's continuation is run. Each helper returns the
	// session record its turn ran on so the chain below never re-fetches it.
	var response []*model.Message

	if kickoff, ok := delegationKickoff(result); ok {
		// Refuse the delegation if it would exceed the depth limit: resolve the
		// delegating session's delegate tool_use with a notice and resume it
		// instead of nesting another sub-agent (under the lock we already hold).
		if refusal := ac.delegationDepthRefusal(ctx, toolReq); refusal != nil {
			response, err = ac.continueWithToolResultSync(ctx, sess, toolReq.SessionId, modelForSession(sess, toolReq.Model), refusal, history, lockHeld)
		} else {
			// Release before startDelegationSync: the chaining loop below folds the
			// child's result back into this session via a waitForLock continuation,
			// which would deadlock on a lock we still held.
			releaseLock()
			response, sess, err = ac.startDelegationSync(ctx, toolReq, kickoff)
		}
	} else {
		// A tool error (nil result, non-nil error) is wrapped as an error tool_result
		// so the conversation can continue.
		toolMsg := buildToolResultMessage(toolReq.ToolUseId, result, toolErr)
		// Continue on the session's own model rather than the client-supplied model.
		aiModel := modelForSession(sess, toolReq.Model)
		response, err = ac.continueWithToolResultSync(ctx, sess, toolReq.SessionId, aiModel, toolMsg, history, lockHeld)
	}
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"sessionId": toolReq.SessionId,
			"toolUseId": toolReq.ToolUseId,
		}).Error("unable to continue with tool result")

		return nil, err
	}

	// The direct continuation is done; release before the resolution loop re-acquires
	// this session's lock (a no-op if already released on the delegation path above).
	releaseLock()

	// Chain turns while a delegated sub-agent finishes (text-only) and its result
	// folds back into the parent. Stop when a turn needs tool approval or a
	// top-level turn completes. This is the non-streaming twin of the PostTool loop.
	for {
		// A coalesced/persist-only continuation returns no messages (a sibling
		// tool_use is still unresolved, or a retry arrived after the turn already
		// continued). There is nothing to chain, so return rather than index an
		// empty slice.
		if len(response) == 0 {
			return response, nil
		}
		last := response[len(response)-1]
		if messageHasToolUse(last) {
			// A tool request hands control back to the client (approve and POST again).
			// This legitimately parks a (sub-)agent mid-task, so do not resolve here.
			return response, nil
		}

		if sess == nil || sess.ParentSessionId == "" {
			// Top-level conversation completed (or the session couldn't be loaded, in
			// which case we can't tell it's a sub-agent, so we stop chaining).
			return response, nil
		}

		// The session that just finished is a delegated sub-agent. Resolve it into its
		// parent and continue with the parent's turn.
		response, sess, err = ac.resolveDelegationSync(ctx, sess, messageText(last))
		if err != nil {
			logger.WithError(err).WithFields(log.Fields{
				"sessionId": toolReq.SessionId,
				"toolUseId": toolReq.ToolUseId,
			}).Error("unable to resolve delegation")
			return nil, err
		}
	}
}

// allToolUsesResolved reports whether every tool_use in the conversation has a
// matching tool_result. Used to coalesce parallel tool calls: a turn must not be
// continued until all of its tool_use blocks are answered (the model API rejects a
// turn carrying an unanswered tool_use). A parked delegate tool_use counts as
// unresolved, so the parent correctly waits for the sub-agent to resolve.
func allToolUsesResolved(messages []*model.Message) bool {
	resolved := make(map[string]struct{})
	for _, m := range messages {
		if m == nil {
			continue
		}
		for _, cb := range m.ContentBlocks {
			if cb.ToolResult != nil && cb.ToolResult.ToolUseId != "" {
				resolved[cb.ToolResult.ToolUseId] = struct{}{}
			}
		}
	}
	for _, m := range messages {
		if m == nil || m.Role != "assistant" {
			continue
		}
		for _, cb := range m.ContentBlocks {
			if cb.Type == "tool_use" {
				if _, ok := resolved[cb.Id]; !ok {
					return false
				}
			}
		}
	}
	return true
}

// firstToolResult returns the ToolResult of a tool_result message, or nil.
func firstToolResult(toolMsg *model.Message) *model.ToolResult {
	if toolMsg == nil || len(toolMsg.ContentBlocks) == 0 {
		return nil
	}
	return toolMsg.ContentBlocks[0].ToolResult
}

// toolResultInHistory reports whether a tool_result for toolUseId is already
// present in the conversation. Used to keep a retried tool request (the UI resends
// a POST whose long-running tool timed out) from persisting a duplicate
// tool_result document
func toolResultInHistory(messages []*model.Message, toolUseId string) bool {
	if toolUseId == "" {
		return false
	}
	for _, m := range messages {
		if m == nil {
			continue
		}
		for _, cb := range m.ContentBlocks {
			if cb.ToolResult != nil && cb.ToolResult.ToolUseId == toolUseId {
				return true
			}
		}
	}
	return false
}

// turnAlreadyContinued reports whether the model has already responded to the
// most recent batch of tool_results -- i.e. the conversation ends with an
// assistant turn rather than a trailing tool_result. Combined with
// allToolUsesResolved (all results in) this is the durable guard that a
// retry arriving AFTER a continuation has been persisted does not dispatch a
// second model turn.
func turnAlreadyContinued(messages []*model.Message) bool {
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i] == nil {
			continue
		}
		return messages[i].Role == "assistant"
	}
	return false
}

// toolUseInHistory reports whether any assistant turn in the history carries a
// tool_use with the given id -- i.e. the turn that requested this tool has been
// persisted.
func toolUseInHistory(messages []*model.Message, toolUseId string) bool {
	return findToolUse(messages, toolUseId) != nil
}

// findToolUse returns the tool_use content block with the given id from the
// history's assistant turns, or nil when no assistant turn requested it.
func findToolUse(messages []*model.Message, toolUseId string) *model.ContentBlock {
	if toolUseId == "" {
		return nil
	}
	for _, m := range messages {
		if m == nil || m.Role != "assistant" {
			continue
		}
		for i, cb := range m.ContentBlocks {
			if cb.Type == "tool_use" && cb.Id == toolUseId {
				return &m.ContentBlocks[i]
			}
		}
	}
	return nil
}

// jsonEqual reports whether two raw JSON documents are semantically equal.
func jsonEqual(a, b json.RawMessage) bool {
	av, aok := normalizeJSON(a)
	bv, bok := normalizeJSON(b)
	if !aok || !bok {
		return false
	}

	return reflect.DeepEqual(av, bv)
}

// normalizeJSON decodes a raw document for semantic comparison, mapping the empty
// spellings (nil, whitespace, "null", "{}") to nil. ok is false when the document
// is present but not valid JSON.
func normalizeJSON(raw json.RawMessage) (v any, ok bool) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, true
	}

	err := json.Unmarshal(raw, &v)
	if err != nil {
		return nil, false
	}

	m, isMap := v.(map[string]any)
	if isMap && len(m) == 0 {
		return nil, true
	}

	return v, true
}

// validateToolRequest ensures a client tool request (approval or rejection) targets
// a real, still-unresolved tool_use before anything executes: the session must
// exist, an assistant turn in it must carry a tool_use with the request's id, that
// tool_use must not already have a tool_result, and the request must describe
// exactly the tool the assistant asked to run (same name, same params). The caller
// holds the session turn lock, so the decision can't race a concurrent resolution.
// On success it returns the validated history -- which contains the request's
// tool_use -- so the turn's continuation doesn't have to load it again.
func (ac *AssistantCoordinator) validateToolRequest(ctx context.Context, sess *model.AssistantSession, toolReq *model.ToolRequest, toolName string) ([]*model.Message, error) {
	if sess == nil {
		return nil, server.ErrToolUseNotFound
	}

	messages, err := ac.loadSessionHistory(ctx, sess)
	if err != nil {
		return nil, err
	}

	// The assistant turn carrying the tool_use is persisted asynchronously after it
	// streams, so a fast approval (routine for sub-agent tools) can arrive before it
	// lands. Poll with the same bounded backoff the continuation path uses before
	// concluding the tool_use doesn't exist.
	messages, found := ac.awaitToolUseTurn(ctx, sess, toolReq.ToolUseId, messages)
	if !found {
		return nil, server.ErrToolUseNotFound
	}

	// Already-resolved is checked before name/params so a genuine retry of a
	// completed request (identical payload) gets the more accurate error.
	if toolResultInHistory(messages, toolReq.ToolUseId) {
		return nil, server.ErrToolAlreadyResolved
	}

	toolUse := findToolUse(messages, toolReq.ToolUseId)
	if toolUse.Name != toolName || !jsonEqual(toolReq.Params, toolUse.Input) {
		return nil, server.ErrToolRequestMismatch
	}

	return messages, nil
}

// beginClientToolTurn is the shared prologue for a fresh client tool request
// (ToolInSession and ToolStreamInSession): it gates the turn behind the session's
// turn lock -- a session already running a tool turn is turned away with
// ErrToolTurnBusy (409) BEFORE the tool runs, so a retry of a busy request never
// re-executes a (possibly non-idempotent) tool -- then loads the session record
// and validates the request under the held lock. On success the caller owns the
// idempotent release func and receives the session together with the validated
// history. On error the lock has already been released.
func (ac *AssistantCoordinator) beginClientToolTurn(ctx context.Context, toolReq *model.ToolRequest, toolName string) (*model.AssistantSession, []*model.Message, func(), error) {
	if !ac.sessionLocks.tryLock(toolReq.SessionId) {
		return nil, nil, nil, server.ErrToolTurnBusy
	}

	released := false
	release := func() {
		if !released {
			ac.sessionLocks.unlock(toolReq.SessionId)
			released = true
		}
	}

	sess := ac.loadTurnSession(ctx, toolReq.SessionId)
	messages, err := ac.validateToolRequest(ctx, sess, toolReq, toolName)
	if err != nil {
		release()
		return nil, nil, nil, err
	}

	return sess, messages, release, nil
}

// awaitToolUseTurn ensures the assistant turn that requested toolUseId is present
// in the loaded history before a tool_result continuation acts on it. The turn that
// emits a tool_use is persisted asynchronously -- the stream's finalize runs in a
// goroutine after the turn streams to the client, while the client (which sees the
// tool_use mid-stream) fires the tool execution immediately. A delegation widens
// this window: the sub-agent's tool_use turn is saved only when its delegate stream
// breaks, so a sub-agent tool's continuation routinely arrives first. Without its
// own tool_use in history, allToolUsesResolved would vacuously pass and we would
// SendStream an orphaned tool_result that the model API rejects. Reload with a short
// bounded backoff until the turn lands; return the freshest history and whether the
// tool_use was found. A nil session yields the input unchanged.
func (ac *AssistantCoordinator) awaitToolUseTurn(ctx context.Context, sess *model.AssistantSession, toolUseId string, messages []*model.Message) ([]*model.Message, bool) {
	if toolUseInHistory(messages, toolUseId) {
		return messages, true
	}
	if sess == nil {
		return messages, false
	}
	for attempt := 0; attempt < ac.toolUseTurnAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return messages, toolUseInHistory(messages, toolUseId)
		case <-time.After(ac.toolUseTurnDelay):
		}
		reloaded, err := ac.loadSessionHistory(ctx, sess)
		if err != nil {
			continue
		}
		messages = reloaded
		if toolUseInHistory(messages, toolUseId) {
			return messages, true
		}
	}
	return messages, false
}

// continueWithToolResultSync is the non-streaming twin of continueWithToolResult.
// It appends a tool_result (or delegation result) message to the given session,
// dispatches the conversation to Send, persists the tool_result, and persists and
// returns the assistant's response messages. sess is the session record loaded
// once at the start of the turn (nil when it couldn't be loaded; sessionId still
// identifies the session for persistence).
//
// Like continueWithToolResult, it holds the per-session lock so exactly one request
// dispatches the continuation when parallel tool results land; preloaded and mode
// have the same meaning (validated history to reuse or nil to load fresh; fail fast
// for a client request, wait for an internal continuation, or run under a lock the
// caller already holds).
func (ac *AssistantCoordinator) continueWithToolResultSync(ctx context.Context, sess *model.AssistantSession, sessionId, aiModel string, toolMsg *model.Message, preloaded []*model.Message, mode lockMode) ([]*model.Message, error) {
	logger := log.FromContext(ctx)

	// The synchronous Send runs entirely under the held lock, so the whole
	// check-dispatch-persist decision is atomic; release on return.
	release, err := ac.acquireTurnLock(sessionId, mode)
	if err != nil {
		logger.WithError(err).WithField("sessionId", sessionId).Error("unable to acquire lock")
		return nil, err
	}
	defer release()

	// A full delegation chains several sequential model calls in one request, so
	// run free of the per-request timeout like the streaming path does.
	noTimeOutCtx := buildNoTimeoutCtx(ctx)

	// Enforce the per-sub-session output-token budget (see continueWithToolResult).
	isSub, remaining := ac.subSessionOutputBudget(sess)
	if isSub && remaining <= 0 {
		return ac.haltSubSessionSync(noTimeOutCtx, sessionId, aiModel, toolMsg)
	}

	messages := preloaded
	if messages == nil {
		messages, err = ac.loadSessionHistory(noTimeOutCtx, sess)
		if err != nil {
			logger.WithError(err).WithField("sessionId", sess.Id).Error("unable to load history")
			return nil, err
		}
	}

	// Wait for this result's own tool_use turn to be persisted (see
	// continueWithToolResult) before deciding, so we never send an orphaned result.
	turnPresent := true
	if tr := firstToolResult(toolMsg); tr != nil {
		messages, turnPresent = ac.awaitToolUseTurn(noTimeOutCtx, sess, tr.ToolUseId, messages)
	}

	messages, saveResult := ac.prepareToolResultPersist(noTimeOutCtx, messages, toolMsg, sessionId, aiModel)

	// If this isn't the last necessary ToolResult, only save the ToolResult and
	// don't attempt to get a turn out of the LLM
	if shouldPersistOnly(turnPresent, messages) {
		if err := saveResult(); err != nil {
			return nil, err
		}
		return []*model.Message{}, nil
	}

	var sendOpts []model.ChatOpt
	if isSub {
		sendOpts = append(sendOpts, model.WithMaxTokens(remaining))
	}

	response, err := ac.Send(noTimeOutCtx, aiModel, messages, sendOpts...)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"model":     aiModel,
			"sessionId": sess.Id,
		}).Error("unable to send message")

		return nil, err
	}

	if err := saveResult(); err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"model":     aiModel,
			"sessionId": sess.Id,
		})

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

	// Detach for the whole turn
	ctx = buildNoTimeoutCtx(ctx)

	// Gate the whole tool turn (approval or rejection) behind the session lock and
	// validate the request under it (see beginClientToolTurn). The lock is held
	// across execution and the continuation; on a dispatched turn it is handed to
	// the turn's finalize so it stays held until the handler persists the assistant
	// turn, then released.
	sess, history, releaseLock, err := ac.beginClientToolTurn(ctx, toolReq, toolName)
	if err != nil {
		return nil, err
	}

	lockTransferred := false
	defer func() {
		if !lockTransferred {
			releaseLock()
		}
	}()

	// handOff wires the session lock's release into a dispatched turn's finalize so it
	// is held until the assistant turn is persisted, closing the retry-during-stream
	// double-dispatch window. A non-dispatched turn (persist-only or error) leaves
	// the deferred release to free the lock on return.
	handOff := func(turn *model.StreamedTurn, err error) (*model.StreamedTurn, error) {
		if err == nil && turn != nil && turn.Response != nil {
			turn.Finalize = withLockRelease(turn.Finalize, releaseLock)
			lockTransferred = true
		}

		return turn, err
	}

	// A rejected tool is not executed: fold an error tool_result in so the turn
	// resolves (letting a parallel turn's other tools continue) with this tool
	// declined, then resume the assistant exactly as a normal tool result would.
	if toolReq.Rejected {
		toolMsg := buildRejectionResultMessage(toolReq.ToolUseId)
		aiModel := modelForSession(sess, toolReq.Model)

		turn, err := ac.continueWithToolResult(ctx, sess, toolReq.SessionId, aiModel, toolMsg, history, lockHeld)
		if err == nil && turn != nil && len(toolMsg.ContentBlocks) > 0 {
			turn.ToolResult = toolMsg.ContentBlocks[0].ToolResult
		}

		return handOff(turn, err)
	}

	result, toolErr := ac.ExecuteTool(ctx, toolName, toolReq)
	if toolErr != nil {
		logger.WithError(toolErr).Error("unable to execute tool")
	}

	// Delegation kickoff: start the sub-agent's session instead of resolving the
	// parent's delegate tool_use. The parent stays parked until the sub-agent
	// finishes and the backend folds its result back in (see ResolveDelegationStream).
	if result != nil {
		if kickoff, ok := result.Result.(model.DelegationKickoff); ok {
			// Refuse the delegation if it would exceed the depth limit: resolve the
			// delegating session's delegate tool_use with a notice and resume it
			// instead of nesting another sub-agent (under the lock we already hold).
			if refusal := ac.delegationDepthRefusal(ctx, toolReq); refusal != nil {
				return handOff(ac.continueWithToolResult(ctx, sess, toolReq.SessionId, modelForSession(sess, toolReq.Model), refusal, history, lockHeld))
			}
			// Release before startDelegation: it operates on the child session and its
			// failure path folds an error back into THIS session via a waitForLock
			// continuation (resolveFailedDelegation), which would deadlock on a lock we
			// still held.
			releaseLock()
			return ac.startDelegation(ctx, toolReq, kickoff)
		}
	}

	toolMsg := buildToolResultMessage(toolReq.ToolUseId, result, toolErr)

	// Resume on the session's own model, not the client-supplied model, so the
	// right agent/prompt continues the turn.
	aiModel := modelForSession(sess, toolReq.Model)

	turn, err := ac.continueWithToolResult(ctx, sess, toolReq.SessionId, aiModel, toolMsg, history, lockHeld)
	if err == nil && turn != nil && len(toolMsg.ContentBlocks) > 0 {
		// Surface the tool result so the handler can stream it to the UI inline,
		// sparing the client a session re-fetch to recover the result. Only the
		// direct-execution path reaches here; the delegation-kickoff branch above
		// returned early, so a delegate tool_use carries no result event.
		turn.ToolResult = toolMsg.ContentBlocks[0].ToolResult
	}
	return handOff(turn, err)
}

// lockMode controls how continueWithToolResult / continueWithToolResultSync acquire
// the per-session turn lock, named for readability at the call site.
type lockMode int

const (
	// failFast: a fresh client tool request. Acquire via tryLock and return
	// server.ErrToolTurnBusy (mapped to 409) rather than block when the session is busy.
	failFast lockMode = iota
	// waitForLock: an internal continuation (delegation resolution). Block until the
	// lock is free; never drop the result it must fold in.
	waitForLock
	// lockHeld: the caller already holds the session lock -- it gated tool execution
	// behind it (see ToolInSession / ToolStreamInSession) and will release it. This
	// call acquires nothing and releases nothing.
	lockHeld
)

// acquireTurnLock acquires the per-session turn lock per mode and returns an
// idempotent release function to pair with the acquisition.
func (ac *AssistantCoordinator) acquireTurnLock(sessionId string, mode lockMode) (release func(), err error) {
	switch mode {
	case failFast:
		if !ac.sessionLocks.tryLock(sessionId) {
			return func() {}, server.ErrToolTurnBusy
		}
	case waitForLock:
		ac.sessionLocks.lock(sessionId)
	case lockHeld:
		return func() {}, nil
	}

	var once sync.Once
	return func() { once.Do(func() { ac.sessionLocks.unlock(sessionId) }) }, nil
}

// withLockRelease wraps a turn's finalize callback so the session lock is released
// once the assistant turn has been persisted. The handler runs finalize after
// streaming completes, so deferring release to it keeps the lock held across the
// whole check-dispatch-persist window -- closing the retry-during-stream
// double-dispatch race. A nil finalize is tolerated.
func withLockRelease(finalize func(rawResponse []byte) error, release func()) func(rawResponse []byte) error {
	return func(rawResponse []byte) error {
		defer release()
		if finalize != nil {
			return finalize(rawResponse)
		}
		return nil
	}
}

// shouldPersistOnly reports whether this request must persist its tool_result and
// wait rather than dispatch the model continuation. True when: this result's tool_use
// turn has not yet been persisted; a sibling tool_use from the same model turn is
// still unresolved (parallel tool calls -- the API rejects a turn with an unanswered
// tool_use); or the model has already responded to this batch of results (a retry
// arriving after the continuation was persisted, which must not dispatch a second time).
func shouldPersistOnly(turnPresent bool, messages []*model.Message) bool {
	return !turnPresent || !allToolUsesResolved(messages) || turnAlreadyContinued(messages)
}

// prepareToolResultPersist appends toolMsg to messages when its result isn't already
// in history, and returns the possibly-extended messages together with a saveResult
// closure that persists the result exactly once (a no-op when it's a duplicate).
// Shared by both sync and non-sync paths; call it after awaitToolUseTurn so history
// reflects this result's tool_use turn.
func (ac *AssistantCoordinator) prepareToolResultPersist(ctx context.Context, messages []*model.Message, toolMsg *model.Message, sessionId, aiModel string) ([]*model.Message, func() error) {
	logger := log.FromContext(ctx)

	tuid := ""
	if tr := firstToolResult(toolMsg); tr != nil {
		tuid = tr.ToolUseId
	}

	needSave := tuid == "" || !toolResultInHistory(messages, tuid)
	if needSave {
		messages = append(messages, toolMsg)
	}

	save := func() error {
		if !needSave {
			return nil
		}
		toolStored := toolMsg.PrepareForStorage(sessionId, []string{"tool_result"}, aiModel)
		if err := ac.srv.Assistantstore.SaveChat(ctx, toolStored); err != nil {
			logger.WithError(err).Error("unable to save tool result")
			return err
		}
		return nil
	}

	return messages, save
}

// continueWithToolResult appends a tool_result (or delegation result) message to
// the given session, dispatches the conversation to SendStream, persists the
// tool_result, and returns the streamed turn with a finalize callback that
// persists the assistant's response once streaming completes. sess is the session
// record loaded once at the start of the turn (nil when it couldn't be loaded;
// sessionId still identifies the session for persistence).
//
// The per-session lock makes the load-check-save-dispatch decision atomic, so when
// several parallel tool results land for one model turn exactly one request
// dispatches the continuation (the rest persist and wait for the last sibling).
//
// preloaded is the session history a validated client tool turn already loaded
// under the held lock (see beginClientToolTurn); passing it spares a second load.
// Internal continuations (delegation resolution) pass nil to load fresh history.
// Reuse is safe because the held session lock excludes every writer that affects
// the continuation decision (sibling tool results are turned away with 409 and
// delegation resolution blocks on the lock).
//
// mode controls lock acquisition: a fresh client tool request passes failFast so a
// session already running a tool turn returns server.ErrToolTurnBusy (409) instead of
// waiting; an internal continuation (delegation resolution) passes waitForLock and
// waits, so it never drops the result it must fold in; a caller that already holds the
// lock (having gated tool execution behind it) passes lockHeld.
func (ac *AssistantCoordinator) continueWithToolResult(ctx context.Context, sess *model.AssistantSession, sessionId, aiModel string, toolMsg *model.Message, preloaded []*model.Message, mode lockMode) (turn *model.StreamedTurn, err error) {
	logger := log.FromContext(ctx)

	release, err := ac.acquireTurnLock(sessionId, mode)
	if err != nil {
		logger.WithError(err).WithField("sessionId", sessionId).Error("unable to acquire lock")
		return nil, err
	}
	// Hold the lock across the whole check-dispatch-persist window. On a dispatched
	// turn (Response != nil) hand release to its finalize so the lock stays held until
	// the assistant turn is persisted
	defer func() {
		if err == nil && turn != nil && turn.Response != nil {
			turn.Finalize = withLockRelease(turn.Finalize, release)
		} else {
			release()
		}
	}()

	// Detach up front
	noTimeOutCtx := buildNoTimeoutCtx(ctx)

	// Enforce the per-sub-session output-token budget. When a sub-agent has spent
	// its budget, halt it instead of running another model turn; otherwise cap this
	// turn's output at the remaining budget.
	isSub, remaining := ac.subSessionOutputBudget(sess)
	if isSub && remaining <= 0 {
		return ac.haltSubSessionStream(noTimeOutCtx, sess, aiModel, toolMsg)
	}

	messages := preloaded
	if messages == nil {
		messages, err = ac.loadSessionHistory(noTimeOutCtx, sess)
		if err != nil {
			logger.WithError(err).WithField("sessionId", sess.Id).Error("unable to load history")
			return nil, err
		}
	}

	// Wait for this result's own tool_use turn to be persisted before deciding. The
	// turn is saved asynchronously after it streams, so a fast continuation can load
	// history that lacks its tool_use; sending then would orphan the result. (A
	// preloaded history already contains the tool_use, so this is a no-op check.)
	turnPresent := true
	if tr := firstToolResult(toolMsg); tr != nil {
		messages, turnPresent = ac.awaitToolUseTurn(noTimeOutCtx, sess, tr.ToolUseId, messages)
	}

	messages, saveResult := ac.prepareToolResultPersist(noTimeOutCtx, messages, toolMsg, sessionId, aiModel)
	persistOnly := func() (*model.StreamedTurn, error) {
		if err := saveResult(); err != nil {
			logger.WithError(err).WithFields(log.Fields{
				"model":     aiModel,
				"sessionId": sess.Id,
			})

			return nil, err
		}
		// A nil Response signals a persist-only turn: the handler emits the result so
		// the UI marks this tool done, then closes without continuing the model turn.
		return &model.StreamedTurn{
			SessionId:  sessionId,
			Model:      aiModel,
			Session:    sess,
			ToolResult: firstToolResult(toolMsg),
		}, nil
	}

	// Coalesce parallel tool calls and reject a post-continuation retry:
	// persist this result and wait rather than dispatch. Sending a
	// turn with an unanswered sibling tool_use would orphan a tool_result (gateway
	// error: "Expected toolResult blocks ..." / "exceeds the number of toolUse blocks");
	// dispatching a second time on a retry would double the model turn.
	if shouldPersistOnly(turnPresent, messages) {
		return persistOnly()
	}

	var sendOpts []model.ChatOpt
	if isSub {
		sendOpts = append(sendOpts, model.WithMaxTokens(remaining))
	}

	response, aux, err := ac.SendStream(noTimeOutCtx, aiModel, messages, sendOpts...)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"model":     aiModel,
			"streaming": true,
		}).Error("unable to send message to assistant")

		return nil, err
	}

	if err := saveResult(); err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"model":     aiModel,
			"sessionId": sess.Id,
		})

		return nil, err
	}

	finalize := func(rawResponse []byte) error {
		msg, err := server.UnstreamResponse(noTimeOutCtx, string(rawResponse), aux)
		if err != nil {
			logger.WithError(err).Error("error while piecing stream together")
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
		Session:   sess,
	}, nil
}

// loadTurnSession loads the session record once at the start of a tool turn.
// Every per-turn consumer (model resolution, sub-session budget, history, the
// handler's chaining decision) reads from this single record instead of issuing
// its own lookup. Usage aggregation is requested only when the sub-session
// budget is enabled, and message-derived metadata is skipped — the turn path
// never reads it. Returns nil when the session can't be loaded; callers fall
// back exactly as they did when their individual lookups missed.
func (ac *AssistantCoordinator) loadTurnSession(ctx context.Context, sessionId string) *model.AssistantSession {
	if sessionId == "" {
		return nil
	}

	opts := []model.GetSessionsOpt{
		model.GetSessionsWithSessionId(sessionId),
		model.GetSessionsWithIncludeDeleted(true),
		model.GetSessionsWithMessageMeta(false),
	}
	if ac.getMaxSubSessionTokens() > 0 {
		opts = append(opts, model.GetSessionsWithUsage(true))
	}

	sessions, err := ac.srv.Assistantstore.GetSessions(ctx, opts...)
	if err != nil || len(sessions) == 0 {
		return nil
	}
	return sessions[0]
}

// modelForSession returns the model/adapter a session runs on, derived from the
// session record itself rather than trusting a client-supplied value. Legacy
// sessions saved before AssistantSession.Model existed (or a session that can't
// be loaded) fall back to the provided model so existing conversations keep
// working unchanged.
func modelForSession(sess *model.AssistantSession, fallback string) string {
	if sess == nil || sess.Model == "" {
		return fallback
	}
	return sess.Model
}

// loadSessionHistory returns the conversation context for an already-loaded
// session. A nil session yields empty history, matching loadHistory's tolerance
// of brand-new sessions.
func (ac *AssistantCoordinator) loadSessionHistory(ctx context.Context, sess *model.AssistantSession) ([]*model.Message, error) {
	if sess == nil {
		return nil, nil
	}

	history, err := ac.srv.Assistantstore.GetChatMessages(ctx, sess)
	if err != nil {
		log.FromContext(ctx).WithError(err).Error("unable to get chat history")
		return nil, err
	}

	return HistoryToContext(history), nil
}

// subSessionOutputBudget reports the per-sub-session output-token budget state for
// a session: whether it is a delegated sub-agent and, if so, how many output
// tokens remain (the configured limit minus output tokens already generated in the
// sub-session). remaining can be <= 0 once the budget is spent. For top-level
// sessions, when no budget is configured, or when the session (and therefore its
// usage) couldn't be loaded, isSub is false and remaining is 0 (no cap).
func (ac *AssistantCoordinator) subSessionOutputBudget(sess *model.AssistantSession) (isSub bool, remaining int) {
	if ac.getMaxSubSessionTokens() <= 0 || sess == nil {
		return false, 0
	}

	if sess.ParentSessionId == "" {
		return false, 0 // top-level conversation; the budget applies only to sub-agents
	}

	used := 0
	if sess.Usage != nil {
		used = sess.Usage.TotalOutputTokens
	}

	return true, ac.getMaxSubSessionTokens() - used
}

// subSessionStartOpts returns the chat options that cap a sub-agent's first turn
// at the full per-sub-session budget (none has been spent yet). It returns no
// options when the budget is disabled.
func (ac *AssistantCoordinator) subSessionStartOpts() []model.ChatOpt {
	if ac.getMaxSubSessionTokens() <= 0 {
		return nil
	}
	return []model.ChatOpt{model.WithMaxTokens(ac.getMaxSubSessionTokens())}
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
// sess is never nil: callers gate on subSessionOutputBudget's isSub, which is
// false for a session that couldn't be loaded.
func (ac *AssistantCoordinator) haltSubSessionStream(ctx context.Context, sess *model.AssistantSession, aiModel string, toolMsg *model.Message) (*model.StreamedTurn, error) {
	logger := log.FromContext(ctx)
	noTimeOutCtx := buildNoTimeoutCtx(ctx)
	sessionId := sess.SessionId

	logger.WithFields(log.Fields{
		"sessionId": sessionId,
		"budget":    ac.getMaxSubSessionTokens(),
	}).Info("sub-session output-token budget exhausted; halting")

	if toolMsg != nil {
		toolStored := toolMsg.PrepareForStorage(sessionId, []string{"tool_result"}, aiModel)
		if err := ac.srv.Assistantstore.SaveChat(noTimeOutCtx, toolStored); err != nil {
			logger.WithError(err).Error("unable to save tool result before halting sub-session")
			return nil, err
		}
	}

	notice := subSessionBudgetNotice(ac.getMaxSubSessionTokens())

	response, bodyWriter := fabricateResponse(http.StatusOK)
	aux := &model.AuxMessageData{ThoughtSignatures: map[string][]byte{}}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	processor := newStreamProcessor(newSSEEventWriter(logger, bodyWriter), aiModel, wg)

	go func() {
		defer bodyWriter.Close()
		processor.ensureFirstSend()
		processor.writeText(notice)
		processor.finalize("end_turn")
	}()
	wg.Wait()

	finalize := func(rawResponse []byte) error {
		msg, err := server.UnstreamResponse(noTimeOutCtx, string(rawResponse), aux)
		if err != nil {
			logger.WithError(err).Error("error while piecing stream together")
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
		Session:   sess,
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
		"budget":    ac.getMaxSubSessionTokens(),
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
			{Type: "text", Text: subSessionBudgetNotice(ac.getMaxSubSessionTokens())},
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
		// The sub-agent's first turn failed to start (e.g. its mapped model is
		// unavailable). The child session already exists but will never produce a
		// result, so resolve the parent's delegate tool_use with an error rather than
		// leaving it parked on a sub-agent that can't run -- otherwise the delegate
		// card spins "executing" forever after a reload.
		logger.WithError(err).Error("delegated sub-agent failed to start; resolving parent delegate with error")
		return ac.resolveFailedDelegation(noTimeOutCtx, toolReq, err)
	}

	finalize := func(rawResponse []byte) error {
		msg, err := server.UnstreamResponse(noTimeOutCtx, string(rawResponse), aux)
		if err != nil {
			logger.WithError(err).Error("error while piecing stream together")
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
		Session:   session,
		Marker: &model.DelegationMarker{
			Type:            model.DelegationMarkerStart,
			ChildSessionId:  kickoff.ChildSessionId,
			ParentToolUseId: toolReq.ToolUseId,
			AgentName:       kickoff.AgentName,
		},
	}, nil
}

// resolveFailedDelegation folds an error tool_result onto the parent's delegate
// tool_use and resumes the parent session, used when a sub-agent can't run (its
// first turn failed to start). This guarantees the delegation resolves rather than
// leaving the parent parked on a sub-agent that will never produce a result. The
// error result is also surfaced on the turn so the handler streams it inline (Part
// of the tool_result SSE event), updating the delegate card to "error" live as well
// as in storage. No delegation_start was emitted, so no resolved marker is needed.
func (ac *AssistantCoordinator) resolveFailedDelegation(ctx context.Context, toolReq *model.ToolRequest, cause error) (*model.StreamedTurn, error) {
	toolMsg := buildToolResultMessage(toolReq.ToolUseId, nil, fmt.Errorf("the delegated sub-agent could not be started: %w", cause))

	parentSess := ac.loadTurnSession(ctx, toolReq.SessionId)
	parentModel := modelForSession(parentSess, toolReq.Model)

	// Wait for the lock: this must fold the failure result in so the parent isn't left
	// parked on a sub-agent that will never produce a result.
	turn, err := ac.continueWithToolResult(ctx, parentSess, toolReq.SessionId, parentModel, toolMsg, nil, waitForLock)
	if err == nil && turn != nil && len(toolMsg.ContentBlocks) > 0 {
		turn.ToolResult = toolMsg.ContentBlocks[0].ToolResult
	}
	return turn, err
}

// ResolveDelegationStream is called when a delegated sub-agent has finished (its
// turn came back text-only). It folds the sub-agent's final answer into a
// tool_result for the parent's delegate tool_use, resumes the parent session, and
// returns the parent's streamed turn carrying a delegation_resolved marker so the
// UI un-nests and renders the parent's continuation.
func (ac *AssistantCoordinator) ResolveDelegationStream(ctx context.Context, childSession *model.AssistantSession, childFinalText string) (*model.StreamedTurn, error) {
	// Detach before loading the parent
	ctx = buildNoTimeoutCtx(ctx)
	logger := log.FromContext(ctx)

	toolMsg := buildDelegationResultMessage(childSession.ParentToolUseId, childFinalText)

	// Load the parent session once for the whole turn. Prefer its live stored
	// model; fall back to the snapshot taken at delegation time for legacy
	// children created before Model existed.
	parentSess := ac.loadTurnSession(ctx, childSession.ParentSessionId)
	parentModel := modelForSession(parentSess, childSession.ParentModel)

	// Wait for the lock: an internal resolution must fold the child's result in.
	turn, err := ac.continueWithToolResult(ctx, parentSess, childSession.ParentSessionId, parentModel, toolMsg, nil, waitForLock)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"childSessionId":  childSession.Id,
			"parentSessionId": childSession.ParentSessionId,
		}).Error("unable to continue with tool result")

		return nil, err
	}

	turn.Marker = &model.DelegationMarker{
		Type:            model.DelegationMarkerResolved,
		ParentSessionId: childSession.ParentSessionId,
		ParentToolUseId: childSession.ParentToolUseId,
	}

	return turn, nil
}

// delegationDepthNotice is the tool_result text returned to a delegating session
// when a delegation is refused for exceeding maxDelegationDepth.
func delegationDepthNotice(limit int) string {
	return fmt.Sprintf("Delegation was refused because it would exceed the maximum delegation depth (%d) for this conversation. Continue and complete the work without delegating.", limit)
}

// delegationDepthRefusal returns a tool_result refusing a delegation when the new
// sub-agent would exceed maxDelegationDepth, or nil to allow it. The refusal
// resolves the delegating session's delegate tool_use so it resumes instead of
// nesting another sub-agent. A limit of 0 disables the check.
func (ac *AssistantCoordinator) delegationDepthRefusal(ctx context.Context, toolReq *model.ToolRequest) *model.Message {
	if ac.getMaxDelegationDepth() <= 0 {
		return nil
	}

	parentDepth := 0
	if parent := ac.loadSession(ctx, toolReq.SessionId); parent != nil {
		parentDepth = parent.Depth
	}

	// The child would be one level deeper than the delegating session.
	if parentDepth+1 <= ac.getMaxDelegationDepth() {
		return nil
	}

	log.FromContext(ctx).WithFields(log.Fields{
		"sessionId":          toolReq.SessionId,
		"delegatingDepth":    parentDepth,
		"maxDelegationDepth": ac.getMaxDelegationDepth(),
	}).Info("delegation refused; would exceed maximum delegation depth")

	return buildToolResultMessage(toolReq.ToolUseId, &model.ToolResponse{
		ToolName: "delegation",
		Result:   delegationDepthNotice(ac.getMaxDelegationDepth()),
	}, nil)
}

// newDelegationSession builds the linked child session record for a delegation,
// shared by the streaming and non-streaming kickoff paths.
func (ac *AssistantCoordinator) newDelegationSession(ctx context.Context, toolReq *model.ToolRequest, kickoff model.DelegationKickoff) *model.AssistantSession {
	parent := ac.loadSession(ctx, toolReq.SessionId)

	parentDepth := 0
	if parent != nil {
		parentDepth = parent.Depth
	}

	return &model.AssistantSession{
		SessionId:       kickoff.ChildSessionId,
		Title:           kickoff.Objective,
		Type:            "delegation",
		Model:           kickoff.ChildModel,
		DelegateAgent:   kickoff.AgentName,
		ParentSessionId: toolReq.SessionId,
		ParentToolUseId: toolReq.ToolUseId,
		// One level deeper than the delegating session (top-level = 0); drives the
		// delegation depth limit.
		Depth: parentDepth + 1,
		// Snapshot the parent's own stored model (not the client-supplied model) so
		// the parent resumes on the right agent even if the user switched models
		// while the sub-agent was running.
		ParentModel: modelForSession(parent, toolReq.Model),
	}
}

// startDelegationSync is the non-streaming twin of startDelegation. It creates the
// linked child session, seeds the objective as the child's first user message,
// runs the sub-agent's first turn via Send, persists it, and returns the child's
// response messages together with the created child session record so the caller
// can drive the delegation chain without re-fetching it. The parent's delegate
// tool_use is left unresolved here.
func (ac *AssistantCoordinator) startDelegationSync(ctx context.Context, toolReq *model.ToolRequest, kickoff model.DelegationKickoff) ([]*model.Message, *model.AssistantSession, error) {
	logger := log.FromContext(ctx)
	noTimeOutCtx := buildNoTimeoutCtx(ctx)

	session := ac.newDelegationSession(noTimeOutCtx, toolReq, kickoff)
	if err := ac.srv.Assistantstore.CreateSession(noTimeOutCtx, session); err != nil {
		logger.WithError(err).Error("unable to create delegated child session")
		return nil, nil, err
	}

	userMsg := newUserMessage(kickoff.Objective)
	if err := ac.srv.Assistantstore.SaveChat(noTimeOutCtx, userMsg.PrepareForStorage(kickoff.ChildSessionId, nil, kickoff.ChildModel)); err != nil {
		logger.WithError(err).Error("unable to save delegated objective message")
		return nil, nil, err
	}

	// The child's first turn has spent none of its budget; cap it at the full
	// per-sub-session limit (a no-op when the budget is disabled).
	response, err := ac.Send(noTimeOutCtx, kickoff.ChildModel, []*model.Message{userMsg}, ac.subSessionStartOpts()...)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"sessionId": toolReq.SessionId,
			"toolUseId": toolReq.ToolUseId,
		}).Error("unable to send message to assistant")

		return nil, nil, err
	}

	for _, msg := range response {
		stored := msg.PrepareForStorage(kickoff.ChildSessionId, nil, kickoff.ChildModel)
		if err := ac.srv.Assistantstore.SaveChat(noTimeOutCtx, stored); err != nil {
			logger.WithError(err).Error("unable to save delegated sub-agent response (non-streaming)")
			return nil, nil, err
		}
	}

	return response, session, nil
}

// resolveDelegationSync is the non-streaming twin of ResolveDelegationStream. It
// folds a finished sub-agent's final answer into a tool_result for the parent's
// delegate tool_use, resumes the parent session via Send, and returns the
// parent's response messages together with the parent session record so the
// caller can keep chaining without re-fetching it.
func (ac *AssistantCoordinator) resolveDelegationSync(ctx context.Context, childSession *model.AssistantSession, childFinalText string) ([]*model.Message, *model.AssistantSession, error) {
	// Detach before loading the parent
	ctx = buildNoTimeoutCtx(ctx)

	toolMsg := buildDelegationResultMessage(childSession.ParentToolUseId, childFinalText)

	// Load the parent session once for the whole turn. Prefer its live stored
	// model; fall back to the snapshot taken at delegation time for legacy
	// children created before Model existed.
	parentSess := ac.loadTurnSession(ctx, childSession.ParentSessionId)
	parentModel := modelForSession(parentSess, childSession.ParentModel)

	// Wait for the lock: an internal resolution must fold the child's result in.
	response, err := ac.continueWithToolResultSync(ctx, parentSess, childSession.ParentSessionId, parentModel, toolMsg, nil, waitForLock)
	if err != nil {
		return nil, nil, err
	}

	return response, parentSess, nil
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
// Message-derived metadata is skipped; callers only read the record's own fields.
func (ac *AssistantCoordinator) loadSession(ctx context.Context, sessionId string) *model.AssistantSession {
	sessions, err := ac.srv.Assistantstore.GetSessions(ctx,
		model.GetSessionsWithSessionId(sessionId),
		model.GetSessionsWithMessageMeta(false),
	)
	if err != nil || len(sessions) == 0 {
		return nil
	}
	return sessions[0]
}

// rejectionNotice is recorded as a rejected tool's result. It reads as the tool's
// outcome so the model continues without it instead of retrying.
const rejectionNotice = "Tool execution was rejected by the user."

// buildRejectionResultMessage builds the tool_result for a tool the user declined.
// It resolves the tool_use -- so a parallel turn's coalescing can complete -- and is
// flagged "rejected" for the UI while carrying is_error so the model treats the tool
// as not run.
func buildRejectionResultMessage(toolUseId string) *model.Message {
	return &model.Message{
		Id:   uuid.NewString(),
		Role: "user",
		ContentBlocks: []model.ContentBlock{
			{ToolResult: &model.ToolResult{
				ToolUseId: toolUseId,
				Status:    "rejected",
				IsError:   true,
				Content:   []model.ToolResultContent{{Text: rejectionNotice}},
			}},
		},
	}
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

func (ac *AssistantCoordinator) setupAgent(ctx context.Context, req *model.ChatRequest, agent *model.Agent) (err error) {
	logger := log.FromContext(ctx)

	req.System = agent.EffectivePrompt()

	allowedTools := map[string]struct{}{}
	seenSkills := map[string]struct{}{}
	prompts := make([]string, 0, len(agent.AllowedSkills)+1)

	for _, skillName := range agent.AllowedSkills {
		skill, ok := ac.SkillLibrary[skillName]
		if !ok {
			logger.WithFields(log.Fields{
				"skillName": skillName,
				"agentName": agent.Name,
			}).Warn("agent has been assigned an unknown skill, dropping it")

			continue
		}

		_, seen := seenSkills[skillName]
		if seen {
			logger.WithFields(log.Fields{
				"skillName": skillName,
				"agentName": agent.Name,
			}).Warn("agent has been assigned a duplicate skill, dropping it")

			continue
		}

		seenSkills[skillName] = struct{}{}

		// Grants nothing, but stays listed on the agent so re-enabling restores it.
		if !skill.Enabled {
			logger.WithFields(log.Fields{
				"skillName": skillName,
				"agentName": agent.Name,
			}).Debug("agent holds a disabled skill, granting nothing for it")

			continue
		}

		if guidance := skill.EffectiveGuidance(); guidance != "" {
			prompts = append(prompts, guidance)
		}

		for _, tool := range skill.Tools {
			allowedTools[tool] = struct{}{}
		}
	}

	if ac.systemPromptAddendum != "" {
		prompts = append(prompts, ac.systemPromptAddendum)
	}

	req.SystemAppend = strings.Join(prompts, "\n\n")

	tools := make([]string, 0, len(allowedTools))
	for tool := range allowedTools {
		tools = append(tools, tool)
	}

	ac.agentMu.RLock()
	delegationLibrary := ac.DelegationLibrary
	ac.agentMu.RUnlock()

	req.ToolConfig, err = buildToolConfig(ac.FunctionLibrary, delegationLibrary, tools, agent.CanDelegateTo) // build tools for this agent
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"agentName": agent.Name,
		})
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
		// Collapse internal tool_result statuses (e.g. "rejected") onto the success/error
		// vocabulary every model provider accepts. Done once here so no adapter has to.
		m.ContentBlocks = wireCanonicalToolResults(m.ContentBlocks)

		// Coalesce parallel tool calls: the results answering one multi-tool assistant
		// turn are persisted as separate messages (one per tool, executed by its own
		// request), but the model API requires all of a turn's tool_results in a single
		// user turn. Merge a tool_result-only message into the previous one when both
		// are tool_result-only -- otherwise the adapter emits consecutive user turns,
		// each with one result, which the model/gateway rejects.
		if isToolResultOnly(&m) && len(msgs) > 0 && isToolResultOnly(msgs[len(msgs)-1]) {
			prev := msgs[len(msgs)-1]
			prev.ContentBlocks = append(prev.ContentBlocks, m.ContentBlocks...)
			continue
		}

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

// wireCanonicalToolResults returns content blocks whose tool_result statuses are
// valid to send to any model provider. A tool result is conceptually success-or-error
// everywhere (Bedrock, OpenAI, Gemini, ...), and those providers accept only
// "success"/"error" (or none) -- so internal UI markers like "rejected" are collapsed
// onto that binary using IsError, the provider-independent error signal. Already
// canonical statuses pass through untouched, and originals are never mutated (a block
// is copied only when its status changes) so storage and the inline tool_result event
// keep the real status.
func wireCanonicalToolResults(blocks []model.ContentBlock) []model.ContentBlock {
	out := blocks
	copied := false
	for i := range blocks {
		tr := blocks[i].ToolResult
		if tr == nil {
			continue
		}
		ws := wireToolResultStatus(tr)
		if ws == tr.Status {
			continue
		}
		if !copied {
			out = make([]model.ContentBlock, len(blocks))
			copy(out, blocks)
			copied = true
		}
		trCopy := *tr
		trCopy.Status = ws
		out[i].ToolResult = &trCopy
	}
	return out
}

// wireToolResultStatus maps a tool_result's status to the value model providers
// accept: canonical statuses are kept; anything else collapses to error/success per
// IsError.
func wireToolResultStatus(tr *model.ToolResult) string {
	switch tr.Status {
	case "", "success", "error":
		return tr.Status
	default:
		if tr.IsError {
			return "error"
		}
		return "success"
	}
}

// isToolResultOnly reports whether a message consists solely of tool_result blocks
// (an answer to one or more tool_use calls), so adjacent ones can be merged into a
// single user turn.
func isToolResultOnly(m *model.Message) bool {
	if m == nil || len(m.ContentBlocks) == 0 {
		return false
	}
	for _, cb := range m.ContentBlocks {
		if cb.ToolResult == nil {
			return false
		}
	}
	return true
}
