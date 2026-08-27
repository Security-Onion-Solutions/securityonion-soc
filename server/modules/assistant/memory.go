// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/assistant/database"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
)

// setupMemoryAgents defines the internal roles backing the background memory
// worker: Memory extracts facts from session transcripts, Embed names the
// embedding model, and Reconcile merges new facts against stored memories.
func (ac *AssistantCoordinator) setupMemoryAgents(prompts map[string]string) {
	ac.memoryAgents = map[string]model.Agent{
		"Memory": {
			Name:          "Memory",
			AllowedSkills: []string{},
			CanDelegateTo: []string{},
			Prompt:        prompts["prompt_agent_memory"],
		},
		"Embed": {
			Name:          "Embed",
			AllowedSkills: []string{},
			CanDelegateTo: []string{},
			Prompt:        prompts["prompt_agent_embed"],
		},
		"Reconcile": {
			Name:          "Reconcile",
			AllowedSkills: []string{},
			CanDelegateTo: []string{},
			Prompt:        prompts["prompt_agent_reconcile"],
		},
	}
}

// Re-reads the memory tunables, starting or stopping the scanner and re-arming
// its ticker to match. An unparseable setting keeps the current value.
func (ac *AssistantCoordinator) reloadMemoryConfiguration(ctx context.Context) {
	logger := log.FromContext(ctx)
	settings := ac.memorySnapshot()
	before := settings

	if ac.srv.Configstore != nil {
		stored, err := ac.srv.Configstore.GetSettings(ctx, true)
		if err != nil {
			logger.WithError(err).Error("unable to load settings for memory configuration reload")
		} else {
			byID := make(map[string]*model.Setting, len(stored))
			for _, s := range stored {
				if s != nil {
					byID[s.Id] = s
				}
			}

			settings = applyMemorySettings(logger, settings, byID)
		}
	}

	ac.setMemorySettings(settings)
	ac.applyMemoryAgents(settings)
	ac.exposeMemorySettings()

	ac.applyScannerState(settings.useScanner)

	if settings.scanInterval != before.scanInterval {
		ac.wakeScanner()
	}

	// Also run on the first reload, which Start performs, to pick up a model that
	// was changed while the process was down.
	if settings.useMemory || settings.useScanner {
		ac.startReembed(ctx)
	}
}

// applyMemorySettings overlays the stored settings onto the current values.
func applyMemorySettings(logger log.Interface, settings memorySettings, byID map[string]*model.Setting) memorySettings {
	boolSetting := func(id string, target *bool) {
		s, ok := byID[id]
		if !ok || strings.TrimSpace(s.Value) == "" {
			return
		}

		v, err := strconv.ParseBool(strings.TrimSpace(s.Value))
		if err != nil {
			logger.WithError(err).WithField("setting", id).Warn("invalid boolean; keeping previous value")
			return
		}

		*target = v
	}

	intSetting := func(id string, target *int) {
		s, ok := byID[id]
		if !ok || strings.TrimSpace(s.Value) == "" {
			return
		}

		v, err := parseIntSetting(s.Value)
		if err != nil {
			logger.WithError(err).WithField("setting", id).Warn("invalid integer; keeping previous value")
			return
		}

		*target = v
	}

	floatSetting := func(id string, target *float64) {
		s, ok := byID[id]
		if !ok || strings.TrimSpace(s.Value) == "" {
			return
		}

		v, err := strconv.ParseFloat(strings.TrimSpace(s.Value), 64)
		if err != nil {
			logger.WithError(err).WithField("setting", id).Warn("invalid number; keeping previous value")
			return
		}

		*target = v
	}

	// A model selector is cleared by setting it empty, which disables its role, so
	// an empty stored value is applied rather than ignored.
	stringSetting := func(id string, target *string) {
		if s, ok := byID[id]; ok {
			*target = strings.TrimSpace(s.Value)
		}
	}

	stringSetting(ConfigSettingMemoryModel, &settings.memoryModel)
	stringSetting(ConfigSettingEmbedModel, &settings.embedModel)
	stringSetting(ConfigSettingReconcileModel, &settings.reconcileModel)

	// Personas keep their internal whitespace; only a stored value replaces them.
	if s, ok := byID[ConfigSettingMemoryPersona]; ok {
		settings.memoryPersona = s.Value
	}

	if s, ok := byID[ConfigSettingReconcilePersona]; ok {
		settings.reconcilePersona = s.Value
	}

	boolSetting(ConfigSettingUseMemory, &settings.useMemory)
	boolSetting(ConfigSettingUseMemoryScanner, &settings.useScanner)
	floatSetting(ConfigSettingMemoryProximity, &settings.mem2mem)
	floatSetting(ConfigSettingMessageProximity, &settings.mem2msg)
	intSetting(ConfigSettingMaxUserMemoriesToInclude, &settings.maxUserInclude)
	intSetting(ConfigSettingMaxGlobalMemoriesToInclude, &settings.maxGlobalInclude)
	intSetting(ConfigSettingMaxUserMemoriesToReconcile, &settings.maxUserReconcile)
	intSetting(ConfigSettingMaxGlobalMemoriesToReconcile, &settings.maxGlobalReconcile)

	seconds := int(settings.scanInterval / time.Second)
	intSetting(ConfigSettingMemoryScanInterval, &seconds)

	// A zero or negative interval would panic time.NewTicker, so refuse it.
	if seconds > 0 {
		settings.scanInterval = time.Duration(seconds) * time.Second
	} else {
		logger.WithField("setting", ConfigSettingMemoryScanInterval).Warn("scan interval must be positive; keeping previous value")
	}

	return settings
}

func (ac *AssistantCoordinator) exposeMemorySettings() {
	settings := ac.memorySnapshot()

	params := &ac.srv.Config.ClientParams.AssistantParams
	params.MemoryEnabled = settings.useMemory || settings.useScanner
	params.MemoryParams = model.MemoryParameters{
		UseMemory:                    settings.useMemory,
		UseMemoryScanner:             settings.useScanner,
		ScanIntervalSeconds:          int(settings.scanInterval / time.Second),
		MemoryProximityThreshold:     settings.mem2mem,
		MessageProximityThreshold:    settings.mem2msg,
		MaxUserMemoriesToInclude:     settings.maxUserInclude,
		MaxGlobalMemoriesToInclude:   settings.maxGlobalInclude,
		MaxUserMemoriesToReconcile:   settings.maxUserReconcile,
		MaxGlobalMemoriesToReconcile: settings.maxGlobalReconcile,
		MemoryModel:                  settings.memoryModel,
		EmbedModel:                   settings.embedModel,
		ReconcileModel:               settings.reconcileModel,
		MemoryPersona:                settings.memoryPersona,
		ReconcilePersona:             settings.reconcilePersona,
		StaleMemoryCount:             int(ac.staleMemories.Load()),
	}

	ac.broadcastAgenticUpdate()
}

// Publishes re-embed progress.
func (ac *AssistantCoordinator) setStaleMemoryCount(stale int) {
	ac.staleMemories.Store(int64(stale))
	ac.exposeMemorySettings()
}

func (ac *AssistantCoordinator) startReembed(ctx context.Context) {
	ac.memoryWorkerMu.Lock()
	if ac.reembedding || ac.store == nil {
		ac.memoryWorkerMu.Unlock()
		return
	}

	// The pass outlives the request that triggered it, so it keeps that context's
	// values but takes its cancellation from Stop instead.
	passCtx, cancel := context.WithCancelCause(context.WithoutCancel(ctx))

	ac.reembedding = true
	ac.terminateReembed = cancel
	ac.memoryWorkerMu.Unlock()

	go func() {
		defer func() {
			cancel(nil)

			ac.memoryWorkerMu.Lock()
			ac.reembedding = false
			ac.terminateReembed = nil
			ac.memoryWorkerMu.Unlock()
		}()

		ac.reembedStaleMemories(passCtx)
	}()
}

// Bounds one embedding call so a stalled gateway cannot park the pass forever.
func (ac *AssistantCoordinator) embedWithTimeout(ctx context.Context, selector string, texts []string) (*model.EmbeddingResponse, error) {
	timeout := ac.reembedCallTimeout
	if timeout <= 0 {
		timeout = MEMORY_REEMBED_CALL_TIMEOUT
	}

	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return ac.Embed(callCtx, selector, texts)
}

func (ac *AssistantCoordinator) reembedStaleMemories(ctx context.Context) {
	logger := log.FromContext(ctx).WithField("memoryReembedId", uuid.NewString())

	_, embedModel, err := ac.resolveMemoryAgent("Embed")
	if err != nil {
		logger.WithError(err).Error("unable to resolve Embed agent; not re-embedding")
		return
	}

	// One usage session per pass; per-batch recording would create hundreds of
	// sessions and copy every memory text into chat storage. Recorded in a defer,
	// detached from ctx, so an interrupted pass still books what it spent.
	var passUsage model.Usage

	done := 0

	addUsage := func(res *model.EmbeddingResponse) {
		if res != nil && res.Usage != nil {
			passUsage.InputTokens += res.Usage.InputTokens
			passUsage.OutputTokens += res.Usage.OutputTokens
			passUsage.Credits += res.Usage.Credits
		}
	}

	defer func() {
		recCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second*10)
		defer cancel()

		summary := fmt.Sprintf("Re-embedded %d memories using %s", done, embedModel.Selector())
		ac.recordEmbedUsageSummary(recCtx, summary, passUsage, embedModel.Selector())
	}()

	// model_id is whatever the provider reported, not the selector, so a probe
	// embedding names the current model.
	probe, err := ac.embedWithTimeout(ctx, embedModel.Selector(), []string{"probe"})
	addUsage(probe)
	if err != nil || len(probe.Embeddings) == 0 {
		logger.WithError(err).Error("unable to determine the current embedding model; not re-embedding")
		return
	}

	current := probe.Model

	total, err := ac.store.CountStaleMemories(ctx, current)
	if err != nil {
		logger.WithError(err).Error("unable to count memories needing re-embedding")
		return
	}

	ac.setStaleMemoryCount(total)

	if total == 0 {
		return
	}

	logger.WithFields(log.Fields{"staleCount": total, "embedModel": current}).Info("re-embedding memories after an embedding model change")

	start := time.Now()

	for {
		batch, err := ac.store.StaleMemoryBatch(ctx, current, MEMORY_REEMBED_BATCH_SIZE)
		if err != nil {
			logger.WithError(err).Error("unable to read memories needing re-embedding")
			return
		}

		if len(batch) == 0 {
			break
		}

		texts := make([]string, 0, len(batch))
		for _, mem := range batch {
			texts = append(texts, mem.MemoryText)
		}

		res, err := ac.embedWithTimeout(ctx, embedModel.Selector(), texts)
		addUsage(res)
		if err != nil {
			logger.WithError(err).WithField("reembedded", done).Error("unable to embed; stopping re-embed pass")
			return
		}

		if len(res.Embeddings) != len(batch) {
			logger.WithFields(log.Fields{
				"embeddingsCount": len(res.Embeddings),
				"batchSize":       len(batch),
			}).Error("unexpected number of embeddings returned; stopping re-embed pass")

			return
		}

		// Storing a model the batch query does not filter on would re-read the same
		// rows forever. The next pass re-probes and picks up the new model.
		if res.Model != current {
			logger.WithFields(log.Fields{
				"expectedModel": current,
				"embedModel":    res.Model,
				"reembedded":    done,
			}).Error("embedding model changed mid-pass; stopping re-embed pass")

			return
		}

		for i, mem := range batch {
			if err := ac.store.SetMemoryEmbedding(ctx, mem.Id, res.Embeddings[i], res.Model); err != nil {
				logger.WithError(err).WithField("memoryId", mem.Id).Error("unable to store re-embedded memory")
				return
			}

			done++
		}

		ac.setStaleMemoryCount(max(total-done, 0))
		logger.WithFields(log.Fields{"reembedded": done, "staleCount": total}).Debug("re-embed progress")

		select {
		case <-ctx.Done():
			logger.WithField("reembedded", done).Info("re-embed pass interrupted; remaining memories are picked up by the next pass")
			return
		case <-time.After(ac.reembedBatchDelay):
		}
	}

	ac.setStaleMemoryCount(0)

	logger.WithFields(log.Fields{
		"reembedded":      done,
		"reembedDuration": time.Since(start),
	}).Info("re-embed pass complete")
}

// Rebuilds the memory roles and their model mapping. A rebuild, not a
// revalidation, since validateMemoryMappings deletes the roles it disables.
func (ac *AssistantCoordinator) applyMemoryAgents(settings memorySettings) {
	if !settings.useMemory && !settings.useScanner {
		ac.memoryAgents = nil
		ac.memoryMapping = nil

		return
	}

	ac.setupMemoryAgents(ac.embeddedPrompts)
	ac.memoryMapping = map[string]string{
		"Memory":    settings.memoryModel,
		"Embed":     settings.embedModel,
		"Reconcile": settings.reconcileModel,
	}

	for role, persona := range map[string]string{"Memory": settings.memoryPersona, "Reconcile": settings.reconcilePersona} {
		if agent, ok := ac.memoryAgents[role]; ok {
			agent.PersonaAddendum = persona
			ac.memoryAgents[role] = agent
		}
	}

	ac.validateMemoryMappings()
}

// validateMemoryMappings drops any memory role whose configured model
// selector is missing or does not resolve to an enabled model.
func (ac *AssistantCoordinator) validateMemoryMappings() {
	logger := log.FromContext(ac.srv.Context)

	for name := range ac.memoryAgents {
		modelSelector, mapped := ac.memoryMapping[name]
		if !mapped || modelSelector == "" {
			logger.WithField("memoryRole", name).Error("memory role has no configured model; disabling role")
			delete(ac.memoryAgents, name)
			continue
		}

		params := ac.resolveModel(modelSelector)
		if params == nil || !params.Enabled {
			logger.WithFields(log.Fields{
				"memoryRole": name,
				"model":      modelSelector,
			}).Error("memory role maps to a model that is not configured or not enabled; disabling role")
			delete(ac.memoryAgents, name)
		}
	}
}

func (ac *AssistantCoordinator) memoryWorker(ctx context.Context, wake <-chan struct{}) {
	logger := log.FromContext(ctx)

	interval := ac.memorySnapshot().scanInterval
	logger.WithField("interval", interval).Info("starting interval")
	ticker := time.NewTicker(interval)

	// defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			err := context.Cause(ctx)
			logger.WithField("cause", err).Info("memory worker shutting down")

			return
		case <-wake:
			// The interval changed; re-arm and wait out the new one rather than
			// scanning immediately.
			if next := ac.memorySnapshot().scanInterval; next != interval {
				interval = next
				ticker.Reset(interval)

				logger.WithField("memoryScanInterval", interval).Info("memory scan interval updated")
			}

			continue
		case <-ticker.C:
		}

		logger := log.FromContext(ctx).WithField("memoryScanId", uuid.NewString())

		if ac.store == nil {
			logger.Warn("no database connection; skipping scan")
			continue
		}

		logger.Info("starting memory scan")

		start := time.Now()

		ac.scanForMemories(ctx, logger)

		logger.WithField("memoryScanDuration", time.Since(start)).Info("scan completed")
	}
}

func (ac *AssistantCoordinator) scanForMemories(ctx context.Context, logger *log.Entry) {
	defer func() {
		if r := recover(); r != nil {
			logger.WithField("recoverValue", r).Error("recovered from an error in the memory pipeline")
		}
	}()

	memoryAgent, memoryModel, err := ac.resolveMemoryAgent("Memory")
	if err != nil {
		logger.WithError(err).Error("unable to resolve Memory agent, ending scan")
		return
	}

	_, embedModel, err := ac.resolveMemoryAgent("Embed")
	if err != nil {
		logger.WithError(err).Error("unable to resolve Embed agent, ending scan")
		return
	}

	logger.Info("scanning for sessions that need memory processing")

	queryResults, err := ac.srv.Assistantstore.FindSessionsPendingMemoryScan(ctx)
	if err != nil {
		logger.WithError(err).Error("unable to find sessions pending memory scan")
		return
	}

	logger.WithField("sessionCount", len(queryResults)).Info("query complete")

	for _, sessionDetails := range queryResults {
		logger.WithFields(log.Fields{
			"sessionId":              sessionDetails.Session.SessionId,
			"lastMemoryScannedIndex": sessionDetails.Session.LastMemoryScannedIndex,
		}).Info("scanning for memories to add")

		// Extract
		facts, extractExchange, err := ac.extractFacts(ctx, sessionDetails, memoryAgent, memoryModel)
		ac.recordAgentSession(ctx, model.SessionTagMemory, sessionDetails.Session.SessionId, memoryModel.Selector(), extractExchange)
		if err != nil {
			logger.WithError(err).Error("unable to extract facts")
			continue
		}

		sesOwnerCtx := context.WithValue(ctx, web.ContextKeyRequestorId, sessionDetails.Session.UserId)

		before := len(facts)

		// filter facts by user permissions
		facts = ac.filterFactsByUserPerms(sesOwnerCtx, facts)

		filteredFacts := before - len(facts)

		logger.WithFields(log.Fields{
			"factsCount":    len(facts),
			"factsFiltered": filteredFacts,
		}).Info("extracted facts")

		if len(facts) != 0 {
			justFacts := make([]string, 0, len(facts))
			for _, f := range facts {
				justFacts = append(justFacts, f.Fact)
			}

			logger.WithField("sessionId", sessionDetails.Session.SessionId).Info("embedding facts")

			// Embed
			res, err := ac.Embed(ctx, embedModel.Selector(), justFacts)
			if err != nil {
				logger.WithError(err).Error("unable to embed")
				continue
			}

			ac.recordEmbedUsage(ctx, sessionDetails.Session.SessionId, embedModel.Selector(), res, justFacts)

			if len(res.Embeddings) != len(facts) {
				logger.WithFields(log.Fields{
					"embeddingsCount": len(res.Embeddings),
					"factsCount":      len(facts),
				}).Error("unexpected number of embeddings returned")

				continue
			}

			mems := make([]*model.Memory, 0, len(facts))
			for i, fact := range facts {
				var target *string

				if strings.EqualFold(fact.Scope, "user") {
					target = new(sessionDetails.Session.UserId)
				}

				mems = append(mems, &model.Memory{
					Auditable: model.Auditable{
						UserId: server.SYSTEM_ID,
						Kind:   "memory",
					},
					MemoryText:   fact.Fact,
					SessionId:    sessionDetails.Session.SessionId,
					Embedding:    res.Embeddings[i],
					ModelID:      res.Model,
					TargetUserId: target,
				})
			}

			logger.Info("reconciling against existing memories")

			// Reconcile
			memChanges, reconcileExchanges, reconcileSelector, err := ac.reconcileMemories(sesOwnerCtx, mems)
			for _, exchange := range reconcileExchanges {
				ac.recordAgentSession(ctx, model.SessionTagReconcile, sessionDetails.Session.SessionId, reconcileSelector, exchange)
			}
			if err != nil {
				logger.WithError(err).Error("unable to reconcile memories")
				continue
			}

			logger.WithField("numChanges", len(memChanges)).Info("reconciled memories")

			// Reembed
			reembed := []*model.ReconciledMemory{}
			for _, change := range memChanges {
				if change.ReEmbed {
					reembed = append(reembed, change)
				}
			}

			if len(reembed) != 0 {
				logger.WithField("reembedCount", len(reembed)).Info("reembeding reconciled memories that were altered")

				justFacts = make([]string, 0, len(reembed))
				for _, r := range reembed {
					justFacts = append(justFacts, r.Memory.MemoryText)
				}

				res, err := ac.Embed(ctx, embedModel.Selector(), justFacts)
				if err != nil {
					logger.WithError(err).Error("unable to embed")
					continue
				}

				ac.recordEmbedUsage(ctx, sessionDetails.Session.SessionId, embedModel.Selector(), res, justFacts)

				if len(res.Embeddings) != len(reembed) {
					logger.WithFields(log.Fields{
						"embeddingsCount": len(res.Embeddings),
						"reembedCount":    len(reembed),
					}).Error("unexpected number of embeddings returned")

					continue
				}

				for i, emb := range res.Embeddings {
					reembed[i].Memory.Embedding = emb
				}
			}

			// Update
			if len(memChanges) != 0 {
				logger.Info("applying memory changes")

				created, updated, deleted, errMap := ac.applyMemories(ctx, memChanges)
				if len(errMap) != 0 {
					logger.WithField("errMap", util.TruncateMap(errMap, 5)).Error("unable to apply reconciled memories")
				}

				logger.WithFields(log.Fields{
					"memories": len(facts),
					"created":  created,
					"updated":  updated,
					"deleted":  deleted,
					"errored":  len(errMap),
				}).Info("applied memories")
			}
		}

		err = ac.srv.Assistantstore.UpdateSessionMemoryScanIndex(ctx, sessionDetails.Session.SessionId, len(sessionDetails.History))
		if err != nil {
			logger.WithError(err).WithField("sessionId", sessionDetails.Session.SessionId).Error("unable to update session with new memory scan count")
			continue
		}
	}
}

// memoryPerms reports whether the requestor may act on their own memories and
// on global memories for the given verb ("read" or "write"). The self-scoped
// permission names are asymmetric (read_authored vs write_self), so the
// mapping lives here rather than at each call site.
func (ac *AssistantCoordinator) memoryPerms(ctx context.Context, verb string) (self bool, global bool) {
	selfOp := verb + "_self"
	if verb == "read" {
		selfOp = "read_authored"
	}

	self = ac.srv.CheckAuthorized(ctx, selfOp, "memory") == nil
	global = ac.srv.CheckAuthorized(ctx, verb+"_global", "memory") == nil

	return self, global
}

// filterFactsByUserPerms filters out candidate facts that the user is not allowed to write.
func (ac *AssistantCoordinator) filterFactsByUserPerms(ctx context.Context, facts []*model.ExtractedFact) (filtered []*model.ExtractedFact) {
	filtered = make([]*model.ExtractedFact, 0, len(facts))

	canWriteSelf, canWriteGlobal := ac.memoryPerms(ctx, "write")
	if !canWriteSelf {
		return nil
	}

	// the memory scanner cannot result in a fact written by one user being applied
	// explicitly to another user, no need to check write_all here.

	for _, fact := range facts {
		if strings.EqualFold(fact.Scope, "global") {
			if canWriteGlobal {
				filtered = append(filtered, fact)
			}
		} else {
			filtered = append(filtered, fact)
		}
	}

	return filtered
}

// extractFacts also returns the request/response exchange whenever the send
// itself succeeded — even when the response content is unusable — so the
// caller can record the token usage that was spent either way.
func (ac *AssistantCoordinator) extractFacts(ctx context.Context, details *model.AssistantSessionDetails, memoryAgent *model.Agent, memoryModel *model.ModelParameters) ([]*model.ExtractedFact, []*model.Message, error) {
	logger := log.FromContext(ctx)
	ts := buildMemoryExtractTranscript(details)

	req := &model.ChatRequest{
		Messages: []*model.Message{
			{
				Role: "user",
				ContentBlocks: []model.ContentBlock{
					{
						Type: "text",
						Text: ts,
					},
				},
			},
		},
		UserId: server.SYSTEM_ID,
		Model:  memoryModel.ID,
	}

	err := ac.setupAgent(ctx, req, memoryAgent)
	if err != nil {
		return nil, nil, err
	}

	adapter, ok := ac.adapters[memoryModel.Adapter]
	if !ok {
		logger.WithField("adapterName", memoryModel.Adapter).Error("Memory Agent's model references unknown adapter")
		return nil, nil, fmt.Errorf("unknown adapter for memory model")
	}

	msg, err := adapter.SendMessage(ctx, req)
	if err != nil {
		return nil, nil, err
	}

	exchange := []*model.Message{req.Messages[0], msg}

	var jsn string
	for _, cb := range msg.ContentBlocks {
		if strings.EqualFold(cb.Type, "Text") {
			jsn = cb.Text
		}
	}

	if len(jsn) == 0 {
		return nil, exchange, fmt.Errorf("no returned content from Extraction agent")
	}

	extracted := []*model.ExtractedFact{}

	err = json.Unmarshal([]byte(jsn), &extracted)
	if err != nil {
		return nil, exchange, err
	}

	normalized := make([]*model.ExtractedFact, 0, len(extracted))
	// normalize
	for _, fact := range extracted {
		if fact == nil {
			continue
		}

		// Collapse all interior whitespace
		fact.Fact = strings.Join(strings.Fields(fact.Fact), " ")

		// The prompt allows only "user" and "global" and says to default to
		// "user" when unsure; normalize anything unexpected the same way.
		if strings.EqualFold(fact.Scope, "global") {
			fact.Scope = "global"
		} else {
			fact.Scope = "user"
		}

		if len(fact.Fact) > 0 {
			normalized = append(normalized, fact)
		}
	}

	return normalized, exchange, nil
}

// reconcileMemories also returns the request/response exchanges collected so
// far — one per Reconcile agent call, even on a mid-loop error — along with the
// resolved model selector, so the caller can record the token usage that was
// spent either way.
func (ac *AssistantCoordinator) reconcileMemories(ctx context.Context, mems []*model.Memory) (ops []*model.ReconciledMemory, exchanges [][]*model.Message, selector string, err error) {
	if ac.store == nil {
		return nil, nil, "", ErrNoDatabase
	}

	logger := log.FromContext(ctx)

	// retrieve agent and setup before looping
	agentParams, modelParams, err := ac.resolveMemoryAgent("Reconcile")
	if err != nil {
		return nil, nil, "", err
	}

	selector = modelParams.Selector()

	adapter, ok := ac.adapters[modelParams.Adapter]
	if !ok {
		logger.WithField("adapterName", modelParams.Adapter).Error("Reconcile Agent's model references unknown adapter")
		return nil, nil, selector, fmt.Errorf("unknown adapter for memory model")
	}

	canWriteSelf, canWriteGlobal := ac.memoryPerms(ctx, "write")
	settings := ac.memorySnapshot()

	ops = make([]*model.ReconciledMemory, 0, len(mems))

	for _, mem := range mems {
		// filter out candidates whose scope the session owner cannot write
		if (mem.TargetUserId == nil && !canWriteGlobal) || (mem.TargetUserId != nil && !canWriteSelf) {
			continue
		}

		// find similar memories, limited to scopes the session owner is allowed
		// to modify: their own memories, plus global memories only if they can
		// write global, one scope per query
		var nearby []*model.NearbyMemory

		if canWriteGlobal && settings.maxGlobalReconcile > 0 {
			nearby, err = ac.store.FindNearbyMemories(ctx, mem.Embedding, mem.ModelID, database.GlobalMemories(), database.WithMinSimilarity(settings.mem2mem), database.WithLimit(settings.maxGlobalReconcile))
			if err != nil {
				return nil, exchanges, selector, err
			}
		}

		if mem.TargetUserId != nil && settings.maxUserReconcile > 0 {
			userNearby, err := ac.store.FindNearbyMemories(ctx, mem.Embedding, mem.ModelID, database.UserMemories(*mem.TargetUserId), database.WithMinSimilarity(settings.mem2mem), database.WithLimit(settings.maxUserReconcile))
			if err != nil {
				return nil, exchanges, selector, err
			}

			nearby = append(nearby, userNearby...)
		}

		sort.Slice(nearby, func(i, j int) bool {
			return nearby[i].Similarity > nearby[j].Similarity
		})

		if len(nearby) == 0 {
			// there are no similar memories, add this memory
			ops = append(ops, &model.ReconciledMemory{
				Action: "ADD",
				Memory: mem,
			})

			continue
		}

		// there are similar memories so we're going to ask the Reconcile agent
		// to sort things out

		memScope := "global"
		if mem.TargetUserId != nil {
			memScope = "user"
		}

		body := model.ReconcileMemoryBody{
			Candidate: model.ReconcileCandidate{
				Content: mem.MemoryText,
				Scope:   memScope,
			},
			Neighbors: make([]model.MemoryNeighbor, 0, len(nearby)),
		}

		nearbyById := map[string]*model.NearbyMemory{}
		for _, near := range nearby {
			nearbyScope := "global"
			if near.Memory.TargetUserId != nil {
				nearbyScope = "user"
			}

			body.Neighbors = append(body.Neighbors, model.MemoryNeighbor{
				Id:          near.Memory.Id,
				Content:     near.Memory.MemoryText,
				Scope:       nearbyScope,
				Similarity:  near.Similarity,
				UserDefined: near.Memory.UserDefined,
			})

			nearbyById[near.Memory.Id] = near
		}

		rawBody, err := json.Marshal(body)
		if err != nil {
			return nil, exchanges, selector, err
		}

		req := &model.ChatRequest{
			Messages: []*model.Message{
				{
					Role: "user",
					ContentBlocks: []model.ContentBlock{
						{
							Type: "text",
							Text: string(rawBody),
						},
					},
				},
			},
			UserId: server.SYSTEM_ID,
			Model:  modelParams.ID,
		}

		err = ac.setupAgent(ctx, req, agentParams)
		if err != nil {
			return nil, exchanges, selector, err
		}

		msg, err := adapter.SendMessage(ctx, req)
		if err != nil {
			return nil, exchanges, selector, err
		}

		exchanges = append(exchanges, []*model.Message{req.Messages[0], msg})

		var rawResult string
		for _, cb := range msg.ContentBlocks {
			if strings.EqualFold(cb.Type, "Text") {
				rawResult = cb.Text
			}
		}

		if len(rawResult) == 0 {
			return nil, exchanges, selector, fmt.Errorf("no returned content from Reconcile agent")
		}

		changes := model.MemoryOperations{}

		err = json.Unmarshal([]byte(rawResult), &changes)
		if err != nil {
			return nil, exchanges, selector, err
		}

		changes.RemoveInvalid(body.Neighbors)

		for _, op := range changes.Operations {
			action := strings.ToUpper(op.Op)
			reembed := false

			switch action {
			case "ADD":
				if op.Content != nil && mem.MemoryText != *op.Content {
					mem.MemoryText = *op.Content
					reembed = true
				}
			case "UPDATE":
				if op.Content != nil && mem.MemoryText != *op.Content {
					mem.MemoryText = *op.Content
					reembed = true
				}

				if op.TargetId != nil {
					mem.Auditable.Id = *op.TargetId

					// match scope with target
					other, ok := nearbyById[*op.TargetId]
					if ok {
						if other.Memory.TargetUserId == nil {
							mem.TargetUserId = nil
						} else {
							mem.TargetUserId = new(*other.Memory.TargetUserId)
						}
					}
				}

			case "NOOP":
				continue
			}

			if action == "DELETE" {
				// changes.RemoveInvalid() ensured op.TargetId is not null
				ops = append(ops, &model.ReconciledMemory{
					Action: action,
					Memory: &model.Memory{
						Auditable: model.Auditable{
							Id: *op.TargetId,
						},
					},
				})
			} else {
				ops = append(ops, &model.ReconciledMemory{
					Action:  action,
					ReEmbed: reembed,
					Memory:  mem,
				})
			}
		}
	}

	return ops, exchanges, selector, nil
}

// memoryReadScope builds the WHERE clause limiting a listing to the memories the
// requestor is allowed to read, returning the args the clause references.
func (ac *AssistantCoordinator) memoryReadScope(ctx context.Context, filter *model.MemoryFilter) (string, []any, error) {
	requestorId, ok := ctx.Value(web.ContextKeyRequestorId).(string)
	if !ok {
		return "", nil, errors.New("context is missing RequestorId")
	}

	canReadSelf, canReadGlobal := ac.memoryPerms(ctx, "read")
	canReadAll := ac.srv.CheckAuthorized(ctx, "read_all", "memory") == nil

	targetUserId := requestorId
	if filter.TargetUserId != "" && filter.TargetUserId != requestorId {
		if !canReadAll {
			return "", nil, ErrUnauthorizedMemory
		}

		targetUserId = filter.TargetUserId
	}

	args := []any{}

	switch strings.ToLower(filter.Scope) {
	case model.MemoryScopeSelf:
		if !canReadSelf && !canReadAll {
			return "", nil, ErrUnauthorizedMemory
		}

		args = append(args, targetUserId)

		return fmt.Sprintf(`target_user_id = $%d`, len(args)), args, nil
	case model.MemoryScopeGlobal:
		if !canReadGlobal {
			return "", nil, ErrUnauthorizedMemory
		}

		return `target_user_id IS NULL`, args, nil
	default:
		if canReadAll && filter.TargetUserId == "" {
			return `TRUE`, args, nil
		}

		clauses := []string{}

		if canReadSelf || canReadAll {
			args = append(args, targetUserId)
			clauses = append(clauses, fmt.Sprintf(`target_user_id = $%d`, len(args)))
		}

		if canReadGlobal || canReadAll {
			clauses = append(clauses, `target_user_id IS NULL`)
		}

		if len(clauses) == 0 {
			return "", nil, ErrUnauthorizedMemory
		}

		return `(` + strings.Join(clauses, ` OR `) + `)`, args, nil
	}
}

func (ac *AssistantCoordinator) ListMemories(ctx context.Context, filter *model.MemoryFilter) (*model.MemoryResults, error) {
	if ac.store == nil {
		return nil, ErrNoDatabase
	}

	if filter == nil {
		filter = &model.MemoryFilter{}
	}

	where, args, err := ac.memoryReadScope(ctx, filter)
	if err != nil {
		return nil, err
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = DEFAULT_MEMORY_PAGE_SIZE
	}

	query := database.MemoryQuery{
		Where:  where,
		Args:   args,
		Limit:  min(limit, MAX_MEMORY_PAGE_SIZE),
		Offset: max(filter.Offset, 0),
	}

	if strings.TrimSpace(filter.Query) != "" {
		_, embedModel, err := ac.resolveMemoryAgent("Embed")
		if err != nil {
			return nil, err
		}

		resp, err := ac.Embed(ctx, embedModel.Selector(), []string{filter.Query})
		if err != nil {
			return nil, err
		}

		ac.recordEmbedUsageAsync(ctx, "", embedModel.Selector(), resp, []string{filter.Query})

		if len(resp.Embeddings) != 1 {
			return nil, fmt.Errorf("expected 1 embedding but got %d", len(resp.Embeddings))
		}

		query.Embedding = resp.Embeddings[0]
		query.EmbedModelId = resp.Model
	}

	return ac.store.ListMemories(ctx, query)
}

func (ac *AssistantCoordinator) checkMemoryWrite(ctx context.Context, requestorId string, targetUserId *string) error {
	op := "write_all"

	switch {
	case targetUserId == nil:
		op = "write_global"
	case *targetUserId == requestorId:
		op = "write_self"
	}

	if err := ac.srv.CheckAuthorized(ctx, op, "memory"); err != nil {
		return fmt.Errorf("%w: %s", ErrUnauthorizedMemory, err)
	}

	return nil
}

func (ac *AssistantCoordinator) SaveMemory(ctx context.Context, mem *model.Memory) error {
	if ac.store == nil {
		return ErrNoDatabase
	}

	requestorId, ok := ctx.Value(web.ContextKeyRequestorId).(string)
	if !ok {
		return errors.New("context is missing RequestorId")
	}

	mem.MemoryText = strings.Join(strings.Fields(mem.MemoryText), " ")
	if mem.MemoryText == "" {
		return ErrInvalidMemory
	}

	if mem.Id != "" {
		existing, err := ac.store.GetMemory(ctx, mem.Id)
		if err != nil {
			return err
		}

		// The scope it is moving out of has to be writable too, so an edit cannot
		// launder a memory through a scope the requestor could not have changed.
		if err := ac.checkMemoryWrite(ctx, requestorId, existing.TargetUserId); err != nil {
			return err
		}

		mem.UserId = existing.UserId
		mem.SessionId = existing.SessionId
	} else {
		mem.UserId = requestorId
	}

	if err := ac.checkMemoryWrite(ctx, requestorId, mem.TargetUserId); err != nil {
		return err
	}

	_, embedModel, err := ac.resolveMemoryAgent("Embed")
	if err != nil {
		return err
	}

	resp, err := ac.Embed(ctx, embedModel.Selector(), []string{mem.MemoryText})
	if err != nil {
		return err
	}

	ac.recordEmbedUsageAsync(ctx, "", embedModel.Selector(), resp, []string{mem.MemoryText})

	if len(resp.Embeddings) != 1 {
		return fmt.Errorf("expected 1 embedding but got %d", len(resp.Embeddings))
	}

	mem.Embedding = resp.Embeddings[0]
	mem.ModelID = resp.Model
	mem.UserDefined = true
	mem.Kind = "memory"

	if mem.Id == "" {
		return ac.store.AddMemory(ctx, mem)
	}

	return ac.store.UpdateMemory(ctx, mem)
}

func (ac *AssistantCoordinator) RemoveMemory(ctx context.Context, id string) error {
	if ac.store == nil {
		return ErrNoDatabase
	}

	requestorId, ok := ctx.Value(web.ContextKeyRequestorId).(string)
	if !ok {
		return errors.New("context is missing RequestorId")
	}

	existing, err := ac.store.GetMemory(ctx, id)
	if err != nil {
		return err
	}

	if err := ac.checkMemoryWrite(ctx, requestorId, existing.TargetUserId); err != nil {
		return err
	}

	return ac.store.DeleteMemory(ctx, id)
}

func (ac *AssistantCoordinator) applyMemories(ctx context.Context, memories []*model.ReconciledMemory) (created int, updated int, deleted int, errMap map[string]string) {
	errMap = map[string]string{}

	for _, mem := range memories {
		action := strings.ToUpper(mem.Action)

		var err error

		switch action {
		case "ADD":
			err = ac.store.AddMemory(ctx, mem.Memory)
			if err == nil {
				created++
			}
		case "UPDATE":
			err = ac.store.UpdateMemory(ctx, mem.Memory)
			if err == nil {
				updated++
			}
		case "DELETE":
			err = ac.store.DeleteMemory(ctx, mem.Memory.Id)
			if err == nil {
				deleted++
			}
		case "NOOP":
		default:
			err = fmt.Errorf("unknown memory action: %s", mem.Action)
		}

		if err != nil {
			if action != "DELETE" {
				if mem.Memory.Id != "" {
					errMap[mem.Memory.Id] = err.Error()
				} else {
					// no ID and we want to keep memories out of the log
					// so md5 fingerprint
					h := md5.Sum([]byte(mem.Memory.MemoryText))
					fp := base64.StdEncoding.EncodeToString(h[:])

					errMap[fp] = err.Error()
				}
			} else {
				errMap["DELETE "+mem.Memory.Id] = err.Error()
			}
		}
	}

	return created, updated, deleted, errMap
}

func buildMemoryExtractTranscript(details *model.AssistantSessionDetails) string {
	lines := []string{}

	begin := max(details.Session.LastMemoryScannedIndex-2, 0)

	if begin >= len(details.History) {
		return ""
	}

	for _, msg := range details.History[begin:] {
		line := strings.Builder{}
		line.WriteString(msg.Message.Role)
		line.WriteString(": ")
		for _, cb := range msg.Message.ContentBlocks {
			if strings.EqualFold(cb.Type, "text") {
				line.WriteString(cb.Text)
			}
		}

		lines = append(lines, line.String())
	}

	return strings.Join(lines, "\n\n")
}

func (ac *AssistantCoordinator) fetchMemoriesForPrompt(ctx context.Context, content string, sourceSessionId string) (user []*model.NearbyMemory, global []*model.NearbyMemory, err error) {
	if ac.store == nil {
		return nil, nil, ErrNoDatabase
	}

	logger := log.FromContext(ctx)

	userId, ok := ctx.Value(web.ContextKeyRequestorId).(string)
	if !ok {
		err := errors.New("context is missing RequestorId")
		logger.WithError(err).Error("invalid context")

		return nil, nil, err
	}

	canReadSelf, canReadGlobal := ac.memoryPerms(ctx, "read")

	if !canReadSelf {
		return nil, nil, nil
	}

	_, embedModel, err := ac.resolveMemoryAgent("Embed")
	if err != nil {
		return nil, nil, err
	}

	resp, err := ac.Embed(ctx, embedModel.Selector(), []string{content})
	if err != nil {
		return nil, nil, err
	}

	ac.recordEmbedUsageAsync(ctx, sourceSessionId, embedModel.Selector(), resp, []string{content})

	if len(resp.Embeddings) != 1 {
		err := fmt.Errorf("expected 1 embedding but got %d", len(resp.Embeddings))
		return nil, nil, err
	}

	emb := resp.Embeddings[0]
	modelUsed := resp.Model
	settings := ac.memorySnapshot()

	if settings.maxUserInclude > 0 {
		user, err = ac.store.FindNearbyMemories(ctx, emb, modelUsed, database.UserMemories(userId), database.WithMinSimilarity(settings.mem2msg), database.WithLimit(settings.maxUserInclude))
		if err != nil {
			return nil, nil, err
		}
	}

	if canReadGlobal && settings.maxGlobalInclude > 0 {
		global, err = ac.store.FindNearbyMemories(ctx, emb, modelUsed, database.GlobalMemories(), database.WithMinSimilarity(settings.mem2msg), database.WithLimit(settings.maxGlobalInclude))
		if err != nil {
			return nil, nil, err
		}
	}

	return user, global, nil
}
