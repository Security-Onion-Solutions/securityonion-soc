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

func (ac *AssistantCoordinator) memoryWorker(ctx context.Context) {
	logger := log.FromContext(ctx)

	ticker := time.NewTicker(ac.memoryScanInterval)

	for {
		select {
		case <-ctx.Done():
			err := context.Cause(ctx)
			logger.WithField("cause", err).Info("memory worker shutting down")

			return
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

	// Only needed to label the Reconcile usage records; reconcileMemories
	// re-resolves for itself and reports its own error, so a failure here just
	// skips Reconcile usage recording.
	var reconcileSelector string
	if _, reconcileModel, err := ac.resolveMemoryAgent("Reconcile"); err == nil {
		reconcileSelector = reconcileModel.Selector()
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
			memChanges, reconcileExchanges, err := ac.reconcileMemories(sesOwnerCtx, mems)
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
// far — one per Reconcile agent call, even on a mid-loop error — so the caller
// can record the token usage that was spent either way.
func (ac *AssistantCoordinator) reconcileMemories(ctx context.Context, mems []*model.Memory) (ops []*model.ReconciledMemory, exchanges [][]*model.Message, err error) {
	if ac.store == nil {
		return nil, nil, ErrNoDatabase
	}

	logger := log.FromContext(ctx)

	// retrieve agent and setup before looping
	agentParams, modelParams, err := ac.resolveMemoryAgent("Reconcile")
	if err != nil {
		return nil, nil, err
	}

	adapter, ok := ac.adapters[modelParams.Adapter]
	if !ok {
		logger.WithField("adapterName", modelParams.Adapter).Error("Reconcile Agent's model references unknown adapter")
		return nil, nil, fmt.Errorf("unknown adapter for memory model")
	}

	canWriteSelf, canWriteGlobal := ac.memoryPerms(ctx, "write")

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

		if canWriteGlobal && ac.maxGlobalMemoriesToReconcile > 0 {
			nearby, err = ac.store.FindNearbyMemories(ctx, mem.Embedding, mem.ModelID, database.GlobalMemories(), database.WithMinSimilarity(ac.mem2memProximityThreshold), database.WithLimit(ac.maxGlobalMemoriesToReconcile))
			if err != nil {
				return nil, exchanges, err
			}
		}

		if mem.TargetUserId != nil && ac.maxUserMemoriesToReconcile > 0 {
			userNearby, err := ac.store.FindNearbyMemories(ctx, mem.Embedding, mem.ModelID, database.UserMemories(*mem.TargetUserId), database.WithMinSimilarity(ac.mem2memProximityThreshold), database.WithLimit(ac.maxUserMemoriesToReconcile))
			if err != nil {
				return nil, exchanges, err
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
			return nil, exchanges, err
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
			return nil, exchanges, err
		}

		msg, err := adapter.SendMessage(ctx, req)
		if err != nil {
			return nil, exchanges, err
		}

		exchanges = append(exchanges, []*model.Message{req.Messages[0], msg})

		var rawResult string
		for _, cb := range msg.ContentBlocks {
			if strings.EqualFold(cb.Type, "Text") {
				rawResult = cb.Text
			}
		}

		if len(rawResult) == 0 {
			return nil, exchanges, fmt.Errorf("no returned content from Reconcile agent")
		}

		changes := model.MemoryOperations{}

		err = json.Unmarshal([]byte(rawResult), &changes)
		if err != nil {
			return nil, exchanges, err
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

	return ops, exchanges, nil
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

	// Record the embedding spend off the chat hot path; the chat must not wait
	// on, or fail because of, usage bookkeeping.
	if sourceSessionId != "" {
		go func() {
			recCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second*10)
			defer cancel()

			ac.recordEmbedUsage(recCtx, sourceSessionId, embedModel.Selector(), resp, []string{content})
		}()
	}

	if len(resp.Embeddings) != 1 {
		err := fmt.Errorf("expected 1 embedding but got %d", len(resp.Embeddings))
		return nil, nil, err
	}

	emb := resp.Embeddings[0]
	modelUsed := resp.Model

	if ac.maxUserMemoriesToInclude > 0 {
		user, err = ac.store.FindNearbyMemories(ctx, emb, modelUsed, database.UserMemories(userId), database.WithMinSimilarity(ac.mem2msgProximityThreshold), database.WithLimit(ac.maxUserMemoriesToInclude))
		if err != nil {
			return nil, nil, err
		}
	}

	if canReadGlobal && ac.maxGlobalMemoriesToInclude > 0 {
		global, err = ac.store.FindNearbyMemories(ctx, emb, modelUsed, database.GlobalMemories(), database.WithMinSimilarity(ac.mem2msgProximityThreshold), database.WithLimit(ac.maxGlobalMemoriesToInclude))
		if err != nil {
			return nil, nil, err
		}
	}

	return user, global, nil
}
