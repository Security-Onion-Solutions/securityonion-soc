// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/google/uuid"
)

// turnBudget is shared by a session and every sub-agent it delegates to.
type turnBudget struct {
	used, max int
}

func (b *turnBudget) exhausted() bool { return b.used >= b.max }

// RunAgentSession drives one agent session to completion with no client attached:
// tools are executed as they are requested and delegated sub-agents run the same way.
// The result carries the session id on every path once it is known, error included,
// because a failed session still has to be recorded against the work it was doing.
func (ac *AssistantCoordinator) RunAgentSession(ctx context.Context, req *model.AgentSessionRequest) (result *model.AgentSessionResult, err error) {
	if req == nil {
		return nil, ErrAgentSessionRequestRequired
	}

	sessionId := uuid.NewString()
	result = &model.AgentSessionResult{SessionId: sessionId}

	budget := &turnBudget{max: req.MaxTurns}
	if budget.max <= 0 {
		budget.max = max(ac.agentSessionMaxTurns, 1)
	}

	requestId := automationRequestId(sessionId)
	logger := log.FromContext(ctx).WithFields(log.Fields{
		"requestId": requestId,
		"sessionId": sessionId,
		"agent":     req.Agent,
		"headless":  true,
	})

	defer func() {
		result.Turns = budget.used

		if r := recover(); r != nil {
			logger.WithFields(log.Fields{"panic": r, "stack": string(debug.Stack())}).Error("recovered panic in headless agent session")
			err = fmt.Errorf("agent session panicked: %v", r)
		}
	}()

	if err := ac.ValidateAgentSessionRequest(req); err != nil {
		return result, err
	}

	// Stores and tools take the owner from the requestor id; this is what makes the
	// session theirs and authorizes the agent as them.
	ownerCtx := context.WithValue(ctx, web.ContextKeyRequestorId, req.OwnerId)
	ownerCtx = context.WithValue(ownerCtx, web.ContextKeyRequestId, requestId)
	ownerCtx = log.NewContext(ownerCtx, logger)

	sess := &model.AssistantSession{
		SessionId: sessionId,
		Title:     req.Objective,
		Model:     req.Agent,
		Tags:      automationTags(req.Tags),
	}

	result.FinalText, result.Truncated, err = ac.driveAgentSession(ownerCtx, sess, sessionId, req.Objective, budget)

	return result, err
}

// ValidateAgentSessionRequest reports why RunAgentSession would refuse req, so a
// caller can check before recording the session anywhere.
func (ac *AssistantCoordinator) ValidateAgentSessionRequest(req *model.AgentSessionRequest) error {
	if req == nil {
		return ErrAgentSessionRequestRequired
	}

	if strings.TrimSpace(req.Objective) == "" {
		return ErrAgentSessionObjectiveRequired
	}

	if req.OwnerId == "" {
		return ErrAgentSessionOwnerRequired
	}

	if !ac.isAgentic {
		return ErrInvalidAgent
	}

	_, _, err := ac.resolveAgent(req.Agent)

	return err
}

// driveAgentSession creates sess, seeds the objective and runs its turns. The root
// and every delegated child come through here.
func (ac *AssistantCoordinator) driveAgentSession(ctx context.Context, sess *model.AssistantSession, rootSessionId, objective string, budget *turnBudget) (finalText string, truncated bool, err error) {
	logger := log.FromContext(ctx)

	if !ac.sessionLocks.tryLock(sess.SessionId) {
		return "", false, ErrAgentSessionBusy
	}
	defer ac.sessionLocks.unlock(sess.SessionId)

	ac.setAgentPhase(sess.SessionId, rootSessionId, sess.Model, model.AgentPhaseWaitingLLM)
	defer ac.clearAgentPhase(sess.SessionId)

	if err := ac.srv.Assistantstore.CreateSession(ctx, sess); err != nil {
		logger.WithError(err).Error("unable to create headless session")
		return "", false, causeOr(ctx, err)
	}

	userMsg := newUserMessage(objective)
	if err := ac.srv.Assistantstore.SaveChat(ctx, userMsg.PrepareForStorage(sess.SessionId, nil, sess.Model)); err != nil {
		logger.WithError(err).Error("unable to save headless objective message")
		return "", false, causeOr(ctx, err)
	}

	return ac.runAgentTurns(ctx, sess, rootSessionId, []*model.Message{userMsg}, budget)
}

// runAgentTurns loops model turns and tool executions until the agent ends its turn
// or the budget trips.
func (ac *AssistantCoordinator) runAgentTurns(ctx context.Context, sess *model.AssistantSession, rootSessionId string, history []*model.Message, budget *turnBudget) (finalText string, truncated bool, err error) {
	spent := 0

	for {
		if ctx.Err() != nil {
			return "", false, context.Cause(ctx)
		}

		if budget.exhausted() {
			return "", true, nil
		}

		var opts []model.ChatOpt
		if sess.ParentSessionId != "" && ac.getMaxSubSessionTokens() > 0 {
			remaining := ac.getMaxSubSessionTokens() - spent
			if remaining <= 0 {
				notice, err := ac.haltSubSessionSync(ctx, sess.SessionId, sess.Model, nil)
				if err != nil {
					return "", false, causeOr(ctx, err)
				}

				return messageText(notice[0]), false, nil
			}

			opts = append(opts, model.WithMaxTokens(remaining))
		}

		msg, sent, err := ac.streamAgentTurn(ctx, sess, rootSessionId, history, opts)
		if sent {
			budget.used++
		}
		if err != nil {
			return "", false, err
		}

		history = append(history, msg)
		if msg.Usage != nil {
			spent += msg.Usage.OutputTokens
		}

		if !messageHasToolUse(msg) {
			return messageText(msg), false, nil
		}

		// The tools the last permitted turn asked for are never run.
		if budget.exhausted() {
			return "", true, nil
		}

		for _, cb := range dedupeToolUses(msg.ContentBlocks) {
			if cb.Type != "tool_use" {
				continue
			}

			result, err := ac.runAgentTool(ctx, sess, rootSessionId, cb, budget)
			if err != nil {
				return "", false, err
			}

			history = append(history, result)
		}
	}
}

// streamAgentTurn runs one model turn, storing and broadcasting the partial as it
// streams. sent reports whether the model was reached, so a turn that failed to start
// costs no budget.
func (ac *AssistantCoordinator) streamAgentTurn(ctx context.Context, sess *model.AssistantSession, rootSessionId string, history []*model.Message, opts []model.ChatOpt) (msg *model.Message, sent bool, err error) {
	logger := log.FromContext(ctx)

	turnCtx, cancelTurn := context.WithCancelCause(ctx)
	defer cancelTurn(nil)

	touch := func() {}
	if idle := ac.agentStreamIdleTimeout; idle > 0 {
		timer := time.AfterFunc(idle, func() { cancelTurn(ErrAgentTurnStalled) })
		defer timer.Stop()

		touch = func() { timer.Reset(idle) }
	}

	ac.setAgentPhase(sess.SessionId, rootSessionId, sess.Model, model.AgentPhaseWaitingLLM)

	res, aux, err := ac.SendStream(turnCtx, sess.Model, history, opts...)
	if err != nil {
		return nil, false, causeOr(turnCtx, err)
	}
	defer res.Body.Close()

	turnId := uuid.NewString()
	// One stored record across the turn's flushes keeps its CreateTime and tags.
	stored := &model.StoredMessage{SessionId: sess.SessionId, Model: sess.Model}
	seq := 0

	publisher := newAgentStreamPublisher(ac.broadcastAgentStream)
	defer publisher.close()

	var raw []byte
	buf := make([]byte, 4096)
	lastFlush := time.Now()

	// UnstreamResponse is stateless, so each flush re-parses the whole buffer.
	flush := func() error {
		end := lastEventEnd(raw)
		if end < 0 {
			return nil
		}

		// An SDK adapter reports a cancelled stream as an SSE error event, not a read error.
		parsed, err := server.UnstreamResponse(ctx, string(raw[:end]), aux)
		if err != nil {
			return causeOr(turnCtx, err)
		}

		snap, ok := partialSnapshot(parsed)
		if !ok {
			return nil
		}

		snap.Id = turnId
		stored.Message = snap

		if err := ac.srv.Assistantstore.SavePartialChat(ctx, stored); err != nil {
			logger.WithError(err).Warn("unable to save partial headless turn")
			return nil
		}

		seq++
		publisher.publish(model.AgentStreamEvent{SessionId: sess.SessionId, MessageId: turnId, Seq: seq, Message: snap})

		return nil
	}

	for {
		n, readErr := res.Body.Read(buf)
		if n > 0 {
			raw = append(raw, buf[:n]...)
			touch()

			if time.Since(lastFlush) >= ac.agentStreamFlushInterval {
				if err := flush(); err != nil {
					return nil, true, err
				}

				lastFlush = time.Now()
			}
		}

		if readErr == io.EOF {
			break
		}

		if readErr != nil {
			return nil, true, causeOr(turnCtx, readErr)
		}
	}

	// An adapter may end its stream cleanly on cancellation.
	if turnCtx.Err() != nil {
		return nil, true, context.Cause(turnCtx)
	}

	msg, err = server.UnstreamResponse(ctx, string(raw), aux)
	if err != nil {
		return nil, true, causeOr(turnCtx, err)
	}

	if msg == nil {
		return nil, true, ErrAgentTurnEmpty
	}

	msg.Id = turnId
	stored.Message = msg

	if err := ac.srv.Assistantstore.FinishPartialChat(ctx, stored); err != nil {
		logger.WithError(err).Error("unable to save headless turn")
		return nil, true, causeOr(ctx, err)
	}

	publisher.publish(model.AgentStreamEvent{SessionId: sess.SessionId, MessageId: turnId, Seq: seq + 1, Message: msg, Done: true})

	return msg, true, nil
}

// partialSnapshot makes a mid-stream message storable: an open text block still holds
// its text in Content, and an open tool_use holds half of its input JSON. ok is false
// while nothing storable has arrived.
func partialSnapshot(msg *model.Message) (*model.Message, bool) {
	if msg == nil {
		return nil, false
	}

	snap := *msg
	snap.ContentBlocks = make([]model.ContentBlock, 0, len(msg.ContentBlocks))
	ok := false

	for _, cb := range msg.ContentBlocks {
		if cb.Type == "" && cb.ToolResult == nil {
			cb.Type = "text"
		}

		if text, isText := cb.Content.(string); isText && cb.Text == "" {
			cb.Text = text
		}
		cb.Content = nil

		if cb.Type == "tool_use" && len(cb.Input) > 0 && !json.Valid(cb.Input) {
			cb.Input = nil
		}

		ok = ok || (cb.Type == "text" && cb.Text != "") || cb.Type == "tool_use" || cb.ToolResult != nil

		snap.ContentBlocks = append(snap.ContentBlocks, cb)
	}

	return &snap, ok
}

// lastEventEnd returns the length of raw through its last complete SSE event, or
// -1 when none has arrived.
func lastEventEnd(raw []byte) int {
	end := -1
	for _, delim := range [][]byte{[]byte("\n\n"), []byte("\r\n\r\n")} {
		if i := bytes.LastIndex(raw, delim); i >= 0 {
			end = max(end, i+len(delim))
		}
	}

	return end
}

// runAgentTool executes one tool_use and returns its stored tool_result message. A
// tool failure is the model's to react to, not the session's; a delegation runs the
// sub-agent to completion first.
func (ac *AssistantCoordinator) runAgentTool(ctx context.Context, sess *model.AssistantSession, rootSessionId string, cb model.ContentBlock, budget *turnBudget) (*model.Message, error) {
	if ctx.Err() != nil {
		return nil, context.Cause(ctx)
	}

	ac.setAgentPhase(sess.SessionId, rootSessionId, sess.Model, model.AgentPhaseInvokingToolPrefix+cb.Name)

	params := cb.Input
	if len(bytes.TrimSpace(params)) == 0 {
		params = json.RawMessage("{}")
	}

	toolReq := &model.ToolRequest{SessionId: sess.SessionId, ToolUseId: cb.Id, Params: params, Model: sess.Model}

	// The tool gets its own idle window; the next model turn starts a fresh one.
	toolCtx, cancelTool := ac.agentToolContext(ctx)
	resp, toolErr := ac.ExecuteTool(toolCtx, cb.Name, toolReq)
	stopped := toolCtx.Err() != nil
	cancelTool()

	var result *model.Message
	switch {
	case toolErr != nil:
		if stopped {
			return nil, context.Cause(toolCtx)
		}
		result = buildToolResultMessage(cb.Id, nil, toolErr)
	case resp == nil:
		result = buildToolResultMessage(cb.Id, nil, errors.New("tool returned no result"))
	default:
		kickoff, isDelegation := delegationKickoff(resp)
		if !isDelegation {
			result = buildToolResultMessage(cb.Id, resp, nil)
			break
		}

		var err error
		result, err = ac.runAgentDelegation(ctx, sess, rootSessionId, toolReq, kickoff, budget)
		if err != nil {
			return nil, err
		}
	}

	// The tool has already run, so its result is recorded even if the run was
	// cancelled meanwhile, unless the whole engine is stopping.
	if shuttingDown(ctx) {
		return nil, context.Cause(ctx)
	}

	saveCtx, cancel := web.DetachContext(ctx, DETACHED_WRITE_TIMEOUT)
	defer cancel()
	if err := ac.srv.Assistantstore.SaveChat(saveCtx, result.PrepareForStorage(sess.SessionId, []string{"tool_result"}, sess.Model)); err != nil {
		log.FromContext(ctx).WithError(err).Error("unable to save headless tool result")
		return nil, err
	}

	return result, nil
}

// agentToolContext bounds one tool execution by the same idle timeout as a model
// turn; 0 leaves it unbounded.
func (ac *AssistantCoordinator) agentToolContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ac.agentStreamIdleTimeout <= 0 {
		return context.WithCancel(ctx)
	}

	return context.WithTimeoutCause(ctx, ac.agentStreamIdleTimeout, ErrAgentTurnStalled)
}

// runAgentDelegation runs the sub-agent headlessly on the shared budget and folds its
// answer into the parent's tool_result. A child that fails resolves the tool_use with
// the error so the parent continues, unless the whole run is being cancelled.
func (ac *AssistantCoordinator) runAgentDelegation(ctx context.Context, sess *model.AssistantSession, rootSessionId string, toolReq *model.ToolRequest, kickoff model.DelegationKickoff, budget *turnBudget) (*model.Message, error) {
	if refusal := ac.delegationDepthRefusalFor(ctx, sess, toolReq); refusal != nil {
		return refusal, nil
	}

	child := newDelegationSessionFor(sess, toolReq, kickoff)
	child.Tags = automationTags(sess.Tags)

	childCtx := log.NewContext(ctx, log.FromContext(ctx).WithFields(log.Fields{
		"sessionId":       child.SessionId,
		"parentSessionId": sess.SessionId,
		"agent":           child.Model,
	}))

	text, _, err := ac.driveAgentSession(childCtx, child, rootSessionId, kickoff.Objective, budget)
	if err != nil {
		if ctx.Err() != nil {
			return nil, context.Cause(ctx)
		}

		return buildToolResultMessage(toolReq.ToolUseId, nil, fmt.Errorf("the delegated sub-agent could not complete: %w", err)), nil
	}

	return buildDelegationResultMessage(toolReq.ToolUseId, text), nil
}

// automationRequestId stands in for the web request id a headless run never has.
func automationRequestId(sessionId string) string {
	return "automation-" + sessionId
}

func automationTags(extra []string) []string {
	tags := slices.Clone(model.AutomationSessionTags)
	for _, tag := range extra {
		if tag != "" && !slices.Contains(tags, tag) {
			tags = append(tags, tag)
		}
	}

	return tags
}

// causeOr prefers the cancellation cause, so a cancelled run reports why it stopped
// rather than whatever the interrupted call happened to return.
func causeOr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}

	return err
}

// agentStreamPublisher broadcasts a turn's events off the read loop. Only the newest
// event waits, so a slow websocket viewer costs the turn nothing and the last event
// published is always the last one sent.
type agentStreamPublisher struct {
	events chan model.AgentStreamEvent
	done   chan struct{}
}

func newAgentStreamPublisher(broadcast func(model.AgentStreamEvent)) *agentStreamPublisher {
	p := &agentStreamPublisher{events: make(chan model.AgentStreamEvent, 1), done: make(chan struct{})}

	go func() {
		defer close(p.done)
		for event := range p.events {
			broadcast(event)
		}
	}()

	return p
}

// publish never blocks: with one producer, a full slot is drained and refilled.
func (p *agentStreamPublisher) publish(event model.AgentStreamEvent) {
	event.Message = withoutThoughtSignatures(event.Message)

	// attempt to write to the channel, skip writing if the channel is full
	select {
	case p.events <- event:
		return
	default:
	}

	// If the channel was full, attempt to read from the channel to drop its contents.
	// Skip if the channel has been emptied in the meantime.
	select {
	case <-p.events:
	default:
	}

	// replace the out of date event with the latest event
	p.events <- event
}

// close lets the goroutine finish whatever is queued; nothing waits on it.
func (p *agentStreamPublisher) close() {
	close(p.events)
}

func (ac *AssistantCoordinator) broadcastAgentStream(event model.AgentStreamEvent) {
	if ac.srv == nil || ac.srv.Host == nil {
		return
	}

	ac.srv.Host.Broadcast(AgentStreamKind, "assistant", event)
}

// withoutThoughtSignatures copies msg with provider signatures dropped, as the
// history endpoint serves it. The copy is taken before the event leaves the turn's
// goroutine, so the broadcast never reads a message the run is still using.
func withoutThoughtSignatures(msg *model.Message) *model.Message {
	if msg == nil {
		return nil
	}

	out := *msg
	out.ContentBlocks = slices.Clone(msg.ContentBlocks)
	for i := range out.ContentBlocks {
		out.ContentBlocks[i].ThoughtSignature = nil
	}

	return &out
}

func (ac *AssistantCoordinator) setAgentPhase(sessionId, rootSessionId, agent, phase string) {
	ac.agentPhaseMu.Lock()
	defer ac.agentPhaseMu.Unlock()

	if ac.agentPhases == nil {
		ac.agentPhases = map[string]model.AgentSessionPhase{}
	}

	ac.agentPhases[sessionId] = model.AgentSessionPhase{
		SessionId:     sessionId,
		RootSessionId: rootSessionId,
		Agent:         agent,
		Phase:         phase,
		Since:         time.Now(),
	}
}

func (ac *AssistantCoordinator) clearAgentPhase(sessionId string) {
	ac.agentPhaseMu.Lock()
	defer ac.agentPhaseMu.Unlock()

	delete(ac.agentPhases, sessionId)
}

// AgentSessionPhases reports every headless session currently running.
func (ac *AssistantCoordinator) AgentSessionPhases() []model.AgentSessionPhase {
	ac.agentPhaseMu.Lock()
	defer ac.agentPhaseMu.Unlock()

	phases := make([]model.AgentSessionPhase, 0, len(ac.agentPhases))
	for _, phase := range ac.agentPhases {
		phases = append(phases, phase)
	}

	slices.SortFunc(phases, func(a, b model.AgentSessionPhase) int { return strings.Compare(a.SessionId, b.SessionId) })

	return phases
}
