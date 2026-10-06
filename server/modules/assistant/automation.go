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
	"maps"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/security-onion-solutions/securityonion-soc/execpool"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/assistant/database"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/google/uuid"
)

const (
	// A JSON array of every stored automation.
	ConfigSettingAutomations = "soc.config.server.modules.assistant.automations"

	// A label for one row in a list, so it is capped well below what the setting could
	// hold.
	MaxAutomationDisplayNameLength = 100

	// Fixed so the stored copy, its runs and its work items key on the same id in every build.
	BuiltinAlertTriageAutomationId = "a1d3f5b7-9c2e-4e68-8b4a-6f0c2d9e7b13"
)

// Wrap ErrInvalidAutomationParams with %w to name the offending field: respondConfigWrite
// matches on the message substring, so the wrapped form still maps to the right status.
var (
	ErrAutomationNotFound      = errors.New("ERROR_AUTOMATION_NOT_FOUND")
	ErrAutomationKindNotFound  = errors.New("ERROR_AUTOMATION_KIND_NOT_FOUND")
	ErrInvalidAutomationParams = errors.New("ERROR_AUTOMATION_PARAMS_INVALID")
	ErrConfigstoreUnavailable  = errors.New("ERROR_CONFIGSTORE_UNAVAILABLE")

	// A system automation can be disabled, never removed.
	ErrSystemAutomationUndeletable = errors.New("ERROR_SYSTEM_AUTOMATION_UNDELETABLE")

	// The cancel cause a redefined automation gives its run, so a run that unwinds can tell
	// this from a shutdown, and the reason recorded on the work it was holding.
	ErrAutomationParamsChanged = errors.New("ERROR_AUTOMATION_PARAMS_CHANGED")

	// The reason recorded on work that outlived the automation it was queued for.
	ErrAutomationDeleted = errors.New("ERROR_AUTOMATION_DELETED")

	// The reason recorded on work whose run stopped without settling it; also what reconcile
	// writes at startup.
	ErrAutomationWorkItemInterrupted = errors.New("ERROR_AUTOMATION_WORK_ITEM_INTERRUPTED")
)

type AutomationKind interface {
	GetName() string
	GetDisplayName() string
	GetDescription() string
	GetParamSchema() model.JSONSchema
	// ValidateParams inspects the raw params without modifying them; kinds apply their
	// defaults when they unmarshal inside Execute.
	ValidateParams(params json.RawMessage) error
	Execute(ctx context.Context, run *AutomationRun) error
}

// Written only from package init(), like knownTools, so it needs no lock. Lookups go
// through AssistantCoordinator.AutomationKindLibrary so a test can substitute a kind.
var knownAutomationKinds = map[string]AutomationKind{}

type AutomationRun struct {
	Srv  *server.Server
	Task *model.Automation
	// Unique per execution and stamped on the sessions it creates. Not the scheduler's
	// dedupe key, which is the automation id.
	RunId string

	// Never nil: a run is not opened at all without Postgres, so kinds do not check.
	Store AutomationStore

	// Where a kind submits its work items. The run itself never goes through it.
	Pool *execpool.Pool

	// Alert triage never reaches back before this.
	AlertTriageEpoch time.Time

	// Every unfinished item for this task, oldest first. A kind drains this rather than
	// rescanning, so resumption arrives as data rather than a second method.
	OpenItems []*model.AutomationWorkItem
}

// RunAgentSession runs one headless session for a work item. The session is recorded on the
// item before it starts, so the item leads to the transcript while it runs and after it fails.
func (run *AutomationRun) RunAgentSession(ctx context.Context, itemId string, req *model.AgentSessionRequest) (*model.AgentSessionResult, error) {
	if req == nil {
		return nil, ErrAgentSessionRequestRequired
	}

	if err := run.Srv.AssistantManager.ValidateAgentSessionRequest(req); err != nil {
		return nil, err
	}

	if ctx.Err() != nil {
		return nil, context.Cause(ctx)
	}

	started := *req
	if started.SessionId == "" {
		started.SessionId = uuid.NewString()
	}

	if err := run.Store.EnsureAutomationWorkItemSession(ctx, itemId, started.SessionId); err != nil {
		return nil, causeOr(ctx, err)
	}

	return run.Srv.AssistantManager.RunAgentSession(ctx, &started)
}

// automationWriteContext detaches from a params-change cancel, so a finished session is still
// recorded, but never from a shutdown.
func automationWriteContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if !errors.Is(context.Cause(ctx), ErrAutomationParamsChanged) {
		return ctx, func() {}
	}

	return web.DetachContext(ctx, DETACHED_WRITE_TIMEOUT)
}

// WorkItemFunc is the body of one pool job. Its context carries the run's cancellation and a
// logger naming the item.
type WorkItemFunc func(ctx context.Context, item *model.AutomationWorkItem) error

// Submit queues work for an item the caller already holds, keyed by the agent running it and
// deduped by the item's id. A refused submission requeues the item so it is not left claimed
// with nothing running it, except a duplicate: the job that holds the item is still running it.
// At shutdown nothing is written; reconcile at the next start requeues what was claimed.
func (run *AutomationRun) Submit(ctx context.Context, agent string, item *model.AutomationWorkItem, work WorkItemFunc) (*execpool.Handle, error) {
	jobCtx := log.NewContext(ctx, log.FromContext(ctx).WithFields(log.Fields{
		"workItemId": item.Id,
		"groupKey":   item.GroupKey,
	}))

	handle, err := run.Pool.Submit(execpool.Job{
		Key:       agent,
		DedupeKey: item.Id,
		// The run's context, not the pool's: a params change cancels the run alone.
		Run: func(context.Context) error {
			// The pool outlives the scheduler, so work still queued at shutdown must not start.
			if shuttingDown(jobCtx) {
				return context.Cause(jobCtx)
			}

			return work(jobCtx, item)
		},
	})
	if errors.Is(err, execpool.ErrDuplicate) {
		return nil, err
	}

	if err != nil {
		if shuttingDown(ctx) {
			return nil, err
		}

		if requeueErr := run.Store.RequeueAutomationWorkItem(ctx, item.Id, err.Error()); requeueErr != nil {
			err = errors.Join(err, requeueErr)
		}

		return nil, err
	}

	return handle, nil
}

// ClaimAndSubmit claims the oldest pending item this run has not failed and that has fewer
// than maxFailures failed runs, and submits it. Nil item means nothing was claimable.
func (run *AutomationRun) ClaimAndSubmit(ctx context.Context, agent string, maxFailures int, work WorkItemFunc) (*model.AutomationWorkItem, *execpool.Handle, error) {
	item, err := run.Store.ClaimNextAutomationWorkItem(ctx, run.Task.Id, run.RunId, maxFailures)
	if err != nil || item == nil {
		return nil, nil, err
	}

	handle, err := run.Submit(ctx, agent, item, work)

	return item, handle, err
}

// Await returns once every job has finished, with their errors joined. Jobs see the run's
// cancellation, so a cancelled run drains rather than being abandoned mid-transition.
func (run *AutomationRun) Await(handles []*execpool.Handle) error {
	var errs []error

	for _, handle := range handles {
		<-handle.Done()

		if err := handle.Err(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// recoverOrphanedWorkItems returns running items no job in this process holds to the queue,
// recording the run that held them as having failed them, the same as reconcile does at
// startup. Without it a job that died before its transition leaves its group skipped until a
// restart. Items a sweep already ended are dropped; ones the store could not reset stay as
// listed for the next run.
func (run *AutomationRun) recoverOrphanedWorkItems(ctx context.Context, items []*model.AutomationWorkItem) []*model.AutomationWorkItem {
	recovered := make([]*model.AutomationWorkItem, 0, len(items))

	for _, item := range items {
		if item.State != model.AutomationWorkItemRunning || run.Pool.Holds(item.Id) {
			recovered = append(recovered, item)

			continue
		}

		logger := log.FromContext(ctx).WithFields(log.Fields{
			"workItemId": item.Id,
			"heldByRun":  item.RunId,
		})

		reset, err := run.Store.FailAutomationWorkItemRun(ctx, item.Id, ErrAutomationWorkItemInterrupted.Error())
		if errors.Is(err, database.ErrAutomationWorkItemNotFound) {
			continue
		}

		if err != nil {
			logger.WithError(err).Warn("unable to return an orphaned work item to the queue; leaving it for the next run")
			recovered = append(recovered, item)

			continue
		}

		logger.Info("returned a work item left running with no job to the queue")
		recovered = append(recovered, reset)
	}

	return recovered
}

// setupBuiltinAutomations defines the automations that ship with the product.
func (ac *AssistantCoordinator) setupBuiltinAutomations() {
	ac.builtinAutomations = map[string]*model.Automation{
		BuiltinAlertTriageAutomationId: {
			DisplayName:     "Alert Triage",
			AutomationKind:  alertTriageKindName,
			Agent:           "Investigator",
			IntervalSeconds: int(ac.getAutomationTickInterval().Seconds()),
			Params:          json.RawMessage(`{"groupBy":["source.ip","rule.uuid","destination.ip"]}`),
		},
	}
}

func (ac *AssistantCoordinator) isBuiltinAutomation(id string) bool {
	_, ok := ac.builtinAutomations[id]

	return ok
}

// overlayBuiltinAutomation is the builtin with stored's Auditable, enabled, agent and interval; a
// nil stored is the builtin as shipped.
func (ac *AssistantCoordinator) overlayBuiltinAutomation(id string, stored *model.Automation) *model.Automation {
	if ac.builtinAutomations[id] == nil {
		return nil
	}

	automation := *ac.builtinAutomations[id]
	automation.Params = bytes.Clone(automation.Params)

	if stored != nil {
		automation.Auditable = stored.Auditable
		automation.Enabled = stored.Enabled

		// A blank agent is the shipped one.
		if strings.TrimSpace(stored.Agent) != "" {
			automation.Agent = stored.Agent
		}

		// An absent interval is the shipped one; a negative one is left for validation to refuse.
		if stored.IntervalSeconds != 0 {
			automation.IntervalSeconds = stored.IntervalSeconds
		}
	}

	automation.Id = id
	automation.Kind = "automation"
	automation.IsSystem = true

	return &automation
}

func (ac *AssistantCoordinator) lookupAutomationKind(name string) (AutomationKind, error) {
	kind, ok := ac.AutomationKindLibrary[name]
	if !ok {
		return nil, ErrAutomationKindNotFound
	}

	return kind, nil
}

// isAutomationId reports whether id can address an automation.
func isAutomationId(id string) bool {
	_, err := uuid.Parse(id)

	return err == nil
}

// unmarshalAutomation decodes one element of the stored list.
func unmarshalAutomation(raw json.RawMessage) (*model.Automation, error) {
	automation := &model.Automation{}
	if err := json.Unmarshal(raw, automation); err != nil {
		return nil, fmt.Errorf("automation is not valid JSON: %w", err)
	}

	// A hand-edited entry can name anything; only a UUID survives the store's uuid columns,
	// so reject it here rather than at the first query.
	if !isAutomationId(automation.Id) {
		return nil, fmt.Errorf("automation id %q is not a UUID", automation.Id)
	}

	automation.Kind = "automation"
	// Only the overlay may claim this.
	automation.IsSystem = false

	return automation, nil
}

// readStoredAutomations returns the stored list with each element as written, so a rewrite
// carries the ones it cannot read through untouched.
func (ac *AssistantCoordinator) readStoredAutomations(ctx context.Context) ([]json.RawMessage, error) {
	setting, err := ac.srv.Configstore.LookupSetting(ctx, ConfigSettingAutomations)
	if err != nil {
		return nil, err
	}

	if setting == nil || strings.TrimSpace(setting.Value) == "" {
		return []json.RawMessage{}, nil
	}

	stored := []json.RawMessage{}
	if err := json.Unmarshal([]byte(setting.Value), &stored); err != nil {
		return nil, fmt.Errorf("setting %s is not a JSON array: %w", ConfigSettingAutomations, err)
	}

	return stored, nil
}

func (ac *AssistantCoordinator) writeStoredAutomations(ctx context.Context, stored []json.RawMessage) error {
	encoded, err := json.Marshal(stored)
	if err != nil {
		return err
	}

	return ac.srv.Configstore.UpdateSetting(ctx, &model.Setting{
		Id:    ConfigSettingAutomations,
		Value: string(encoded),
	}, false)
}

// findStoredAutomation returns the first readable element with this id, or nil.
func findStoredAutomation(stored []json.RawMessage, id string) *model.Automation {
	for _, raw := range stored {
		automation, err := unmarshalAutomation(raw)
		if err == nil && automation.Id == id {
			return automation
		}
	}

	return nil
}

// replaceStoredAutomation puts replacement where the first element with this id was, or at
// the end, dropping any repeats. A nil replacement removes the id.
func replaceStoredAutomation(stored []json.RawMessage, id string, replacement json.RawMessage) []json.RawMessage {
	replaced := make([]json.RawMessage, 0, len(stored)+1)

	for _, raw := range stored {
		automation, err := unmarshalAutomation(raw)
		if err != nil || automation.Id != id {
			replaced = append(replaced, raw)

			continue
		}

		if replacement != nil {
			replaced = append(replaced, replacement)
			replacement = nil
		}
	}

	if replacement != nil {
		replaced = append(replaced, replacement)
	}

	return replaced
}

func (ac *AssistantCoordinator) ListAutomations(ctx context.Context) ([]*model.Automation, error) {
	if ac.srv == nil || ac.srv.Configstore == nil {
		return nil, ErrConfigstoreUnavailable
	}

	if err := ac.srv.CheckAuthorized(ctx, "read", "automations"); err != nil {
		return nil, err
	}

	automations, _, err := ac.scanAutomations(ctx)

	return automations, err
}

// scanAutomations returns every readable automation and how many stored entries could not be
// read, so a caller that acts on an automation's absence can refuse to act on partial knowledge.
func (ac *AssistantCoordinator) scanAutomations(ctx context.Context) ([]*model.Automation, int, error) {
	if ac.srv == nil || ac.srv.Configstore == nil {
		return nil, 0, ErrConfigstoreUnavailable
	}

	stored, err := ac.readStoredAutomations(ctx)
	if err != nil {
		return nil, 0, err
	}

	automations := []*model.Automation{}
	unreadable := 0
	seen := map[string]bool{}

	for index, raw := range stored {
		automation, err := unmarshalAutomation(raw)
		if err == nil && seen[automation.Id] {
			err = fmt.Errorf("automation %s is stored more than once", automation.Id)
		}

		if err != nil {
			// One malformed automation must not hide the rest.
			log.FromContext(ctx).WithError(err).WithField("index", index).
				Warn("skipping unreadable automation")

			unreadable++

			continue
		}

		seen[automation.Id] = true

		if ac.isBuiltinAutomation(automation.Id) {
			automation = ac.overlayBuiltinAutomation(automation.Id, automation)
		}

		automations = append(automations, automation)
	}

	// Builtins can be disabled but never removed, so one without a stored copy is listed as shipped.
	for _, id := range slices.Sorted(maps.Keys(ac.builtinAutomations)) {
		if !seen[id] {
			automations = append(automations, ac.overlayBuiltinAutomation(id, nil))
		}
	}

	return automations, unreadable, nil
}

func (ac *AssistantCoordinator) GetAutomation(ctx context.Context, id string) (*model.Automation, error) {
	if ac.srv == nil || ac.srv.Configstore == nil {
		return nil, ErrConfigstoreUnavailable
	}

	if err := ac.srv.CheckAuthorized(ctx, "read", "automations"); err != nil {
		return nil, err
	}

	stored, err := ac.getStoredAutomation(ctx, id)

	if !ac.isBuiltinAutomation(id) {
		return stored, err
	}

	if errors.Is(err, ErrAutomationNotFound) {
		return ac.overlayBuiltinAutomation(id, nil), nil
	}

	if err != nil {
		return nil, err
	}

	return ac.overlayBuiltinAutomation(id, stored), nil
}

// getStoredAutomation reads the automation as written, without the builtin overlay.
func (ac *AssistantCoordinator) getStoredAutomation(ctx context.Context, id string) (*model.Automation, error) {
	if ac.srv == nil || ac.srv.Configstore == nil {
		return nil, ErrConfigstoreUnavailable
	}

	if !isAutomationId(id) {
		return nil, ErrAutomationNotFound
	}

	stored, err := ac.readStoredAutomations(ctx)
	if err != nil {
		return nil, err
	}

	automation := findStoredAutomation(stored, id)
	if automation == nil {
		return nil, ErrAutomationNotFound
	}

	return automation, nil
}

func (ac *AssistantCoordinator) SaveAutomation(ctx context.Context, automation *model.Automation) error {
	if ac.srv == nil || ac.srv.Configstore == nil {
		return ErrConfigstoreUnavailable
	}

	if automation == nil {
		return ErrInvalidAutomationParams
	}

	if err := ac.srv.CheckAuthorized(ctx, "write", "config"); err != nil {
		return err
	}

	builtin := ac.isBuiltinAutomation(automation.Id)

	if automation.IsSystem != builtin {
		return fmt.Errorf("%w: isSystem does not match this automation", ErrInvalidAutomationParams)
	}

	// Into the caller's value: the handler answers with what it passed in. A rejected save
	// leaves the overlay behind, which the handler discards.
	if builtin {
		*automation = *ac.overlayBuiltinAutomation(automation.Id, automation)
	}

	if err := validateAutomation(automation); err != nil {
		return err
	}

	// A disabled automation may keep an agent that no longer resolves; enabling it is what needs
	// one that does.
	if automation.Enabled {
		if _, _, err := ac.resolveAgent(automation.Agent); err != nil {
			return fmt.Errorf("%w: agent %q is not available", ErrInvalidAutomationParams, automation.Agent)
		}
	}

	kind, err := ac.lookupAutomationKind(automation.AutomationKind)
	if err != nil {
		return err
	}

	if err := kind.ValidateParams(automation.Params); err != nil {
		return err
	}

	ac.configWriteMu.Lock()
	defer ac.configWriteMu.Unlock()

	stored, err := ac.readStoredAutomations(ctx)
	if err != nil {
		return err
	}

	existing, err := ac.stampAutomation(ctx, automation, stored)
	if err != nil {
		return err
	}

	encoded, err := json.Marshal(automation)
	if err != nil {
		return err
	}

	if err := ac.writeStoredAutomations(ctx, replaceStoredAutomation(stored, automation.Id, encoded)); err != nil {
		return err
	}

	// The new definition is stored, so the work the old params derived is now stale. Cancel
	// first so the run stops claiming, then finalize what it was holding. A failed sweep
	// leaves that stale work in place.
	// A builtin's params come with the build, so a save never changes what its work was derived from.
	if existing != nil && !builtin && !jsonEqual(existing.Params, automation.Params) {
		ac.interruptAutomationRun(automation.Id)

		if ac.store != nil {
			if err := ac.sweepAutomationWork(ctx, ac.store.FailStaleAutomationWorkItems, automation.Id,
				ErrAutomationParamsChanged,
				"assistant: dropped automation work derived from superseded params"); err != nil {
				return err
			}
		}
	}

	ac.invalidateAutomations()

	return nil
}

// validateAutomation checks what the kind cannot: what an automation is called and how
// often it runs belong to the automation rather than to its params.
func validateAutomation(automation *model.Automation) error {
	name := strings.TrimSpace(automation.DisplayName)

	if name == "" {
		return fmt.Errorf("%w: displayName is required", ErrInvalidAutomationParams)
	}

	// Runes, not bytes: the cap is on what an admin typed, not on its encoding.
	if utf8.RuneCountInString(name) > MaxAutomationDisplayNameLength {
		return fmt.Errorf("%w: displayName must be at most %d characters",
			ErrInvalidAutomationParams, MaxAutomationDisplayNameLength)
	}

	if automation.IntervalSeconds <= 0 {
		return fmt.Errorf("%w: intervalSeconds must be positive", ErrInvalidAutomationParams)
	}

	if strings.TrimSpace(automation.Agent) == "" {
		return fmt.Errorf("%w: agent is required", ErrInvalidAutomationParams)
	}

	return nil
}

// stampAutomation settles the fields an automation does not set for itself: identity, creator
// and timestamps, returning the stored copy it found so the caller can see what changed.
// The caller read stored under configWriteMu, which is what makes that read and the write that
// follows it one edit rather than two. Nothing is written back to automation until every check
// has passed, so a rejected save leaves it as SaveAutomation handed it over.
func (ac *AssistantCoordinator) stampAutomation(ctx context.Context, automation *model.Automation, stored []json.RawMessage) (*model.Automation, error) {
	id := automation.Id
	// The handler puts the path id here, so an absent id is the only thing that means create.
	create := id == ""

	if create {
		id = uuid.NewString()
	} else if !isAutomationId(id) {
		return nil, fmt.Errorf("%w: id must be a UUID", ErrInvalidAutomationParams)
	}

	// The stored copy, not the overlay: only it says whether a builtin was ever saved.
	existing := findStoredAutomation(stored, id)

	// A builtin's first save creates its stored copy under the fixed id.
	if existing == nil && ac.isBuiltinAutomation(id) {
		create = true
	}

	if !create && existing == nil {
		return nil, ErrAutomationNotFound
	}

	now := time.Now()
	createTime := &now
	userId := ""

	if create {
		requestor, ok := ctx.Value(web.ContextKeyRequestorId).(string)
		if !ok {
			return nil, errors.New("context is missing RequestorId")
		}

		userId = requestor
	} else {
		// Existing runs and work items hold payloads only the original kind can read. A
		// builtin's kind is fixed here, so a stored drift heals instead.
		if !ac.isBuiltinAutomation(id) && existing.AutomationKind != automation.AutomationKind {
			return nil, fmt.Errorf("%w: automationKind cannot be changed", ErrInvalidAutomationParams)
		}

		// UserId records who created the automation; an edit does not reassign it.
		createTime = existing.CreateTime
		userId = existing.UserId
	}

	automation.Id = id
	automation.Kind = "automation"
	automation.CreateTime = createTime
	automation.UpdateTime = &now
	automation.UserId = userId

	return existing, nil
}

// registerAutomationRun records a run's cancel so a params change can reach it, returning the
// release the engine defers.
func (ac *AssistantCoordinator) registerAutomationRun(id string, cancel context.CancelCauseFunc) func() {
	ac.automationRunMu.Lock()
	defer ac.automationRunMu.Unlock()

	if ac.automationRuns == nil {
		ac.automationRuns = map[string]context.CancelCauseFunc{}
	}

	ac.automationRuns[id] = cancel

	return func() {
		ac.automationRunMu.Lock()
		defer ac.automationRunMu.Unlock()

		delete(ac.automationRuns, id)
	}
}

// interruptAutomationRun signals the run executing this automation to stop. It does not wait:
// a config write must not block on an LLM turn. The stale work is finalized immediately after,
// so a run still unwinding finds nothing left to claim.
func (ac *AssistantCoordinator) interruptAutomationRun(id string) {
	ac.automationRunMu.Lock()
	defer ac.automationRunMu.Unlock()

	if cancel := ac.automationRuns[id]; cancel != nil {
		cancel(ErrAutomationParamsChanged)
	}
}

type workItemSweep func(ctx context.Context, automationId, cause string) (int, error)

// sweepAutomationWork runs one of the store's sweeps and reports what it dropped.
func (ac *AssistantCoordinator) sweepAutomationWork(ctx context.Context, sweep workItemSweep,
	id string, cause error, message string) error {
	failed, err := sweep(ctx, id, cause.Error())
	if err != nil {
		return err
	}

	if failed > 0 {
		log.FromContext(ctx).WithFields(log.Fields{
			"automationId": id,
			"failedItems":  failed,
		}).Info(message)
	}

	return nil
}

// DeleteAutomation removes an automation, allowing in-flight runs to finish.
func (ac *AssistantCoordinator) DeleteAutomation(ctx context.Context, id string) error {
	if ac.srv == nil || ac.srv.Configstore == nil {
		return ErrConfigstoreUnavailable
	}

	if !isAutomationId(id) {
		return ErrAutomationNotFound
	}

	if err := ac.srv.CheckAuthorized(ctx, "write", "config"); err != nil {
		return err
	}

	if ac.isBuiltinAutomation(id) {
		return ErrSystemAutomationUndeletable
	}

	ac.configWriteMu.Lock()
	defer ac.configWriteMu.Unlock()

	stored, err := ac.readStoredAutomations(ctx)
	if err != nil {
		return err
	}

	if findStoredAutomation(stored, id) == nil {
		return ErrAutomationNotFound
	}

	if err := ac.writeStoredAutomations(ctx, replaceStoredAutomation(stored, id, nil)); err != nil {
		return err
	}

	if ac.store != nil {
		if err := ac.sweepAutomationWork(ctx, ac.store.FailPendingAutomationWorkItems, id,
			ErrAutomationDeleted,
			"assistant: dropped automation work queued for a deleted automation"); err != nil {
			return err
		}
	}

	ac.invalidateAutomations()

	return nil
}

// sweepOrphanedAutomationWork drops the work items left behind by automations that no longer
// exist.
func (ac *AssistantCoordinator) sweepOrphanedAutomationWork(ctx context.Context) {
	if ac.store == nil {
		return
	}

	automations, unreadable, err := ac.scanAutomations(ctx)
	if err != nil {
		log.FromContext(ctx).WithError(err).Warn("unable to list automations; orphaned automation work was not swept")

		return
	}

	// After reconcileAutomationRuns: reconcile resets running items to pending, so sweeping
	// first would let it resurrect them.
	_ = ac.failOrphanedWorkItems(ctx, ac.store.FailOrphanedAutomationWorkItems, automations, unreadable)
}

type orphanSweep func(ctx context.Context, liveIds []string, cause string) (int, error)

// failOrphanedWorkItems drops work whose automation is no longer defined: a delete leaves an
// in-flight run's items behind, and a pillar edit never passes through DeleteAutomation.
func (ac *AssistantCoordinator) failOrphanedWorkItems(ctx context.Context, sweep orphanSweep, live []*model.Automation, unreadable int) error {
	logger := log.FromContext(ctx)

	// An unreadable automation is indistinguishable from a deleted one here.
	if unreadable > 0 {
		logger.WithField("unreadable", unreadable).
			Warn("assistant: skipping orphaned automation work sweep; some automations are unreadable")

		return nil
	}

	liveIds := make([]string, 0, len(live))
	for _, automation := range live {
		liveIds = append(liveIds, automation.Id)
	}

	failed, err := sweep(ctx, liveIds, ErrAutomationDeleted.Error())
	if err != nil {
		logger.WithError(err).Error("assistant: unable to drop orphaned automation work")

		return err
	}

	if failed > 0 {
		logger.WithField("failedItems", failed).
			Info("assistant: dropped automation work left by automations that no longer exist")
	}

	return nil
}

// reconcileAutomationRuns closes out runs a previous process left open and requeues the work
// they had in flight. Called once from Start, before anything can schedule, which is the
// window in which every open run is known to be abandoned. A failure is logged rather than
// returned: an unreachable reconcile must not stop the assistant serving chat.
func (ac *AssistantCoordinator) reconcileAutomationRuns(ctx context.Context) {
	logger := log.FromContext(ctx)

	result, err := ac.store.ReconcileAutomationRuns(ctx)
	if err != nil {
		logger.WithError(err).Error("assistant: automation run reconciliation failed")

		return
	}

	if result.FailedRuns == 0 && result.ResetItems == 0 {
		return
	}

	logger.WithFields(log.Fields{
		"failedRuns": result.FailedRuns,
		"resetItems": result.ResetItems,
	}).Info("assistant: recovered automation runs left open by a previous process")
}
