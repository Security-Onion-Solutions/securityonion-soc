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
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/security-onion-solutions/securityonion-soc/execpool"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/google/uuid"
)

const (
	// One setting per automation, so config history and rollback are per automation.
	ConfigSettingAutomationsPrefix = "soc.config.server.modules.assistant.automations."

	// An annotation anchor that never holds a value; instances duplicate it to inherit
	// its syntax, forced type and description.
	ConfigSettingAutomationTemplate = ConfigSettingAutomationsPrefix + "template"

	// A label for one row in a list, so it is capped well below what the setting could
	// hold.
	MaxAutomationDisplayNameLength = 100
)

// Wrap ErrInvalidAutomationParams with %w to name the offending field: respondConfigWrite
// matches on the message substring, so the wrapped form still maps to the right status.
var (
	ErrAutomationNotFound      = errors.New("ERROR_AUTOMATION_NOT_FOUND")
	ErrAutomationKindNotFound  = errors.New("ERROR_AUTOMATION_KIND_NOT_FOUND")
	ErrInvalidAutomationParams = errors.New("ERROR_AUTOMATION_PARAMS_INVALID")
	ErrConfigstoreUnavailable  = errors.New("ERROR_CONFIGSTORE_UNAVAILABLE")

	// The cancel cause a redefined automation gives its run, so a run that unwinds can tell
	// this from a shutdown, and the reason recorded on the work it was holding.
	ErrAutomationParamsChanged = errors.New("ERROR_AUTOMATION_PARAMS_CHANGED")

	// The reason recorded on work that outlived the automation it was queued for.
	ErrAutomationDeleted = errors.New("ERROR_AUTOMATION_DELETED")
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

// RunAgentSession runs one headless session for a work item and records the session on
// the item, failed runs included, so the item always leads to the transcript.
func (run *AutomationRun) RunAgentSession(ctx context.Context, itemId string, req *model.AgentSessionRequest) (*model.AgentSessionResult, error) {
	if req == nil {
		return nil, ErrAgentSessionRequestRequired
	}

	if req.OwnerId == "" && run.Task != nil {
		req.OwnerId = run.Task.UserId
	}

	if err := run.Srv.AssistantManager.ValidateAgentSessionRequest(req); err != nil {
		return nil, err
	}

	result, runErr := run.Srv.AssistantManager.RunAgentSession(ctx, req)
	if result != nil && result.SessionId != "" && !shuttingDown(ctx) {
		if err := run.Store.EnsureAutomationWorkItemSession(ctx, itemId, result.SessionId); err != nil {
			return result, errors.Join(runErr, err)
		}
	}

	return result, runErr
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
		Run: func(context.Context) error { return work(jobCtx, item) },
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

func (ac *AssistantCoordinator) lookupAutomationKind(name string) (AutomationKind, error) {
	kind, ok := ac.AutomationKindLibrary[name]
	if !ok {
		return nil, ErrAutomationKindNotFound
	}

	return kind, nil
}

func automationSettingId(id string) string {
	return ConfigSettingAutomationsPrefix + id
}

// isAutomationId reports whether id can address an automation.
func isAutomationId(id string) bool {
	_, err := uuid.Parse(id)

	return err == nil
}

// automationIdFromSetting returns the automation id a setting holds, or "" when the setting
// is not an automation. The template is excluded: it is an annotation anchor.
func automationIdFromSetting(settingId string) string {
	if settingId == ConfigSettingAutomationTemplate {
		return ""
	}

	id := strings.TrimPrefix(settingId, ConfigSettingAutomationsPrefix)
	if id == settingId || id == "" || strings.Contains(id, ".") {
		return ""
	}

	return id
}

// unmarshalAutomation decodes one stored automation. The setting id is authoritative for Id:
// it is where the value actually lives, and everything durable keys on it.
func unmarshalAutomation(settingId, value string) (*model.Automation, error) {
	id := automationIdFromSetting(settingId)
	if id == "" {
		return nil, fmt.Errorf("setting %s is not an automation", settingId)
	}

	// A hand-edited pillar entry can name anything; only a UUID survives the store's
	// uuid columns, so reject it here rather than at the first query.
	if !isAutomationId(id) {
		return nil, fmt.Errorf("automation id %s is not a UUID", id)
	}

	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("automation %s has no value", id)
	}

	automation := &model.Automation{}
	if err := json.Unmarshal([]byte(value), automation); err != nil {
		return nil, fmt.Errorf("automation %s is not valid JSON: %w", id, err)
	}

	automation.Id = id
	automation.Kind = "automation"

	return automation, nil
}

func (ac *AssistantCoordinator) ListAutomations(ctx context.Context) ([]*model.Automation, error) {
	automations, _, err := ac.scanAutomations(ctx)

	return automations, err
}

// scanAutomations returns every readable automation and how many settings could not be read,
// so a caller that acts on an automation's absence can refuse to act on partial knowledge.
func (ac *AssistantCoordinator) scanAutomations(ctx context.Context) ([]*model.Automation, int, error) {
	if ac.srv == nil || ac.srv.Configstore == nil {
		return nil, 0, ErrConfigstoreUnavailable
	}

	settings, err := ac.srv.Configstore.GetSettings(ctx, true)
	if err != nil {
		return nil, 0, err
	}

	automations := []*model.Automation{}
	unreadable := 0

	for _, setting := range settings {
		if automationIdFromSetting(setting.Id) == "" {
			continue
		}

		automation, err := unmarshalAutomation(setting.Id, setting.Value)
		if err != nil {
			// One malformed automation must not hide the rest.
			log.FromContext(ctx).WithError(err).WithField("settingId", setting.Id).
				Warn("skipping unreadable automation")

			unreadable++

			continue
		}

		automations = append(automations, automation)
	}

	return automations, unreadable, nil
}

func (ac *AssistantCoordinator) GetAutomation(ctx context.Context, id string) (*model.Automation, error) {
	if ac.srv == nil || ac.srv.Configstore == nil {
		return nil, ErrConfigstoreUnavailable
	}

	if !isAutomationId(id) {
		return nil, ErrAutomationNotFound
	}

	setting, err := ac.srv.Configstore.GetSetting(ctx, automationSettingId(id))
	if err != nil {
		return nil, err
	}

	if setting == nil || strings.TrimSpace(setting.Value) == "" {
		return nil, ErrAutomationNotFound
	}

	return unmarshalAutomation(setting.Id, setting.Value)
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

	if err := validateAutomation(automation); err != nil {
		return err
	}

	if _, _, err := ac.resolveAgent(automation.Agent); err != nil {
		return fmt.Errorf("%w: agent %q is not available", ErrInvalidAutomationParams, automation.Agent)
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

	existing, err := ac.stampAutomation(ctx, automation)
	if err != nil {
		return err
	}

	encoded, err := json.Marshal(automation)
	if err != nil {
		return err
	}

	// Without DuplicatedFromID, UpdateSetting resolves no definition and blanks the
	// inherited forced type, expanding this value into a nested YAML mapping.
	err = ac.srv.Configstore.UpdateSetting(ctx, &model.Setting{
		Id:               automationSettingId(automation.Id),
		Value:            string(encoded),
		DuplicatedFromID: ConfigSettingAutomationTemplate,
	}, false)
	if err != nil {
		return err
	}

	ac.watchAutomationSetting(automation.Id)

	// The new definition is stored, so the work the old params derived is now stale. Cancel
	// first so the run stops claiming, then finalize what it was holding. A failed sweep
	// leaves that stale work in place.
	if existing != nil && !jsonEqual(existing.Params, automation.Params) {
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

// stampAutomation settles the fields an automation does not set for itself: identity, owner
// and timestamps, returning the stored copy it read so the caller can see what changed.
// Caller holds configWriteMu, which is what makes that read and the write that follows it one
// edit rather than two. Nothing is written back to automation until every check has passed,
// so a rejected save leaves it as it arrived.
func (ac *AssistantCoordinator) stampAutomation(ctx context.Context, automation *model.Automation) (*model.Automation, error) {
	id := automation.Id
	// The handler puts the path id here, so an absent id is the only thing that means create.
	create := id == ""

	if create {
		id = uuid.NewString()
	} else if !isAutomationId(id) {
		return nil, fmt.Errorf("%w: id must be a UUID", ErrInvalidAutomationParams)
	}

	existing, err := ac.GetAutomation(ctx, id)
	if err != nil && !errors.Is(err, ErrAutomationNotFound) {
		return nil, err
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
		// Existing runs and work items hold payloads only the original kind can read.
		if existing.AutomationKind != automation.AutomationKind {
			return nil, fmt.Errorf("%w: automationKind cannot be changed", ErrInvalidAutomationParams)
		}

		// The owner is the identity unattended sessions execute as, so an edit by a second
		// admin must not silently hand them that user's RBAC.
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

	ac.configWriteMu.Lock()
	defer ac.configWriteMu.Unlock()

	if _, err := ac.GetAutomation(ctx, id); err != nil {
		return err
	}

	setting := model.NewSetting(automationSettingId(id))

	if err := ac.srv.Configstore.UpdateSetting(ctx, setting, true); err != nil {
		// Removing from a pillar file that was never created reports the missing file.
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
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

// watchAutomationSetting subscribes to one automation's setting. Registration appends and
// cannot be undone, so watchedAutomations is what keeps a second one from doubling every
// update.
func (ac *AssistantCoordinator) watchAutomationSetting(id string) {
	registrar, ok := ac.srv.Configstore.(server.ConfigSettingCallbackRegistrar)
	if !ok {
		return
	}

	ac.watchMu.Lock()
	defer ac.watchMu.Unlock()

	if ac.watchedAutomations == nil {
		ac.watchedAutomations = map[string]bool{}
	}

	if ac.watchedAutomations[id] {
		return
	}

	ac.watchedAutomations[id] = true

	registrar.RegisterConfigSettingCallback(automationSettingId(id), ac)
}

// watchStoredAutomations subscribes to every stored automation and drops the work items left
// behind by automations that no longer exist.
func (ac *AssistantCoordinator) watchStoredAutomations(ctx context.Context) {
	automations, unreadable, err := ac.scanAutomations(ctx)
	if err != nil {
		log.FromContext(ctx).WithError(err).Warn("unable to list automations; config changes will not hot-reload")

		return
	}

	for _, automation := range automations {
		ac.watchAutomationSetting(automation.Id)
	}

	if ac.store != nil {
		// After reconcileAutomationRuns: reconcile resets running items to pending, so
		// sweeping first would let it resurrect them.
		_ = ac.failOrphanedWorkItems(ctx, ac.store.FailOrphanedAutomationWorkItems, automations, unreadable)
	}
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
