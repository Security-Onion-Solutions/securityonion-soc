// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/execpool"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/assistant/database"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
)

var (
	// The cause recorded on a run the scheduler cancelled at shutdown.
	ErrAutomationSchedulerStopped = errors.New("ERROR_AUTOMATION_SCHEDULER_STOPPED")
	// The cause recorded on an open run row this process has no run for.
	ErrAutomationRunAbandoned = errors.New("ERROR_AUTOMATION_RUN_ABANDONED")
)

// automationScheduler is one started worker. Runs descend from ctx; done closes once the
// worker and every run it started have returned.
type automationScheduler struct {
	ctx    context.Context
	cancel context.CancelCauseFunc
	wake   chan struct{}
	done   chan struct{}
	pool   *execpool.Pool
}

// startAutomationScheduler starts the worker where a run could succeed: agentic, online, with Postgres.
func (ac *AssistantCoordinator) startAutomationScheduler() {
	logger := log.FromContext(ac.srv.Context)

	switch {
	case !ac.isAgentic:
		return
	case ac.srv.Config != nil && ac.srv.Config.AirgapEnabled:
		logger.Info("airgap enabled; automations will not run")

		return
	case ac.store == nil:
		logger.Warn("no database connection; automations will not run")

		return
	case ac.getAutomationTickInterval() <= 0:
		logger.Warn("automation tick interval is not positive; automations will not run")

		return
	}

	ac.automationWorkerMu.Lock()
	defer ac.automationWorkerMu.Unlock()

	if ac.automationScheduler != nil {
		return
	}

	ctx, cancel := context.WithCancelCause(ac.srv.Context)

	s := &automationScheduler{
		ctx:    ctx,
		cancel: cancel,
		wake:   make(chan struct{}, 1),
		done:   make(chan struct{}),
		pool: execpool.New(ctx, execpool.Config{
			Name:          "automation",
			MaxQueueDepth: ac.automationMaxQueuedItems,
			MaxConcurrent: ac.automationMaxConcurrentItems,
			KeyLimitFunc:  ac.agentConcurrencyLimit,
		}),
	}

	ac.automationScheduler = s

	go ac.automationWorker(s)
}

// stopAutomationScheduler cancels the worker and every run, then waits, bounded, for their rows to close.
func (ac *AssistantCoordinator) stopAutomationScheduler() {
	ac.automationWorkerMu.Lock()
	s := ac.automationScheduler
	ac.automationScheduler = nil
	ac.automationWorkerMu.Unlock()

	if s == nil {
		return
	}

	s.cancel(ErrAutomationSchedulerStopped)

	logger := log.FromContext(ac.srv.Context)

	ctx, cancel := context.WithTimeout(ac.srv.Context, AUTOMATION_STOP_TIMEOUT)
	defer cancel()

	select {
	case <-s.done:
	case <-ctx.Done():
		logger.Warn("automation runs still in flight at stop; reconciliation closes their rows at the next start")
	}

	if err := s.pool.Shutdown(ctx); err != nil {
		logger.WithError(err).Warn("automation pool did not drain")
	}
}

// shuttingDown reports whether ctx was cancelled by the scheduler stopping, as opposed to a
// params change; the cause reaches every context derived from the scheduler's.
func shuttingDown(ctx context.Context) bool {
	return errors.Is(context.Cause(ctx), ErrAutomationSchedulerStopped)
}

// agentConcurrencyLimit is the pool's KeyLimitFunc; it runs under the pool lock, so it only reads the agent map.
func (ac *AssistantCoordinator) agentConcurrencyLimit(name string) int {
	ac.agentMu.RLock()
	defer ac.agentMu.RUnlock()

	return ac.agents[name].MaxConcurrentInstances
}

// automationEngineStatus is what the scheduler can say about itself without Postgres.
type automationEngineStatus struct {
	Running bool
	Pool    execpool.Stats
	// Automations with a run executing right now.
	ActiveAutomationIds []string
}

func (ac *AssistantCoordinator) getAutomationEngineStatus() automationEngineStatus {
	ac.automationWorkerMu.Lock()
	s := ac.automationScheduler
	ac.automationWorkerMu.Unlock()

	status := automationEngineStatus{Running: s != nil, ActiveAutomationIds: []string{}}
	if s != nil {
		status.Pool = s.pool.Stats()
	}

	ac.automationRunMu.Lock()
	defer ac.automationRunMu.Unlock()

	for id := range ac.automationRuns {
		status.ActiveAutomationIds = append(status.ActiveAutomationIds, id)
	}

	slices.Sort(status.ActiveAutomationIds)

	return status
}

// wakeAutomationScheduler ticks ahead of the ticker without blocking; config callbacks call it inline.
func (ac *AssistantCoordinator) wakeAutomationScheduler() {
	ac.automationWorkerMu.Lock()
	defer ac.automationWorkerMu.Unlock()

	if ac.automationScheduler == nil {
		return
	}

	select {
	case ac.automationScheduler.wake <- struct{}{}:
	default:
	}
}

// invalidateAutomations records a write to the stored set and ticks now.
func (ac *AssistantCoordinator) invalidateAutomations() {
	ac.automationsDirty.Store(true)
	ac.wakeAutomationScheduler()
}

func (ac *AssistantCoordinator) getAutomationTickInterval() time.Duration {
	return time.Duration(ac.automationTickInterval.Load())
}

// reloadAutomationTickInterval overlays the stored tick interval; an absent value restores the
// Init one and an unusable value keeps the current one.
func (ac *AssistantCoordinator) reloadAutomationTickInterval(ctx context.Context) {
	if ac.srv.Configstore == nil {
		return
	}

	logger := log.FromContext(ctx).WithField("setting", ConfigSettingAutomationTickInterval)

	setting, err := ac.srv.Configstore.GetSetting(ctx, ConfigSettingAutomationTickInterval)
	if err != nil {
		logger.WithError(err).Warn("unable to read automation tick interval; keeping previous value")

		return
	}

	next := int64(ac.automationDefaultTickInterval)

	if setting != nil && strings.TrimSpace(setting.Value) != "" {
		seconds, err := parseIntSetting(setting.Value)
		if err != nil || seconds <= 0 {
			logger.WithField("value", setting.Value).Warn("automation tick interval must be a positive integer; keeping previous value")

			return
		}

		next = int64(time.Duration(seconds) * time.Second)
	}

	if ac.automationTickInterval.Swap(next) != next {
		ac.wakeAutomationScheduler()
	}
}

func (ac *AssistantCoordinator) getAlertTriageEpoch() time.Time {
	return time.Unix(0, ac.alertTriageEpoch.Load()).UTC()
}

func parseAlertTriageEpoch(value string) (time.Time, error) {
	return time.Parse(time.RFC3339, strings.TrimSpace(value))
}

// reloadAlertTriageEpoch overlays the stored epoch; an absent value restores the Init one and an
// unusable value keeps the current one. Runs already under way keep the epoch they started with.
func (ac *AssistantCoordinator) reloadAlertTriageEpoch(ctx context.Context) {
	if ac.srv.Configstore == nil {
		return
	}

	logger := log.FromContext(ctx).WithField("setting", ConfigSettingAlertTriageEpoch)

	setting, err := ac.srv.Configstore.GetSetting(ctx, ConfigSettingAlertTriageEpoch)
	if err != nil {
		logger.WithError(err).Warn("unable to read alert triage epoch; keeping previous value")

		return
	}

	next := ac.alertTriageDefaultEpoch

	if setting != nil && strings.TrimSpace(setting.Value) != "" {
		next, err = parseAlertTriageEpoch(setting.Value)
		if err != nil {
			logger.WithError(err).WithField("value", setting.Value).Warn("alert triage epoch must be an RFC3339 time; keeping previous value")

			return
		}
	}

	ac.alertTriageEpoch.Store(next.UnixNano())
}

// automationWorker ticks on the interval and on every wake.
func (ac *AssistantCoordinator) automationWorker(s *automationScheduler) {
	defer close(s.done)

	logger := log.FromContext(s.ctx)

	interval := ac.getAutomationTickInterval()
	logger.WithField("automationTickInterval", interval).Info("automation scheduler started")

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			ac.automationRunsWg.Wait()
			logger.WithField("cause", context.Cause(s.ctx)).Info("automation scheduler stopped")

			return
		case <-s.wake:
			if next := ac.getAutomationTickInterval(); next != interval {
				interval = next
				ticker.Reset(interval)

				logger.WithField("automationTickInterval", interval).Info("automation tick interval updated")
			}
		case <-ticker.C:
		}

		ac.automationTick(s)
	}
}

// automationTick re-reads the stored set, drops work queued for automations that left it, and
// starts what is due. Pillar edits raise no callback, so the set is read every tick.
func (ac *AssistantCoordinator) automationTick(s *automationScheduler) {
	if s.ctx.Err() != nil {
		return
	}

	logger := log.FromContext(s.ctx)

	// Bounds the reads and the opens to one interval; runs descend from s.ctx.
	tickCtx, cancel := context.WithTimeout(s.ctx, ac.getAutomationTickInterval())
	defer cancel()

	// Cleared before the read so a write that lands during it is still set at the open.
	ac.automationsDirty.Store(false)

	automations, unreadable, err := ac.scanAutomations(tickCtx)
	if err != nil {
		logger.WithError(err).Warn("unable to list automations; automation tick skipped")

		return
	}

	// Pending only: a run already under way for a removed automation is allowed to finish.
	if err := ac.failOrphanedWorkItems(tickCtx, ac.store.FailOrphanedPendingAutomationWorkItems, automations, unreadable); err != nil {
		return
	}

	if err := ac.startDueAutomationRuns(tickCtx, s, automations); err != nil {
		logger.WithError(err).Warn("automation tick skipped")
	}
}

// startDueAutomationRuns opens runs under configWriteMu so none opens between a save's write and
// its sweep. A write that landed during this tick's read leaves the opens to the tick it woke,
// which reads the new definitions. A nil store is ErrNoDatabase rather than a run built on one.
func (ac *AssistantCoordinator) startDueAutomationRuns(tickCtx context.Context, s *automationScheduler, automations []*model.Automation) error {
	if ac.store == nil {
		return ErrNoDatabase
	}

	ids := make([]string, 0, len(automations))
	for _, automation := range automations {
		ids = append(ids, automation.Id)
	}

	lastStarted, err := ac.store.LatestAutomationRunStartTimes(tickCtx, ids)
	if err != nil {
		return err
	}

	ac.configWriteMu.Lock()
	defer ac.configWriteMu.Unlock()

	if ac.automationsDirty.Load() {
		return nil
	}

	now := time.Now()

	for _, automation := range automations {
		if s.ctx.Err() != nil {
			return nil
		}

		if automationDue(automation, lastStarted, now) {
			ac.startAutomationRun(tickCtx, s, automation)
		}
	}

	return nil
}

// The interval runs from the last start, so run length never stretches the cadence. Zero is
// what an omitted interval decodes to, so it means never rather than always.
func automationDue(automation *model.Automation, lastStarted map[string]time.Time, now time.Time) bool {
	if !automation.Enabled || automation.IntervalSeconds <= 0 {
		return false
	}

	last, ok := lastStarted[automation.Id]

	return !ok || now.Sub(last) >= time.Duration(automation.IntervalSeconds)*time.Second
}

func (ac *AssistantCoordinator) isAutomationRunning(id string) bool {
	ac.automationRunMu.Lock()
	defer ac.automationRunMu.Unlock()

	return ac.automationRuns[id] != nil
}

// The kind is resolved before the row opens, so an unknown kind costs a log line rather than a failed row every interval.
// tickCtx bounds the open; the run itself descends from the scheduler.
func (ac *AssistantCoordinator) startAutomationRun(tickCtx context.Context, s *automationScheduler, automation *model.Automation) {
	logger := log.FromContext(s.ctx).WithField("automationId", automation.Id)

	kind, err := ac.lookupAutomationKind(automation.AutomationKind)
	if err != nil {
		logger.WithField("automationKind", automation.AutomationKind).Warn("automation names a kind this build does not provide; skipping")

		return
	}

	if _, _, err := ac.resolveAgent(automation.Agent); err != nil {
		logger.WithField("agent", automation.Agent).Warn("automation names an agent that is not available; skipping")

		return
	}

	if ac.isAutomationRunning(automation.Id) {
		logger.Debug("automation already running; skipping")

		return
	}

	record, err := ac.store.OpenAutomationRun(tickCtx, automation.Id)
	if errors.Is(err, database.ErrAutomationRunInFlight) {
		ac.failAbandonedAutomationRun(tickCtx, logger, automation.Id)

		return
	}

	if err != nil {
		logger.WithError(err).Error("unable to open automation run")

		return
	}

	runCtx, cancel := context.WithCancelCause(s.ctx)
	release := ac.registerAutomationRun(automation.Id, cancel)

	run := &AutomationRun{
		Srv:   ac.srv,
		Task:  automation,
		RunId: record.Id,
		Store: ac.store,
		Pool:  s.pool,

		AlertTriageEpoch: ac.getAlertTriageEpoch(),
	}

	ac.automationRunsWg.Add(1)

	// The row closes before the release, so the automation reads as running everywhere until it is not.
	go func() {
		defer release()
		defer cancel(nil)

		ac.executeAutomationRun(runCtx, kind, run)
	}()
}

// failAbandonedAutomationRun closes the open row nothing owns. Runs open and register on the
// worker goroutine and close their row before releasing, so an in-flight row with no run
// registered here is one an open lost the result of or a close could not end. A failed write
// is retried by the next tick, which meets the same row.
func (ac *AssistantCoordinator) failAbandonedAutomationRun(ctx context.Context, logger *log.Entry, automationId string) {
	failed, err := ac.store.FailAbandonedAutomationRun(ctx, automationId, ErrAutomationRunAbandoned.Error())
	if err != nil {
		logger.WithError(err).Warn("unable to fail abandoned automation run; retrying next tick")

		return
	}

	logger.WithField("failedRuns", failed).Warn("automation run in flight with no owner; failed it so the next tick can open one")
}

func (ac *AssistantCoordinator) executeAutomationRun(ctx context.Context, kind AutomationKind, run *AutomationRun) {
	defer ac.automationRunsWg.Done()

	logger := log.FromContext(ctx).WithFields(log.Fields{
		"automationId":    run.Task.Id,
		"automationRunId": run.RunId,
	})
	ctx = log.NewContext(ctx, logger)

	items, err := run.Store.ListOpenAutomationWorkItems(ctx, run.Task.Id)
	if err == nil {
		run.OpenItems = items
		err = runAutomationKind(ctx, logger, kind, run)
	} else {
		logger.WithError(err).Error("unable to list open automation work items")
	}

	ac.closeAutomationRun(ctx, logger, run.RunId, err)
}

func runAutomationKind(ctx context.Context, logger *log.Entry, kind AutomationKind, run *AutomationRun) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("automation kind panicked: %v", r)

			logger.WithFields(log.Fields{
				"panic": r,
				"stack": string(debug.Stack()),
			}).Error("recovered panic from automation run")
		}
	}()

	return kind.Execute(ctx, run)
}

// A cancelled run failed whatever the kind returned; the write is detached from that cancellation.
// A shutdown skips the write: the row stays open and the next start's reconcile fails it.
func (ac *AssistantCoordinator) closeAutomationRun(ctx context.Context, logger *log.Entry, runId string, err error) {
	if shuttingDown(ctx) {
		logger.Info("automation run left open at shutdown; the next start reconciles it")

		return
	}

	state, cause := model.AutomationRunSucceeded, ""

	switch {
	case ctx.Err() != nil:
		state, cause = model.AutomationRunFailed, context.Cause(ctx).Error()
	case err != nil:
		state, cause = model.AutomationRunFailed, err.Error()
	}

	closeCtx, done := web.DetachContext(ctx, DETACHED_WRITE_TIMEOUT)
	defer done()

	if err := ac.store.CloseAutomationRun(closeCtx, runId, state, cause); err != nil {
		logger.WithError(err).Error("unable to close automation run; the next tick fails it as abandoned")

		return
	}

	logger.WithFields(log.Fields{
		"state": state,
		"cause": cause,
	}).Info("automation run finished")
}
