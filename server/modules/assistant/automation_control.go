// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"errors"
	"fmt"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/assistant/database"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/google/uuid"
)

// canonicalAutomationId returns id in the form the registry and the stored definitions compare
// as a string. Postgres matches its uuid columns in any case, so an uppercase or braced id would
// reach a row while missing the run registered for it.
func canonicalAutomationId(id string) (string, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return "", fmt.Errorf("%w: id must be a UUID", ErrInvalidAutomationParams)
	}

	return parsed.String(), nil
}

// RunAutomationNow starts one run of the automation immediately, whether or not it is enabled or
// due, and returns the opened run. On a disabled automation the run is a one-off.
func (ac *AssistantCoordinator) RunAutomationNow(ctx context.Context, id string) (*model.AutomationRunRecord, error) {
	if err := ac.srv.CheckAuthorized(ctx, "write", "config"); err != nil {
		return nil, err
	}

	id, err := canonicalAutomationId(id)
	if err != nil {
		return nil, err
	}

	startedBy, _ := ctx.Value(web.ContextKeyRequestorId).(string)

	// Released before the wait: a save holds configWriteMu while it takes this lock to wake the
	// scheduler, and the worker needs configWriteMu to answer.
	ac.automationWorkerMu.Lock()
	s := ac.automationScheduler
	ac.automationWorkerMu.Unlock()

	if s == nil {
		log.FromContext(ctx).WithFields(log.Fields{
			"automationId":                id,
			"automationAgentsEnabled":     ac.isAgentic,
			"automationDatabaseConnected": ac.store != nil,
		}).Info("automation run now refused; the automation scheduler is not running")

		return nil, ErrAutomationSchedulerUnavailable
	}

	req := &automationRunNowRequest{automationId: id, startedBy: startedBy, reply: make(chan automationRunNowReply, 1)}

	select {
	case s.runNow <- req:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, ErrAutomationSchedulerUnavailable
	}

	select {
	case reply := <-req.reply:
		return reply.run, reply.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, ErrAutomationSchedulerUnavailable
	}
}

// StopAutomationRun stops the automation's in-flight run, if it is runId, without waiting for it
// to end. With disable, it stops whatever run is in flight and turns the automation off; if the
// turn-off fails, the run is still stopped, and if closing an ownerless run fails, the automation
// is still turned off and the close error is returned.
func (ac *AssistantCoordinator) StopAutomationRun(ctx context.Context, id, runId string, disable bool) error {
	if ac.srv == nil || ac.srv.Configstore == nil {
		return ErrConfigstoreUnavailable
	}

	if err := ac.srv.CheckAuthorized(ctx, "write", "config"); err != nil {
		return err
	}

	userId, _ := ctx.Value(web.ContextKeyRequestorId).(string)

	id, err := canonicalAutomationId(id)
	if err != nil {
		return err
	}

	runId, err = canonicalAutomationId(runId)
	if err != nil {
		return err
	}

	ac.configWriteMu.Lock()
	defer ac.configWriteMu.Unlock()

	// Turning the automation off stops whatever it has in flight, even if the named run ended
	// while the dialog was open.
	target := runId
	if disable {
		target = ""
	}

	var closeErr error
	stopped := ac.stopRegisteredAutomationRun(ctx, id, target, userId)
	if stopped == "" {
		closeErr = ac.closeOwnerlessAutomationRun(ctx, id, runId, userId)
		if disable && errors.Is(closeErr, ErrAutomationRunNotInFlight) {
			closeErr = nil
		} else if closeErr != nil && !disable {
			return closeErr
		}
	}

	var disableErr error
	if disable {
		disableErr = ac.turnOffAutomationLocked(ctx, id)
	}

	logged := stopped
	if logged == "" {
		logged = runId
	}

	log.FromContext(ctx).WithFields(log.Fields{
		"automationId":        id,
		"automationRunId":     logged,
		"automationStoppedBy": userId,
		"automationDisabled":  disable,
	}).Info("automation run stop requested")

	return errors.Join(closeErr, disableErr)
}

// closeOwnerlessAutomationRun closes the named run's open row as stopped when no run is
// registered for the automation. Under configWriteMu no open is half done, so such a row has no
// owner: its close write failed, which on a disabled automation nothing else clears short of a
// restart. A stopper and stop time already on the row are kept.
func (ac *AssistantCoordinator) closeOwnerlessAutomationRun(ctx context.Context, id, runId, userId string) error {
	if ac.isAutomationRunning(id) || ac.store == nil {
		return ErrAutomationRunNotInFlight
	}

	_, err := ac.store.CloseStoppedAutomationRun(ctx, id, runId, ErrAutomationRunStopped.Error(), userId)
	if errors.Is(err, database.ErrAutomationRunNotOpen) {
		return ErrAutomationRunNotInFlight
	}

	if err != nil {
		log.FromContext(ctx).WithError(err).WithFields(log.Fields{
			"automationId":    id,
			"automationRunId": runId,
		}).Warn("unable to close an automation run no run owns")
	}

	return err
}

// turnOffAutomationLocked writes the stored copy back with only enabled changed. It skips
// SaveAutomation's validation, so an unrelated invalid field can't block it, and is detached from
// the request so a client that leaves after the stop still gets the automation turned off. The
// caller holds configWriteMu.
func (ac *AssistantCoordinator) turnOffAutomationLocked(ctx context.Context, id string) error {
	writeCtx, done := web.DetachContext(ctx, DETACHED_WRITE_TIMEOUT)
	defer done()

	stored, err := ac.readStoredAutomations(writeCtx)
	if err != nil {
		return err
	}

	automation := findStoredAutomation(stored, id)
	if automation == nil {
		// A builtin with no stored copy ships off.
		if ac.isBuiltinAutomation(id) {
			return nil
		}

		return ErrAutomationNotFound
	}

	if !automation.Enabled {
		return nil
	}

	automation.Enabled = false

	if _, err := ac.writeAutomationLocked(writeCtx, automation, stored); err != nil {
		return err
	}

	ac.invalidateAutomations()

	return nil
}

// stopRegisteredAutomationRun stops the run registered for this automation when it is runId,
// or whichever run is registered when runId is empty, and returns the id of the run it
// stopped, or "" when it stopped nothing. The caller holds configWriteMu. It does not wait for
// the run to end.
func (ac *AssistantCoordinator) stopRegisteredAutomationRun(ctx context.Context, id, runId, userId string) string {
	ac.automationRunMu.Lock()
	run := ac.automationRuns[id]
	ac.automationRunMu.Unlock()

	if run == nil || (runId != "" && run.runId != runId) {
		return ""
	}

	// Marked before the cancel: a run with no jobs can close as soon as it sees the cancel, and
	// the mark only writes an open row. A run that ends on its own in between closes through
	// CloseAutomationRun, which clears the mark.
	if ac.store != nil {
		if err := ac.store.MarkAutomationRunStopping(ctx, run.runId, userId); err != nil {
			log.FromContext(ctx).WithError(err).WithFields(log.Fields{
				"automationId":    id,
				"automationRunId": run.runId,
			}).Warn("unable to record who stopped the automation run; stopping it anyway")
		}
	}

	run.cancel(ErrAutomationRunStopped)
	ac.notifyAutomationActivity()

	return run.runId
}
