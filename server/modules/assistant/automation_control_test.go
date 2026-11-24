// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	mockdb "github.com/security-onion-solutions/securityonion-soc/db/mock"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/assistant/database"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const stopTestRunId = "3f1a7c0e-9b21-4d8a-bc55-2e77a1f0c934"

// stopFixture is a coordinator whose store's stop writes are recorded, with Stop's caller
// identified as user-1.
type stopFixture struct {
	ac  *AssistantCoordinator
	cfg *automationConfigstore
	mDB *mockdb.MockDB

	causes    []error
	marks     []string
	ownerless []string
}

func newStopFixture(t *testing.T, stored ...*model.Automation) *stopFixture {
	t.Helper()

	f := &stopFixture{cfg: &automationConfigstore{}, mDB: &mockdb.MockDB{}}
	f.cfg.settings = []*model.Setting{automationsSetting(t, stored...)}
	f.ac = automationCoordinator(f.cfg)
	f.ac.store = automationTestStore(f.mDB)

	f.mDB.On("Query", mock.Anything, sqlLike("SET stopped_by = NULLIF($2, ''), stopped_at = now()"), mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { f.marks = append(f.marks, args.String(2)+":"+args.String(3)) }).
		Return(rowsYielding(1), nil)

	return f
}

// register puts a run in flight for this automation, recording every cancel it gets.
func (f *stopFixture) register(t *testing.T, id, runId string) {
	t.Helper()

	release := f.ac.registerAutomationRun(id, runId, func(cause error) { f.causes = append(f.causes, cause) })
	t.Cleanup(release)
}

// scriptOwnerlessClose answers CloseStoppedAutomationRun: an open row when open, none otherwise,
// or err.
func (f *stopFixture) scriptOwnerlessClose(open bool, err error) {
	mTx := &mockdb.MockTx{}

	call := mTx.On("Query", mock.Anything, sqlLike("SET state = 'stopped'"), mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			f.ownerless = append(f.ownerless, args.String(4)+":"+args.String(3)+":"+args.String(2))
		})

	switch {
	case err != nil:
		call.Return((*mockdb.MockRows)(nil), err)
	case open:
		mRows := &mockdb.MockRows{}
		mRows.On("Next").Return(true).Once()
		mRows.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
			*(args.Get(0).(*string)) = stopTestRunId
		}).Return(nil).Once()
		mRows.On("Next").Return(false)
		mRows.On("Err").Return(nil)
		mRows.On("Close").Return()
		call.Return(mRows, nil)
	default:
		call.Return(rowsYielding(0), nil)
	}

	mTx.On("Query", mock.Anything, sqlLike("UPDATE automation_work_items"), mock.Anything, mock.Anything).Return(rowsYielding(1), nil)
	mTx.On("Commit", mock.Anything).Return(nil)
	mTx.On("Rollback", mock.Anything).Return(nil)

	f.mDB.On("Begin", mock.Anything).Return(mTx, nil)
}

func storedEnabled(id string) *model.Automation {
	automation := storedAutomation(id, "Nightly")
	automation.Enabled = true

	return automation
}

func TestRunAutomationNowRequiresConfigWrite(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinatorAs(cfg, false)

	run, err := ac.RunAutomationNow(automationSaveCtx(), automationTestId)

	assert.Nil(t, run)
	var unauthorized *model.Unauthorized
	require.ErrorAs(t, err, &unauthorized)
	assert.Equal(t, "write", unauthorized.Operation)
	assert.Equal(t, "config", unauthorized.Target)
}

func TestRunAutomationNowRejectsAMalformedId(t *testing.T) {
	ac := automationCoordinator(&automationConfigstore{})
	ac.automationScheduler = &automationScheduler{ctx: context.Background(), runNow: make(chan *automationRunNowRequest)}

	_, err := ac.RunAutomationNow(automationSaveCtx(), "not-a-uuid")

	assert.ErrorIs(t, err, ErrInvalidAutomationParams)
}

func TestRunAutomationNowRefusesWithoutAScheduler(t *testing.T) {
	cases := []struct {
		name     string
		agentic  bool
		database bool
	}{
		{name: "agents off", database: true},
		{name: "no database", agentic: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ac := automationCoordinator(&automationConfigstore{})
			ac.isAgentic = tc.agentic
			if tc.database {
				ac.store = automationTestStore(&mockdb.MockDB{})
			}

			logCtx, h := capturedLogger()
			ctx := context.WithValue(logCtx, web.ContextKeyRequestorId, "user-1")

			_, err := ac.RunAutomationNow(ctx, automationTestId)

			assert.ErrorIs(t, err, ErrAutomationSchedulerUnavailable)
			require.Len(t, h.Entries, 1)
			assert.Equal(t, log.InfoLevel, h.Entries[0].Level)
			assert.Equal(t, tc.agentic, h.Entries[0].Fields["automationAgentsEnabled"])
			assert.Equal(t, tc.database, h.Entries[0].Fields["automationDatabaseConnected"])
		})
	}
}

// The registry compares ids as strings, so an uppercase id must still find the registered run.
func TestRunAutomationNowCanonicalizesTheId(t *testing.T) {
	licenseOAI(t)

	synctest.Test(t, func(t *testing.T) {
		f := newEngineFixture(t, storedAutomationWithParams(automationTestId, `{}`))
		f.ac.startAutomationScheduler()

		release := f.ac.registerAutomationRun(automationTestId, "run-0", func(error) {})
		defer release()

		_, err := f.ac.RunAutomationNow(automationSaveCtx(), strings.ToUpper(automationTestId))

		assert.ErrorIs(t, err, database.ErrAutomationRunInFlight)
		assert.Empty(t, f.openedSeen())
	})
}

// A hand-edited stored id in another form is read canonically, so Run now finds it.
func TestRunAutomationNowFindsAStoredNonCanonicalId(t *testing.T) {
	licenseOAI(t)

	synctest.Test(t, func(t *testing.T) {
		f := newEngineFixture(t, storedAutomationWithParams(strings.ToUpper(automationTestId), `{}`))
		f.ac.startAutomationScheduler()

		run, err := f.ac.RunAutomationNow(automationSaveCtx(), strings.ToUpper(automationTestId))

		require.NoError(t, err)
		assert.Equal(t, "run-1", run.Id)
		assert.Equal(t, []string{automationTestId + ":user-1"}, f.openedSeen())
	})
}

func TestRunAutomationNowReturnsTheOpenedRun(t *testing.T) {
	licenseOAI(t)

	synctest.Test(t, func(t *testing.T) {
		f := newEngineFixture(t, storedAutomationWithParams(automationTestId, `{}`))
		f.ac.startAutomationScheduler()

		run, err := f.ac.RunAutomationNow(automationSaveCtx(), automationTestId)

		require.NoError(t, err)
		assert.Equal(t, "run-1", run.Id)
		assert.Equal(t, []string{automationTestId + ":user-1"}, f.openedSeen())
	})
}

// heldWorker starts the scheduler with every run open held until release. The worker serving a
// request waits inside the open, still holding configWriteMu, and entered receives once it is
// there, so a test knows the worker has taken the request.
func heldWorker(t *testing.T, f *engineFixture) (entered chan struct{}, release func()) {
	t.Helper()

	entered = make(chan struct{}, 1)
	released := make(chan struct{})

	var once sync.Once
	release = func() { once.Do(func() { close(released) }) }
	// Registered after the fixture's Stop, so it runs first and Stop doesn't wait on a held open.
	t.Cleanup(release)

	f.mu.Lock()
	f.onOpen = func() {
		select {
		case entered <- struct{}{}:
		default:
		}

		<-released
	}
	f.mu.Unlock()

	f.ac.startAutomationScheduler()

	return entered, release
}

type runNowResult struct {
	run *model.AutomationRunRecord
	err error
}

func runNowAsync(ac *AssistantCoordinator, ctx context.Context) chan runNowResult {
	results := make(chan runNowResult, 1)

	go func() {
		run, err := ac.RunAutomationNow(ctx, automationTestId)
		results <- runNowResult{run, err}
	}()

	return results
}

func awaitResult[T any](t *testing.T, results chan T) T {
	t.Helper()

	select {
	case result := <-results:
		return result
	case <-time.After(5 * time.Second):
		require.FailNow(t, "the call never returned")
	}

	var zero T

	return zero
}

func TestRunAutomationNowReturnsWhenTheSchedulerStopsWhileItWaits(t *testing.T) {
	licenseOAI(t)

	f := newEngineFixture(t, storedAutomationWithParams(automationTestId, `{}`))
	entered, release := heldWorker(t, f)

	results := runNowAsync(f.ac, automationSaveCtx())
	awaitResult(t, entered)

	f.ac.automationWorkerMu.Lock()
	s := f.ac.automationScheduler
	f.ac.automationWorkerMu.Unlock()
	s.cancel(ErrAutomationSchedulerStopped)

	assert.ErrorIs(t, awaitResult(t, results).err, ErrAutomationSchedulerUnavailable)
	release()
}

// The worker is busy with another request, so this one can't be sent; its caller leaving must not
// leave it blocked.
func TestRunAutomationNowReturnsWhenItsCallerLeavesBeforeTheSend(t *testing.T) {
	licenseOAI(t)

	f := newEngineFixture(t, storedAutomationWithParams(automationTestId, `{}`))
	entered, release := heldWorker(t, f)

	busy := runNowAsync(f.ac, automationSaveCtx())
	awaitResult(t, entered)

	ctx, cancel := context.WithCancel(automationSaveCtx())
	cancel()

	assert.ErrorIs(t, awaitResult(t, runNowAsync(f.ac, ctx)).err, context.Canceled)

	release()
	require.NoError(t, awaitResult(t, busy).err)
}

// A caller that leaves after the worker took its request still gets the run opened.
func TestRunAutomationNowCallerLeavingAfterTheSendStillOpensTheRun(t *testing.T) {
	licenseOAI(t)

	f := newEngineFixture(t, storedAutomationWithParams(automationTestId, `{}`))
	f.kind.executeFunc = waitForStop
	entered, release := heldWorker(t, f)

	ctx, cancel := context.WithCancel(automationSaveCtx())
	results := runNowAsync(f.ac, ctx)
	awaitResult(t, entered)
	cancel()

	assert.ErrorIs(t, awaitResult(t, results).err, context.Canceled)

	release()
	assert.Eventually(t, func() bool { return f.ac.isAutomationRunning(automationTestId) }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, []string{automationTestId + ":user-1"}, f.openedSeen())
}

// A save holds configWriteMu and then wakes the scheduler, which takes automationWorkerMu; the
// worker serving Run now needs configWriteMu. Neither may wait on the other.
func TestRunAutomationNowAndADisablingSaveBothReturn(t *testing.T) {
	licenseOAI(t)

	f := newEngineFixture(t, storedEnabledAutomation(automationTestId, `{}`))
	f.scriptMarkStopping()
	f.scriptCloseStoppedRun(0, nil)
	f.kind.executeFunc = waitForStop
	f.ac.startAutomationScheduler()

	off := automationWithParams(`{}`)
	saved := make(chan error, 1)

	results := runNowAsync(f.ac, automationSaveCtx())
	go func() { saved <- f.ac.SaveAutomation(automationSaveCtx(), off) }()

	awaitResult(t, results)
	require.NoError(t, awaitResult(t, saved))
}

func TestStopAutomationRunRequiresConfigWrite(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinatorAs(cfg, false)
	cancelled := false
	release := ac.registerAutomationRun(automationTestId, stopTestRunId, func(error) { cancelled = true })
	defer release()

	err := ac.StopAutomationRun(automationSaveCtx(), automationTestId, stopTestRunId, true)

	var unauthorized *model.Unauthorized
	require.ErrorAs(t, err, &unauthorized)
	assert.False(t, cancelled)
	assert.Empty(t, cfg.updates)
}

func TestStopAutomationRunRejectsMalformedIds(t *testing.T) {
	f := newStopFixture(t, storedEnabled(automationTestId))
	f.register(t, automationTestId, stopTestRunId)

	assert.ErrorIs(t, f.ac.StopAutomationRun(automationSaveCtx(), "nope", stopTestRunId, false), ErrInvalidAutomationParams)
	assert.ErrorIs(t, f.ac.StopAutomationRun(automationSaveCtx(), automationTestId, "nope", false), ErrInvalidAutomationParams)

	assert.Empty(t, f.causes)
	assert.Empty(t, f.marks)
}

func TestStopAutomationRunStopsTheNamedRun(t *testing.T) {
	f := newStopFixture(t, storedEnabled(automationTestId))
	f.register(t, automationTestId, stopTestRunId)
	logCtx, h := capturedLogger()
	ctx := context.WithValue(logCtx, web.ContextKeyRequestorId, "user-1")

	require.NoError(t, f.ac.StopAutomationRun(ctx, automationTestId, stopTestRunId, false))

	assert.Equal(t, []error{ErrAutomationRunStopped}, f.causes)
	assert.Equal(t, []string{stopTestRunId + ":user-1"}, f.marks)
	assert.Empty(t, f.cfg.updates, "the automation stays on")
	assert.Equal(t, log.Fields{
		"automationId":        automationTestId,
		"automationRunId":     stopTestRunId,
		"automationStoppedBy": "user-1",
		"automationDisabled":  false,
	}, lastLoggedFields(h))
}

func TestStopAutomationRunCanonicalizesIds(t *testing.T) {
	f := newStopFixture(t, storedEnabled(automationTestId))
	f.register(t, automationTestId, stopTestRunId)

	require.NoError(t, f.ac.StopAutomationRun(automationSaveCtx(), strings.ToUpper(automationTestId), strings.ToUpper(stopTestRunId), false))

	assert.Equal(t, []error{ErrAutomationRunStopped}, f.causes)
	assert.Empty(t, f.ownerless, "the registered run was found, so no row is closed directly")
}

// The engine registers runs under the id as read, which is canonical, so a hand-edited uppercase
// stored id still reaches the live run and the stored automation.
func TestStopAutomationRunOnAStoredNonCanonicalId(t *testing.T) {
	f := newStopFixture(t, storedEnabled(strings.ToUpper(automationTestId)))
	f.register(t, automationTestId, stopTestRunId)

	require.NoError(t, f.ac.StopAutomationRun(automationSaveCtx(), strings.ToUpper(automationTestId), stopTestRunId, true))

	assert.Equal(t, []error{ErrAutomationRunStopped}, f.causes)
	assert.Empty(t, f.ownerless, "the live run's row is not closed out from under it")
	require.Len(t, f.cfg.updates, 1)
	written := writtenAutomations(t, f.cfg.updates[0])
	require.Len(t, written, 1, "the stored entry is replaced, not duplicated")
	assert.Equal(t, automationTestId, written[0].Id)
	assert.False(t, written[0].Enabled)
}

func TestStopAutomationRunRefusesAnotherRun(t *testing.T) {
	f := newStopFixture(t, storedEnabled(automationTestId))
	f.register(t, automationTestId, "6d2b9e10-4c7f-4a3e-9b8d-1f0e2c3a4b5c")

	assert.ErrorIs(t, f.ac.StopAutomationRun(automationSaveCtx(), automationTestId, stopTestRunId, false), ErrAutomationRunNotInFlight)
	assert.Empty(t, f.causes)
	assert.Empty(t, f.ownerless)
}

func TestStopAutomationRunWithNothingRegistered(t *testing.T) {
	t.Run("an open row is closed as stopped", func(t *testing.T) {
		f := newStopFixture(t, storedEnabled(automationTestId))
		f.scriptOwnerlessClose(true, nil)
		logCtx, h := capturedLogger()
		ctx := context.WithValue(logCtx, web.ContextKeyRequestorId, "user-1")

		require.NoError(t, f.ac.StopAutomationRun(ctx, automationTestId, stopTestRunId, false))

		assert.Equal(t, []string{stopTestRunId + ":" + automationTestId + ":user-1"}, f.ownerless)
		assert.Equal(t, stopTestRunId, lastLoggedFields(h)["automationRunId"])
	})

	t.Run("no open row", func(t *testing.T) {
		f := newStopFixture(t, storedEnabled(automationTestId))
		f.scriptOwnerlessClose(false, nil)

		assert.ErrorIs(t, f.ac.StopAutomationRun(automationSaveCtx(), automationTestId, stopTestRunId, false), ErrAutomationRunNotInFlight)
	})

	t.Run("no store", func(t *testing.T) {
		f := newStopFixture(t, storedEnabled(automationTestId))
		f.ac.store = nil

		assert.ErrorIs(t, f.ac.StopAutomationRun(automationSaveCtx(), automationTestId, stopTestRunId, false), ErrAutomationRunNotInFlight)
		f.mDB.AssertNotCalled(t, "Begin", mock.Anything)
	})

	t.Run("the close fails", func(t *testing.T) {
		f := newStopFixture(t, storedEnabled(automationTestId))
		f.scriptOwnerlessClose(false, errors.New("postgres is down"))
		logCtx, h := capturedLogger()
		ctx := context.WithValue(logCtx, web.ContextKeyRequestorId, "user-1")

		assert.EqualError(t, f.ac.StopAutomationRun(ctx, automationTestId, stopTestRunId, false), "postgres is down")

		require.NotEmpty(t, h.Entries)
		assert.Equal(t, log.WarnLevel, h.Entries[0].Level)
		assert.Equal(t, stopTestRunId, h.Entries[0].Fields["automationRunId"])
	})

	t.Run("the close fails, the automation is still turned off, and the error is returned", func(t *testing.T) {
		f := newStopFixture(t, storedEnabled(automationTestId))
		f.scriptOwnerlessClose(false, errors.New("postgres is down"))

		assert.EqualError(t, f.ac.StopAutomationRun(automationSaveCtx(), automationTestId, stopTestRunId, true), "postgres is down")

		require.Len(t, f.cfg.updates, 1)
		assert.False(t, writtenAutomations(t, f.cfg.updates[0])[0].Enabled)
	})

	t.Run("the close and the turn-off both fail", func(t *testing.T) {
		f := newStopFixture(t, storedEnabled(automationTestId))
		f.scriptOwnerlessClose(false, errors.New("postgres is down"))
		f.cfg.updateErr = errors.New("salt is down")

		err := f.ac.StopAutomationRun(automationSaveCtx(), automationTestId, stopTestRunId, true)

		assert.ErrorContains(t, err, "postgres is down")
		assert.ErrorContains(t, err, "salt is down")
	})
}

func TestStopAndTurnOff(t *testing.T) {
	t.Run("stops the run, then writes only enabled", func(t *testing.T) {
		stored := storedEnabled(automationTestId)
		// Would fail validation; the turn-off doesn't validate.
		stored.DisplayName = ""
		f := newStopFixture(t, stored)
		f.register(t, automationTestId, stopTestRunId)

		var causesAtWrite int
		f.cfg.onUpdate = func() {
			causesAtWrite = len(f.causes)
			assert.False(t, f.ac.configWriteMu.TryLock(), "written under configWriteMu")
		}
		logCtx, h := capturedLogger()
		ctx := context.WithValue(logCtx, web.ContextKeyRequestorId, "user-1")

		require.NoError(t, f.ac.StopAutomationRun(ctx, automationTestId, stopTestRunId, true))

		assert.Equal(t, 1, causesAtWrite, "the run is stopped before the write")
		require.Len(t, f.cfg.updates, 1)

		written := writtenAutomations(t, f.cfg.updates[0])[0]
		assert.False(t, written.Enabled)
		assert.Empty(t, written.DisplayName)
		assert.Equal(t, stored.IntervalSeconds, written.IntervalSeconds)
		assert.Equal(t, stored.Agent, written.Agent)
		assert.True(t, f.ac.automationsDirty.Load())
		assert.Equal(t, true, lastLoggedFields(h)["automationDisabled"])
	})

	t.Run("a write failure is returned, and the run is still stopped", func(t *testing.T) {
		f := newStopFixture(t, storedEnabled(automationTestId))
		f.register(t, automationTestId, stopTestRunId)
		f.cfg.updateErr = errors.New("salt is down")

		assert.EqualError(t, f.ac.StopAutomationRun(automationSaveCtx(), automationTestId, stopTestRunId, true), "salt is down")
		assert.Equal(t, []error{ErrAutomationRunStopped}, f.causes)
	})

	t.Run("a request cancelled after the stop still turns it off", func(t *testing.T) {
		f := newStopFixture(t, storedEnabled(automationTestId))

		ctx, cancel := context.WithCancel(automationSaveCtx())
		release := f.ac.registerAutomationRun(automationTestId, stopTestRunId, func(error) { cancel() })
		defer release()

		require.NoError(t, f.ac.StopAutomationRun(ctx, automationTestId, stopTestRunId, true))
		require.Len(t, f.cfg.updates, 1)
		assert.False(t, writtenAutomations(t, f.cfg.updates[0])[0].Enabled)
	})

	t.Run("naming a run that already ended", func(t *testing.T) {
		f := newStopFixture(t, storedEnabled(automationTestId))
		f.scriptOwnerlessClose(false, nil)

		require.NoError(t, f.ac.StopAutomationRun(automationSaveCtx(), automationTestId, stopTestRunId, true))
		require.Len(t, f.cfg.updates, 1)
		assert.False(t, writtenAutomations(t, f.cfg.updates[0])[0].Enabled)
	})

	t.Run("a different run registered is stopped too", func(t *testing.T) {
		f := newStopFixture(t, storedEnabled(automationTestId))
		f.register(t, automationTestId, "6d2b9e10-4c7f-4a3e-9b8d-1f0e2c3a4b5c")

		require.NoError(t, f.ac.StopAutomationRun(automationSaveCtx(), automationTestId, stopTestRunId, true))
		assert.Equal(t, []error{ErrAutomationRunStopped}, f.causes)
		assert.Len(t, f.cfg.updates, 1)
	})

	t.Run("an automation already off is not written", func(t *testing.T) {
		f := newStopFixture(t, storedAutomation(automationTestId, "Nightly"))
		f.register(t, automationTestId, stopTestRunId)

		require.NoError(t, f.ac.StopAutomationRun(automationSaveCtx(), automationTestId, stopTestRunId, true))
		assert.Empty(t, f.cfg.updates)
		assert.False(t, f.ac.automationsDirty.Load())
	})

	t.Run("a never-saved builtin has no stored copy to write", func(t *testing.T) {
		f := newStopFixture(t)
		seedBuiltinAutomation(f.ac)
		f.register(t, BuiltinAlertTriageAutomationId, stopTestRunId)

		require.NoError(t, f.ac.StopAutomationRun(automationSaveCtx(), BuiltinAlertTriageAutomationId, stopTestRunId, true))
		assert.Equal(t, []error{ErrAutomationRunStopped}, f.causes)
		assert.Empty(t, f.cfg.updates)
	})

	t.Run("a deleted automation's run is stopped, then not found", func(t *testing.T) {
		f := newStopFixture(t)
		f.register(t, automationTestId, stopTestRunId)

		assert.ErrorIs(t, f.ac.StopAutomationRun(automationSaveCtx(), automationTestId, stopTestRunId, true), ErrAutomationNotFound)
		assert.Equal(t, []error{ErrAutomationRunStopped}, f.causes)
	})
}

func TestStopAutomationRunOnADeletedAutomation(t *testing.T) {
	f := newStopFixture(t)
	f.register(t, automationTestId, stopTestRunId)

	require.NoError(t, f.ac.StopAutomationRun(automationSaveCtx(), automationTestId, stopTestRunId, false))
	assert.Equal(t, []error{ErrAutomationRunStopped}, f.causes)
}
