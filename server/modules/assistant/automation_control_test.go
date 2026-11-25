// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"cmp"
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
	"github.com/apex/log/handlers/memory"
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

func TestAutomationControlRequiresConfigWrite(t *testing.T) {
	cases := []struct {
		name string
		call func(t *testing.T, ac *AssistantCoordinator) error
	}{
		{name: "run now", call: func(t *testing.T, ac *AssistantCoordinator) error {
			run, err := ac.RunAutomationNow(automationSaveCtx(), automationTestId)
			assert.Nil(t, run)

			return err
		}},
		{name: "stop", call: func(t *testing.T, ac *AssistantCoordinator) error {
			return ac.StopAutomationRun(automationSaveCtx(), automationTestId, stopTestRunId, true)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &automationConfigstore{}
			ac := automationCoordinatorAs(cfg, false)
			cancelled := false
			release := ac.registerAutomationRun(automationTestId, stopTestRunId, func(error) { cancelled = true })
			defer release()

			err := tc.call(t, ac)

			var unauthorized *model.Unauthorized
			require.ErrorAs(t, err, &unauthorized)
			assert.Equal(t, "write", unauthorized.Operation)
			assert.Equal(t, "config", unauthorized.Target)
			assert.False(t, cancelled)
			assert.Empty(t, cfg.updates)
		})
	}
}

func TestRunAutomationNowRefusesBeforeTheWorker(t *testing.T) {
	cases := []struct {
		name      string
		id        string
		agentic   bool
		database  bool
		scheduler bool
		wantErr   error
	}{
		{name: "a malformed id", id: "not-a-uuid", scheduler: true, wantErr: ErrInvalidAutomationParams},
		{name: "agents off", id: automationTestId, database: true, wantErr: ErrAutomationSchedulerUnavailable},
		{name: "no database", id: automationTestId, agentic: true, wantErr: ErrAutomationSchedulerUnavailable},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ac := automationCoordinator(&automationConfigstore{})
			ac.isAgentic = tc.agentic
			if tc.database {
				ac.store = automationTestStore(&mockdb.MockDB{})
			}
			if tc.scheduler {
				ac.automationScheduler = &automationScheduler{ctx: context.Background(), runNow: make(chan *automationRunNowRequest)}
			}

			logCtx, h := capturedLogger()
			ctx := context.WithValue(logCtx, web.ContextKeyRequestorId, "user-1")

			_, err := ac.RunAutomationNow(ctx, tc.id)

			assert.ErrorIs(t, err, tc.wantErr)
			if tc.wantErr == ErrAutomationSchedulerUnavailable {
				require.Len(t, h.Entries, 1)
				assert.Equal(t, log.InfoLevel, h.Entries[0].Level)
				assert.Equal(t, tc.agentic, h.Entries[0].Fields["automationAgentsEnabled"])
				assert.Equal(t, tc.database, h.Entries[0].Fields["automationDatabaseConnected"])
			}
		})
	}
}

func TestRunAutomationNowThroughTheWorker(t *testing.T) {
	licenseOAI(t)

	upper := strings.ToUpper(automationTestId)

	cases := []struct {
		name       string
		storedId   string
		callId     string
		registered bool
		wantErr    error
		wantOpened []string
	}{
		{name: "returns the opened run", storedId: automationTestId, callId: automationTestId, wantOpened: []string{automationTestId + ":user-1"}},
		// The registry compares ids as strings, so an uppercase id must still find the registered run.
		{name: "canonicalizes the id", storedId: automationTestId, callId: upper, registered: true, wantErr: database.ErrAutomationRunInFlight},
		// A hand-edited stored id in another form is read canonically, so Run now finds it.
		{name: "finds a stored non-canonical id", storedId: upper, callId: upper, wantOpened: []string{automationTestId + ":user-1"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newEngineFixture(t, storedAutomationWithParams(tc.storedId, `{}`))
				f.ac.startAutomationScheduler()

				if tc.registered {
					release := f.ac.registerAutomationRun(automationTestId, "run-0", func(error) {})
					defer release()
				}

				run, err := f.ac.RunAutomationNow(automationSaveCtx(), tc.callId)

				if tc.wantErr != nil {
					assert.ErrorIs(t, err, tc.wantErr)
				} else {
					require.NoError(t, err)
					assert.Equal(t, "run-1", run.Id)
				}
				assert.ElementsMatch(t, tc.wantOpened, f.openedSeen())
			})
		})
	}
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

func TestStopAutomationRun(t *testing.T) {
	const otherRunId = "6d2b9e10-4c7f-4a3e-9b8d-1f0e2c3a4b5c"

	openRow := func(f *stopFixture) { f.scriptOwnerlessClose(true, nil) }
	noRow := func(f *stopFixture) { f.scriptOwnerlessClose(false, nil) }
	closeFails := func(f *stopFixture) { f.scriptOwnerlessClose(false, errors.New("postgres is down")) }

	// Would fail validation; the turn-off doesn't validate.
	unnamed := storedEnabled(automationTestId)
	unnamed.DisplayName = ""

	cases := []struct {
		name string
		// Defaults to automationTestId stored enabled; deleted stores nothing.
		stored  []*model.Automation
		deleted bool
		setup   func(f *stopFixture)
		// The run in flight, registered under registeredFor (default automationTestId).
		registered    string
		registeredFor string
		// The request is cancelled as soon as the run is.
		cancelRequest bool
		closes        func(f *stopFixture)
		noStore       bool
		updateErr     error
		// Default to automationTestId and stopTestRunId.
		id, runId   string
		disable     bool
		wantErr     error
		wantErrText string
		wantErrs    []string
		// The registered run is marked by user-1 and cancelled as stopped.
		wantStopped bool
		// The automation is written once, turned off.
		wantOff bool
		check   func(t *testing.T, f *stopFixture, h *memory.Handler)
	}{
		{name: "a malformed automation id", registered: stopTestRunId, id: "nope", wantErr: ErrInvalidAutomationParams},
		{name: "a malformed run id", registered: stopTestRunId, runId: "nope", wantErr: ErrInvalidAutomationParams},
		{name: "stops the named run", registered: stopTestRunId, wantStopped: true,
			check: func(t *testing.T, f *stopFixture, h *memory.Handler) {
				assert.Equal(t, log.Fields{
					"automationId":        automationTestId,
					"automationRunId":     stopTestRunId,
					"automationStoppedBy": "user-1",
					"automationDisabled":  false,
				}, lastLoggedFields(h))
			}},
		{name: "canonicalizes ids", registered: stopTestRunId, id: strings.ToUpper(automationTestId), runId: strings.ToUpper(stopTestRunId), wantStopped: true},
		// The engine registers runs under the id as read, which is canonical, so a hand-edited
		// uppercase stored id still reaches the live run and the stored automation.
		{name: "a stored non-canonical id", stored: []*model.Automation{storedEnabled(strings.ToUpper(automationTestId))},
			registered: stopTestRunId, id: strings.ToUpper(automationTestId), disable: true, wantStopped: true, wantOff: true,
			check: func(t *testing.T, f *stopFixture, _ *memory.Handler) {
				written := writtenAutomations(t, f.cfg.updates[0])
				require.Len(t, written, 1, "the stored entry is replaced, not duplicated")
				assert.Equal(t, automationTestId, written[0].Id)
			}},
		{name: "refuses another run", registered: otherRunId, wantErr: ErrAutomationRunNotInFlight},
		{name: "a deleted automation's run", deleted: true, registered: stopTestRunId, wantStopped: true},

		{name: "nothing registered, an open row is closed as stopped", closes: openRow,
			check: func(t *testing.T, _ *stopFixture, h *memory.Handler) {
				assert.Equal(t, stopTestRunId, lastLoggedFields(h)["automationRunId"])
			}},
		{name: "nothing registered, no open row", closes: noRow, wantErr: ErrAutomationRunNotInFlight},
		{name: "nothing registered, no store", noStore: true, wantErr: ErrAutomationRunNotInFlight,
			check: func(t *testing.T, f *stopFixture, _ *memory.Handler) {
				f.mDB.AssertNotCalled(t, "Begin", mock.Anything)
			}},
		{name: "nothing registered, the close fails", closes: closeFails, wantErrText: "postgres is down",
			check: func(t *testing.T, _ *stopFixture, h *memory.Handler) {
				require.NotEmpty(t, h.Entries)
				assert.Equal(t, log.WarnLevel, h.Entries[0].Level)
				assert.Equal(t, stopTestRunId, h.Entries[0].Fields["automationRunId"])
			}},
		{name: "nothing registered, the close fails, the automation is still turned off, and the error is returned",
			closes: closeFails, disable: true, wantErrText: "postgres is down", wantOff: true},
		{name: "nothing registered, the close and the turn-off both fail", closes: closeFails, updateErr: errors.New("salt is down"),
			disable: true, wantErrs: []string{"postgres is down", "salt is down"}},

		{name: "turn off stops the run, then writes only enabled", stored: []*model.Automation{unnamed}, registered: stopTestRunId,
			disable: true, wantStopped: true, wantOff: true,
			setup: func(f *stopFixture) {
				f.cfg.onUpdate = func() {
					assert.Len(t, f.causes, 1, "the run is stopped before the write")
					assert.False(t, f.ac.configWriteMu.TryLock(), "written under configWriteMu")
				}
			},
			check: func(t *testing.T, f *stopFixture, h *memory.Handler) {
				written := writtenAutomations(t, f.cfg.updates[0])[0]
				assert.Empty(t, written.DisplayName)
				assert.Equal(t, unnamed.IntervalSeconds, written.IntervalSeconds)
				assert.Equal(t, unnamed.Agent, written.Agent)
				assert.True(t, f.ac.automationsDirty.Load())
				assert.Equal(t, true, lastLoggedFields(h)["automationDisabled"])
			}},
		{name: "turn off fails to write, and the run is still stopped", registered: stopTestRunId, updateErr: errors.New("salt is down"),
			disable: true, wantErrText: "salt is down", wantStopped: true},
		{name: "turn off with the request cancelled after the stop", registered: stopTestRunId, cancelRequest: true,
			disable: true, wantStopped: true, wantOff: true},
		{name: "turn off naming a run that already ended", closes: noRow, disable: true, wantOff: true},
		{name: "turn off stops a different registered run too", registered: otherRunId, disable: true, wantStopped: true, wantOff: true},
		{name: "turn off leaves an automation already off unwritten", stored: []*model.Automation{storedAutomation(automationTestId, "Nightly")},
			registered: stopTestRunId, disable: true, wantStopped: true,
			check: func(t *testing.T, f *stopFixture, _ *memory.Handler) {
				assert.False(t, f.ac.automationsDirty.Load())
			}},
		{name: "turn off on a never-saved builtin has no stored copy to write", deleted: true,
			setup:      func(f *stopFixture) { seedBuiltinAutomation(f.ac) },
			registered: stopTestRunId, registeredFor: BuiltinAlertTriageAutomationId, id: BuiltinAlertTriageAutomationId,
			disable: true, wantStopped: true},
		{name: "turn off stops a deleted automation's run, then it is not found", deleted: true, registered: stopTestRunId,
			disable: true, wantErr: ErrAutomationNotFound, wantStopped: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stored := tc.stored
			if stored == nil && !tc.deleted {
				stored = []*model.Automation{storedEnabled(automationTestId)}
			}

			f := newStopFixture(t, stored...)
			f.cfg.updateErr = tc.updateErr
			if tc.setup != nil {
				tc.setup(f)
			}
			if tc.closes != nil {
				tc.closes(f)
			}
			if tc.noStore {
				f.ac.store = nil
			}

			logCtx, h := capturedLogger()
			ctx, cancel := context.WithCancel(context.WithValue(logCtx, web.ContextKeyRequestorId, "user-1"))
			defer cancel()

			if tc.registered != "" {
				registeredFor := cmp.Or(tc.registeredFor, automationTestId)
				release := f.ac.registerAutomationRun(registeredFor, tc.registered, func(cause error) {
					f.causes = append(f.causes, cause)
					if tc.cancelRequest {
						cancel()
					}
				})
				defer release()
			}

			err := f.ac.StopAutomationRun(ctx, cmp.Or(tc.id, automationTestId), cmp.Or(tc.runId, stopTestRunId), tc.disable)

			switch {
			case tc.wantErr != nil:
				assert.ErrorIs(t, err, tc.wantErr)
			case tc.wantErrText != "":
				assert.EqualError(t, err, tc.wantErrText)
			case tc.wantErrs != nil:
				for _, want := range tc.wantErrs {
					assert.ErrorContains(t, err, want)
				}
			default:
				require.NoError(t, err)
			}

			if tc.wantStopped {
				assert.Equal(t, []error{ErrAutomationRunStopped}, f.causes)
				assert.Equal(t, []string{tc.registered + ":user-1"}, f.marks)
			} else {
				assert.Empty(t, f.causes)
				assert.Empty(t, f.marks)
			}

			if tc.closes != nil {
				assert.Equal(t, []string{stopTestRunId + ":" + automationTestId + ":user-1"}, f.ownerless)
			} else {
				assert.Empty(t, f.ownerless, "a registered run's row is not closed out from under it")
			}

			if tc.wantOff {
				require.Len(t, f.cfg.updates, 1)
				assert.False(t, writtenAutomations(t, f.cfg.updates[0])[0].Enabled)
			} else {
				assert.Empty(t, f.cfg.updates, "the automation stays as it was")
			}

			if tc.check != nil {
				tc.check(t, f, h)
			}
		})
	}
}
