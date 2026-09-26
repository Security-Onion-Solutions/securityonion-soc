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
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/config"
	mockdb "github.com/security-onion-solutions/securityonion-soc/db/mock"
	"github.com/security-onion-solutions/securityonion-soc/execpool"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/rbac"
	"github.com/security-onion-solutions/securityonion-soc/server"

	"github.com/apex/log"
	"github.com/apex/log/handlers/memory"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// staticRows is a db.Rows whose Next always answers the same, so one scripted expectation
// serves every tick with no cursor shared between goroutines.
type staticRows struct{ next bool }

func (r staticRows) Next() bool        { return r.next }
func (r staticRows) Scan(...any) error { return nil }
func (r staticRows) Err() error        { return nil }
func (r staticRows) Close()            {}

type runClose struct {
	// The close context's state at write time; it is cancelled once the write returns.
	ctxErr              error
	runId, state, cause string
}

// countingConfigstore counts settings reads, which is how a test sees whether a tick re-read
// the automations.
type countingConfigstore struct {
	automationConfigstore

	mu    sync.Mutex
	reads atomic.Int64
}

func (c *countingConfigstore) GetSettings(ctx context.Context, includeDefault bool) ([]*model.Setting, error) {
	c.reads.Add(1)

	c.mu.Lock()
	defer c.mu.Unlock()

	return c.automationConfigstore.GetSettings(ctx, includeDefault)
}

// replace swaps the stored set the way a pillar edit does: nothing is woken, so the lock is
// what orders the write before the next timed read.
func (c *countingConfigstore) replace(settings ...*model.Setting) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.settings = settings
}

// engineFixture is an agentic coordinator whose store reads are scripted so every automation
// is always due, and whose run rows are recorded as they open and close.
type engineFixture struct {
	ac   *AssistantCoordinator
	cfg  *countingConfigstore
	mDB  *mockdb.MockDB
	kind *fakeAutomationKind

	mu     sync.Mutex
	opens  int
	lists  int
	ticks  int
	closes []runClose
	// The live ids each tick's orphan sweep was given.
	sweeps [][]string
}

func newBareEngineFixture(t *testing.T, stored ...*model.Setting) *engineFixture {
	t.Helper()

	f := &engineFixture{
		cfg:  &countingConfigstore{},
		mDB:  &mockdb.MockDB{},
		kind: &fakeAutomationKind{name: "alert_triage"},
	}
	f.cfg.settings = append([]*model.Setting{}, stored...)

	f.ac = &AssistantCoordinator{
		srv: &server.Server{
			Context:     context.Background(),
			Config:      &config.ServerConfig{},
			Configstore: f.cfg,
			Authorizer:  rbac.FakeAuthorizer{Authorized: true},
		},
		isAgentic:             true,
		AutomationKindLibrary: map[string]AutomationKind{"alert_triage": f.kind},
	}
	f.ac.store = automationTestStore(f.mDB)
	f.ac.automationDefaultTickInterval = time.Hour
	f.ac.automationTickInterval.Store(int64(time.Hour))
	f.ac.execPool = f.ac.newExecPool()

	t.Cleanup(func() { require.NoError(t, f.ac.Stop()) })

	return f
}

func newEngineFixture(t *testing.T, stored ...*model.Setting) *engineFixture {
	t.Helper()

	f := newBareEngineFixture(t, stored...)
	f.scriptTicks()
	f.scriptOpenRun()
	f.scriptOpenItems()
	f.scriptCloseRun()

	return f
}

// scriptTicks answers the due query with no history, so every automation is always due, and
// records what each tick's orphan sweep was told is live.
func (f *engineFixture) scriptTicks() {
	f.mDB.On("Query", mock.Anything, sqlLike("FROM unnest($1::uuid[])"), mock.Anything).Run(func(mock.Arguments) {
		f.mu.Lock()
		f.ticks++
		f.mu.Unlock()
	}).Return(staticRows{}, nil)

	f.mDB.On("Query", mock.Anything, orphanSweepSQL, mock.Anything, ErrAutomationDeleted.Error()).
		Run(func(args mock.Arguments) {
			f.mu.Lock()
			f.sweeps = append(f.sweeps, args.Get(2).([]string))
			f.mu.Unlock()
		}).Return(rowsYielding(0), nil)
}

// The tick's sweep reaches pending work only.
var orphanSweepSQL = sqlLike("NOT (automation_id = ANY($1::uuid[]))", "state IN ('pending')")

func (f *engineFixture) sweepsSeen() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([][]string{}, f.sweeps...)
}

func (f *engineFixture) scriptOpenRun() {
	mRow := &mockdb.MockRow{}
	mRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			f.mu.Lock()
			f.opens++
			n := f.opens
			f.mu.Unlock()

			*(args.Get(0).(*string)) = fmt.Sprintf("run-%d", n)
			*(args.Get(1).(*string)) = automationTestId
			*(args.Get(2).(*string)) = string(model.AutomationRunRunning)
		}).Return(nil)

	f.mDB.On("QueryRow", mock.Anything, sqlLike("INSERT INTO automation_runs"), mock.Anything).Return(mRow)
}

func (f *engineFixture) scriptOpenRunInFlight() *mock.Call {
	mRow := &mockdb.MockRow{}
	mRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&pgconn.PgError{Code: "23505", ConstraintName: "idx_automation_runs_one_in_flight"})

	return f.mDB.On("QueryRow", mock.Anything, sqlLike("INSERT INTO automation_runs"), mock.Anything).Return(mRow)
}

// scriptFailAbandonedRun scripts the sweep of an unowned in-flight row and counts its calls.
func (f *engineFixture) scriptFailAbandonedRun(failed int) *atomic.Int32 {
	var calls atomic.Int32

	f.mDB.On("Query", mock.Anything, sqlLike("UPDATE automation_runs", "automation_id = $1 AND ended_at IS NULL"),
		automationTestId, ErrAutomationRunAbandoned.Error()).
		Run(func(mock.Arguments) { calls.Add(1) }).
		Return(rowsYielding(failed), nil)

	return &calls
}

func (f *engineFixture) scriptOpenItems() {
	f.mDB.On("Query", mock.Anything, sqlLike("FROM automation_work_items"), mock.Anything).Run(func(mock.Arguments) {
		f.mu.Lock()
		f.lists++
		f.mu.Unlock()
	}).Return(staticRows{}, nil)
}

func (f *engineFixture) scriptCloseRun() {
	// mock.Anything also matches a missing argument, so the fragment is what keeps the
	// abandoned-run sweep from landing here.
	f.mDB.On("Query", mock.Anything, sqlLike("UPDATE automation_runs", "WHERE id = $1"), mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			f.mu.Lock()
			defer f.mu.Unlock()

			f.closes = append(f.closes, runClose{
				ctxErr: args.Get(0).(context.Context).Err(),
				runId:  args.String(2),
				state:  args.String(3),
				cause:  args.String(4),
			})
		}).Return(staticRows{next: true}, nil)
}

func (f *engineFixture) snapshot() (opens, ticks int, closes []runClose) {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.opens, f.ticks, append([]runClose{}, f.closes...)
}

// startAndWake starts the scheduler and runs its first tick now rather than an interval away.
func (f *engineFixture) startAndWake() {
	f.ac.startAutomationScheduler()
	f.ac.wakeAutomationScheduler()
	synctest.Wait()
}

func storedEnabledAutomation(t *testing.T, id, params string) *model.Setting {
	t.Helper()

	raw, err := json.Marshal(&model.Automation{
		Auditable:       model.Auditable{Id: id, UserId: "user-1"},
		DisplayName:     "Nightly",
		AutomationKind:  "alert_triage",
		Enabled:         true,
		IntervalSeconds: 300,
		Params:          json.RawMessage(params),
	})
	require.NoError(t, err)

	return &model.Setting{Id: automationSettingId(id), Value: string(raw)}
}

func enabledAutomation(id, kind string) *model.Automation {
	return &model.Automation{
		Auditable:       model.Auditable{Id: id},
		AutomationKind:  kind,
		Enabled:         true,
		IntervalSeconds: 300,
	}
}

// Editing a running automation's params reaches the run through the cancel the engine
// registered, and the row records why the run stopped.
func TestSaveAutomationInterruptsTheRunningRun(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newEngineFixture(t, storedEnabledAutomation(t, automationTestId, `{"limit":10}`))

		var mu sync.Mutex
		var causes []error

		f.kind.executeFunc = func(ctx context.Context, run *AutomationRun) error {
			<-ctx.Done()

			mu.Lock()
			causes = append(causes, context.Cause(ctx))
			mu.Unlock()

			// A kind that stops quietly under a params change still leaves a failed row.
			return nil
		}

		f.startAndWake()
		require.True(t, f.ac.isAutomationRunning(automationTestId))

		expectSweep(f.mDB, ErrAutomationParamsChanged, 0)
		require.NoError(t, f.ac.SaveAutomation(automationSaveCtx(), automationWithParams(`{"limit":25}`)))
		synctest.Wait()

		mu.Lock()
		defer mu.Unlock()

		require.NotEmpty(t, causes)
		assert.ErrorIs(t, causes[0], ErrAutomationParamsChanged)

		_, _, closes := f.snapshot()
		require.NotEmpty(t, closes)
		assert.Equal(t, "run-1", closes[0].runId)
		assert.Equal(t, string(model.AutomationRunFailed), closes[0].state)
		assert.Equal(t, ErrAutomationParamsChanged.Error(), closes[0].cause)
	})
}

func TestStartDueAutomationRunsRequiresAStore(t *testing.T) {
	f := newBareEngineFixture(t)
	f.ac.store = nil

	var executed atomic.Bool

	f.kind.executeFunc = func(context.Context, *AutomationRun) error {
		executed.Store(true)

		return nil
	}

	err := f.ac.startDueAutomationRuns(context.Background(), &automationScheduler{ctx: context.Background()}, []*model.Automation{enabledAutomation(automationTestId, "alert_triage")})

	assert.ErrorIs(t, err, ErrNoDatabase)
	assert.False(t, executed.Load())
}

func TestAutomationRunsAreNotPooled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newEngineFixture(t, storedEnabledAutomation(t, automationTestId, `{}`))

		var pool atomic.Pointer[execpool.Pool]

		f.kind.executeFunc = func(ctx context.Context, run *AutomationRun) error {
			pool.Store(run.Pool)

			return nil
		}

		f.startAndWake()

		require.NotNil(t, pool.Load())
		stats := pool.Load().Stats()
		assert.Zero(t, stats.PeakRunning)
		assert.Zero(t, stats.Running)

		_, _, closes := f.snapshot()
		require.Len(t, closes, 1)
		assert.Equal(t, string(model.AutomationRunSucceeded), closes[0].state)
		assert.Empty(t, closes[0].cause)
	})
}

func TestAutomationDue(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		mutate   func(*model.Automation)
		latest   map[string]time.Time
		expected bool
	}{
		{name: "never run", expected: true},
		{name: "started inside the interval", latest: map[string]time.Time{automationTestId: now.Add(-299 * time.Second)}},
		{name: "started one interval ago", latest: map[string]time.Time{automationTestId: now.Add(-300 * time.Second)}, expected: true},
		{name: "only another automation's history", latest: map[string]time.Time{otherAutomationTestId: now}, expected: true},
		{name: "disabled", mutate: func(a *model.Automation) { a.Enabled = false }},
		{name: "zero interval", mutate: func(a *model.Automation) { a.IntervalSeconds = 0 }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			automation := enabledAutomation(automationTestId, "alert_triage")
			if tt.mutate != nil {
				tt.mutate(automation)
			}

			assert.Equal(t, tt.expected, automationDue(automation, tt.latest, now))
		})
	}
}

func TestStartDueAutomationRunsSkipsQuietly(t *testing.T) {
	due := []*model.Automation{enabledAutomation(automationTestId, "alert_triage")}

	t.Run("run registered locally", func(t *testing.T) {
		f := newBareEngineFixture(t)
		f.scriptTicks()

		release := f.ac.registerAutomationRun(automationTestId, func(error) {})
		defer release()

		require.NoError(t, f.ac.startDueAutomationRuns(context.Background(), &automationScheduler{ctx: context.Background()}, due))

		f.mDB.AssertNotCalled(t, "QueryRow", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("unknown kind", func(t *testing.T) {
		f := newBareEngineFixture(t)
		f.scriptTicks()

		require.NoError(t, f.ac.startDueAutomationRuns(context.Background(), &automationScheduler{ctx: context.Background()},
			[]*model.Automation{enabledAutomation(automationTestId, "no_such_kind")}))

		f.mDB.AssertNotCalled(t, "QueryRow", mock.Anything, mock.Anything, mock.Anything)
	})
}

func TestAutomationRunCarriesItsPlumbing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newEngineFixture(t, storedEnabledAutomation(t, automationTestId, `{}`))

		var got atomic.Pointer[AutomationRun]

		f.kind.executeFunc = func(ctx context.Context, run *AutomationRun) error {
			got.Store(run)

			return nil
		}

		f.startAndWake()

		run := got.Load()
		require.NotNil(t, run)
		assert.Equal(t, "run-1", run.RunId)
		assert.Equal(t, automationTestId, run.Task.Id)
		assert.Same(t, f.ac.srv, run.Srv)
		assert.Equal(t, f.ac.store, run.Store)
		assert.NotNil(t, run.Pool)
		assert.Empty(t, run.OpenItems)

		f.mu.Lock()
		defer f.mu.Unlock()
		assert.Equal(t, 1, f.lists, "open items are read for the run")
	})
}

func TestAutomationRunPanicClosesFailedAndWorkerSurvives(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newEngineFixture(t, storedEnabledAutomation(t, automationTestId, `{}`))

		f.kind.executeFunc = func(context.Context, *AutomationRun) error { panic("boom") }

		f.startAndWake()

		_, _, closes := f.snapshot()
		require.Len(t, closes, 1)
		assert.Equal(t, string(model.AutomationRunFailed), closes[0].state)
		assert.Contains(t, closes[0].cause, "panicked")
		assert.Contains(t, closes[0].cause, "boom")
		assert.False(t, f.ac.isAutomationRunning(automationTestId))

		f.ac.wakeAutomationScheduler()
		synctest.Wait()

		opens, ticks, _ := f.snapshot()
		assert.Equal(t, 2, ticks)
		assert.Equal(t, 2, opens)
	})
}

func TestAutomationRunClosesWithADetachedContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newEngineFixture(t, storedEnabledAutomation(t, automationTestId, `{}`))

		f.kind.executeFunc = func(ctx context.Context, _ *AutomationRun) error {
			<-ctx.Done()

			return ctx.Err()
		}

		f.startAndWake()
		f.ac.interruptAutomationRun(automationTestId)
		synctest.Wait()

		_, _, closes := f.snapshot()
		require.Len(t, closes, 1)
		assert.NoError(t, closes[0].ctxErr)
		assert.Equal(t, string(model.AutomationRunFailed), closes[0].state)
		assert.Equal(t, ErrAutomationParamsChanged.Error(), closes[0].cause)
	})
}

func TestAutomationConfigChangeWakes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newEngineFixture(t)

		f.ac.startAutomationScheduler()
		synctest.Wait()

		_, ticks, _ := f.snapshot()
		assert.Zero(t, ticks, "the first tick waits an interval")

		f.ac.OnConfigSettingUpdated(context.Background(), &model.Setting{Id: automationSettingId(automationTestId)}, false)
		synctest.Wait()

		_, ticks, _ = f.snapshot()
		assert.Equal(t, 1, ticks, "a config change ticks now")
		assert.EqualValues(t, 1, f.cfg.reads.Load())

		time.Sleep(time.Hour)
		synctest.Wait()
		time.Sleep(time.Hour)
		synctest.Wait()

		_, ticks, _ = f.snapshot()
		assert.Equal(t, 3, ticks)
		assert.EqualValues(t, 3, f.cfg.reads.Load(), "every tick reads the stored set")
	})
}

// A definition added straight in pillar raises no callback; the next tick's read is what
// finds it.
func TestEveryTickReadsTheStoredAutomations(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newEngineFixture(t)

		f.ac.startAutomationScheduler()
		synctest.Wait()

		f.cfg.replace(storedEnabledAutomation(t, automationTestId, `{}`))

		time.Sleep(time.Hour)
		synctest.Wait()

		opens, _, _ := f.snapshot()
		assert.Equal(t, 1, opens)
		assert.EqualValues(t, 1, f.cfg.reads.Load())
	})
}

// A save that lands while the tick is reading would otherwise open a run on the definitions
// read before it; the tick leaves the open to the tick the save woke.
func TestASaveDuringTheTickReadDefersTheOpen(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newBareEngineFixture(t, storedEnabledAutomation(t, automationTestId, `{"limit":10}`))

		release := make(chan struct{})

		f.mDB.On("Query", mock.Anything, sqlLike("FROM unnest"), mock.Anything).
			Run(func(mock.Arguments) { <-release }).Return(staticRows{}, nil).Once()
		f.scriptTicks()
		f.scriptOpenRun()
		f.scriptOpenItems()
		f.scriptCloseRun()

		var params atomic.Pointer[json.RawMessage]

		f.kind.executeFunc = func(_ context.Context, run *AutomationRun) error {
			params.Store(&run.Task.Params)

			return nil
		}

		f.startAndWake()

		// The fake store only records writes; the next read has to return this one.
		f.cfg.onUpdate = func() { f.cfg.settings = f.cfg.updates[len(f.cfg.updates)-1:] }

		edit := automationWithParams(`{"limit":25}`)
		edit.Enabled = true

		expectSweep(f.mDB, ErrAutomationParamsChanged, 0)
		require.NoError(t, f.ac.SaveAutomation(automationSaveCtx(), edit))

		close(release)
		synctest.Wait()

		opens, _, _ := f.snapshot()
		assert.Equal(t, 1, opens, "the read the save raced opens nothing; the wake it sent does")
		require.NotNil(t, params.Load())
		assert.JSONEq(t, `{"limit":25}`, string(*params.Load()))
	})
}

// A row the in-flight index protects but no run here owns is one an open lost the result of or
// a close could not end; failing it is what lets the automation run again before a restart.
func TestAnAbandonedRunIsFailedSoTheNextTickCanOpen(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newBareEngineFixture(t, storedEnabledAutomation(t, automationTestId, `{}`))
		f.scriptTicks()
		f.scriptOpenRunInFlight().Once()
		f.scriptOpenRun()
		f.scriptOpenItems()
		f.scriptCloseRun()
		failed := f.scriptFailAbandonedRun(1)

		f.startAndWake()

		opens, _, _ := f.snapshot()
		assert.Zero(t, opens)
		assert.EqualValues(t, 1, failed.Load())
		assert.False(t, f.ac.isAutomationRunning(automationTestId))

		time.Sleep(time.Hour)
		synctest.Wait()

		opens, _, _ = f.snapshot()
		assert.Equal(t, 1, opens, "the row is gone, so the next open succeeds")
		assert.EqualValues(t, 1, failed.Load())
	})
}

func TestAutomationTickIntervalHotReload(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newEngineFixture(t)

		f.ac.reloadAutomationTickInterval(context.Background())
		assert.Equal(t, time.Hour, f.ac.getAutomationTickInterval(), "an absent setting is the Init value")

		tick := &model.Setting{Id: ConfigSettingAutomationTickInterval, Value: "60"}
		f.cfg.settings = append(f.cfg.settings, tick)

		f.ac.startAutomationScheduler()
		synctest.Wait()

		f.ac.OnConfigSettingUpdated(context.Background(), tick, false)
		synctest.Wait()

		assert.Equal(t, time.Minute, f.ac.getAutomationTickInterval())
		_, ticks, _ := f.snapshot()
		assert.Equal(t, 1, ticks, "a changed interval ticks now")

		time.Sleep(time.Minute)
		synctest.Wait()

		_, ticks, _ = f.snapshot()
		assert.Equal(t, 2, ticks, "the ticker re-armed on the new interval")

		tick.Value = "0"
		f.ac.OnConfigSettingUpdated(context.Background(), tick, false)
		synctest.Wait()

		assert.Equal(t, time.Minute, f.ac.getAutomationTickInterval())
		_, ticks, _ = f.snapshot()
		assert.Equal(t, 2, ticks, "a rejected value neither re-arms nor ticks")

		f.cfg.settings = f.cfg.settings[:len(f.cfg.settings)-1]
		f.ac.OnConfigSettingUpdated(context.Background(), tick, true)
		synctest.Wait()

		assert.Equal(t, time.Hour, f.ac.getAutomationTickInterval(), "a removed setting restores the Init value")
		_, ticks, _ = f.snapshot()
		assert.Equal(t, 3, ticks, "the restored interval ticks now")
	})
}

func TestStopCancelsRunsAndShutsDownThePool(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newEngineFixture(t, storedEnabledAutomation(t, automationTestId, `{}`))

		f.kind.executeFunc = func(ctx context.Context, _ *AutomationRun) error {
			<-ctx.Done()

			return context.Cause(ctx)
		}

		f.startAndWake()
		require.True(t, f.ac.isAutomationRunning(automationTestId))

		pool := f.ac.execPool
		require.NoError(t, f.ac.Stop())

		_, _, closes := f.snapshot()
		assert.Empty(t, closes, "a stopped run leaves its row for the next start's reconcile")
		assert.False(t, f.ac.isAutomationRunning(automationTestId))

		_, err := pool.Submit(execpool.Job{Run: func(context.Context) error { return nil }})
		assert.ErrorIs(t, err, execpool.ErrShutdown)
		assert.Nil(t, f.ac.automationScheduler)
	})
}

// A kind that ignores its context holds Stop for the budget and no longer.
func TestStopIsBoundedWhenARunIgnoresCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newEngineFixture(t, storedEnabledAutomation(t, automationTestId, `{}`))

		release := make(chan struct{})
		f.kind.executeFunc = func(context.Context, *AutomationRun) error {
			<-release

			return nil
		}

		f.startAndWake()
		require.True(t, f.ac.isAutomationRunning(automationTestId))

		start := time.Now()
		require.NoError(t, f.ac.Stop())
		assert.Equal(t, AUTOMATION_STOP_TIMEOUT, time.Since(start))
		assert.Nil(t, f.ac.automationScheduler)

		close(release)
		synctest.Wait()

		_, _, closes := f.snapshot()
		assert.Empty(t, closes, "a run that finishes after the stop still writes nothing")
		assert.False(t, f.ac.isAutomationRunning(automationTestId))
	})
}

// Pool work queued or submitted at stop fails without starting, and nothing is requeued.
func TestStopFailsQueuedWorkWithoutWriting(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newEngineFixture(t, storedEnabledAutomation(t, automationTestId, `{}`))
		f.ac.automationMaxConcurrentItems = 1
		f.ac.execPool = f.ac.newExecPool()

		store := &claimingStore{}
		var second *execpool.Handle
		var secondRan, thirdRan atomic.Bool
		var third atomic.Pointer[execpool.Handle]

		f.kind.executeFunc = func(ctx context.Context, run *AutomationRun) error {
			store.AutomationStore = run.Store
			run.Store = store

			first, err := run.Submit(ctx, "Hunter", &model.AutomationWorkItem{Id: "item-1"}, func(ctx context.Context, _ *model.AutomationWorkItem) error {
				<-ctx.Done()

				return context.Cause(ctx)
			})
			assert.NoError(t, err)

			second, err = run.Submit(ctx, "Hunter", &model.AutomationWorkItem{Id: "item-2"}, func(context.Context, *model.AutomationWorkItem) error {
				secondRan.Store(true)

				return nil
			})
			assert.NoError(t, err)

			awaitErr := run.Await([]*execpool.Handle{first, second})

			handle, err := run.Submit(ctx, "Hunter", &model.AutomationWorkItem{Id: "item-3"}, func(context.Context, *model.AutomationWorkItem) error {
				thirdRan.Store(true)

				return nil
			})
			assert.NoError(t, err)
			third.Store(handle)

			return awaitErr
		}

		f.startAndWake()
		require.True(t, f.ac.isAutomationRunning(automationTestId))
		assert.Equal(t, execpool.KeyStats{Running: 1, Queued: 1}, f.ac.execPool.Stats().Keys["Hunter"])

		require.NoError(t, f.ac.Stop())

		require.NotNil(t, second)
		assert.ErrorIs(t, second.Err(), ErrAutomationSchedulerStopped)
		assert.False(t, secondRan.Load(), "queued work is failed, not run to observe the cancellation")
		require.NotNil(t, third.Load())
		<-third.Load().Done()
		assert.ErrorIs(t, third.Load().Err(), ErrAutomationSchedulerStopped)
		assert.False(t, thirdRan.Load())
		assert.Empty(t, store.requeued, "work failed at shutdown is not requeued")

		_, _, closes := f.snapshot()
		assert.Empty(t, closes)
	})
}

func TestAutomationSchedulerLifecycle(t *testing.T) {
	t.Run("start is idempotent and stop repeats safely", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := newEngineFixture(t)

			f.ac.startAutomationScheduler()
			running := f.ac.automationScheduler
			require.NotNil(t, running)

			f.ac.startAutomationScheduler()
			assert.Same(t, running, f.ac.automationScheduler)

			f.ac.stopAutomationScheduler(t.Context())
			assert.Nil(t, f.ac.automationScheduler)
			assert.NotPanics(t, func() { f.ac.stopAutomationScheduler(t.Context()) })
		})
	})

	t.Run("stays idle where nothing could run", func(t *testing.T) {
		tests := []struct {
			name  string
			setup func(*engineFixture)
		}{
			{"airgapped", func(f *engineFixture) { f.ac.srv.Config.AirgapEnabled = true }},
			{"not agentic", func(f *engineFixture) { f.ac.isAgentic = false }},
			{"no database", func(f *engineFixture) { f.ac.store = nil }},
			{"no tick interval", func(f *engineFixture) { f.ac.automationTickInterval.Store(0) }},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newBareEngineFixture(t)
				tt.setup(f)

				f.ac.startAutomationScheduler()

				assert.Nil(t, f.ac.automationScheduler)
			})
		}
	})

	t.Run("zero value coordinator", func(t *testing.T) {
		assert.NotPanics(t, func() { (&AssistantCoordinator{}).stopAutomationScheduler(t.Context()) })
	})
}

func TestAgentConcurrencyLimit(t *testing.T) {
	ac := &AssistantCoordinator{}
	assert.Zero(t, ac.agentConcurrencyLimit("Hunter"), "no agents loaded")

	ac.agents = map[string]model.Agent{"Hunter": {MaxConcurrentInstances: 2}}
	assert.Equal(t, 2, ac.agentConcurrencyLimit("Hunter"))
	assert.Zero(t, ac.agentConcurrencyLimit("Unknown"))
}

// The create path registers its config watch after the write, so the save itself has to
// wake the scheduler; edits and deletes wake it too rather than relying on the callback.
func TestSaveAndDeleteAutomationWakeTheScheduler(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{storedAutomation(t, automationTestId, "Nightly")}

	ac := automationCoordinator(cfg)
	ac.automationScheduler = &automationScheduler{wake: make(chan struct{}, 1)}

	woke := func() bool {
		defer ac.automationsDirty.Store(false)

		select {
		case <-ac.automationScheduler.wake:
			return ac.automationsDirty.Load()
		default:
			return false
		}
	}

	edit := validAutomation()
	edit.Id = automationTestId
	require.NoError(t, ac.SaveAutomation(automationSaveCtx(), edit))
	assert.True(t, woke(), "edit")

	require.NoError(t, ac.SaveAutomation(automationSaveCtx(), validAutomation()))
	assert.True(t, woke(), "create")

	require.NoError(t, ac.DeleteAutomation(automationSaveCtx(), automationTestId))
	assert.True(t, woke(), "delete")
}

func TestAssistantCoordinator_Init_AutomationEngineConfig(t *testing.T) {
	newAC := func() *AssistantCoordinator {
		return NewAssistantCoordinator(&server.Server{
			Context: context.Background(),
			Config:  &config.ServerConfig{ClientParams: model.ClientParameters{AssistantParams: model.AssistantParameters{}}},
		})
	}

	ac := newAC()
	require.NoError(t, ac.Init(module.ModuleConfig{}))
	assert.Equal(t, DEFAULT_AUTOMATION_TICK_INTERVAL_SECONDS*time.Second, ac.getAutomationTickInterval())
	assert.Equal(t, DEFAULT_AUTOMATION_MAX_CONCURRENT_ITEMS, ac.automationMaxConcurrentItems)
	assert.Equal(t, DEFAULT_AUTOMATION_MAX_QUEUED_ITEMS, ac.automationMaxQueuedItems)

	ac = newAC()
	require.NoError(t, ac.Init(module.ModuleConfig{
		"automationTickIntervalSeconds": float64(15),
		"automationMaxConcurrentItems":  float64(2),
		"automationMaxQueuedItems":      float64(-5),
	}))
	assert.Equal(t, 15*time.Second, ac.getAutomationTickInterval())
	assert.Equal(t, 15*time.Second, ac.automationDefaultTickInterval)
	assert.Equal(t, 2, ac.automationMaxConcurrentItems)
	assert.Zero(t, ac.automationMaxQueuedItems, "negative clamps to unlimited")

	// A non-positive tick only matters where the scheduler would run.
	ac = newAC()
	require.NoError(t, ac.Init(module.ModuleConfig{"automationTickIntervalSeconds": float64(0)}))

	stubEmbeddedSystemPrompt(t)
	ac, _ = newAgenticTestCoordinator()
	assert.ErrorContains(t, ac.Init(module.ModuleConfig{"agentic": true, "automationTickIntervalSeconds": float64(0)}),
		"automationTickIntervalSeconds")
}

// The due query blocks until its context ends, so the tick's deadline is what frees the worker;
// a config write is not held up meanwhile.
func TestAutomationTickIsBoundedByTheInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newBareEngineFixture(t)

		var cause error

		f.mDB.On("Query", mock.Anything, sqlLike("FROM unnest"), mock.Anything).Run(func(args mock.Arguments) {
			ctx := args.Get(0).(context.Context)
			<-ctx.Done()
			cause = ctx.Err()
		}).Return(staticRows{}, nil).Once()
		f.scriptTicks()

		f.startAndWake()
		require.True(t, f.ac.configWriteMu.TryLock(), "a stuck read does not hold configWriteMu")
		f.ac.configWriteMu.Unlock()

		time.Sleep(time.Hour)
		synctest.Wait()

		assert.ErrorIs(t, cause, context.DeadlineExceeded)
	})
}

// A definition removed from pillar never passes through DeleteAutomation, so the tick's sweep
// of work outside the live set is what drops its queued work.
func TestTickSweepsAutomationsRemovedFromConfig(t *testing.T) {
	remove := func(f *engineFixture) {
		f.cfg.settings = []*model.Setting{storedEnabledAutomation(t, otherAutomationTestId, `{}`)}
		f.ac.OnConfigSettingUpdated(context.Background(), &model.Setting{Id: automationSettingId(automationTestId)}, true)
		synctest.Wait()
	}

	stored := func(t *testing.T) []*model.Setting {
		return []*model.Setting{
			storedEnabledAutomation(t, automationTestId, `{}`),
			storedEnabledAutomation(t, otherAutomationTestId, `{}`),
		}
	}

	t.Run("the removed automation leaves the live set", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := newEngineFixture(t, stored(t)...)
			f.startAndWake()

			sweeps := f.sweepsSeen()
			require.Len(t, sweeps, 1)
			assert.ElementsMatch(t, []string{automationTestId, otherAutomationTestId}, sweeps[0])

			remove(f)

			sweeps = f.sweepsSeen()
			require.Len(t, sweeps, 2)
			assert.Equal(t, []string{otherAutomationTestId}, sweeps[1])

			time.Sleep(time.Hour)
			synctest.Wait()

			opens, _, _ := f.snapshot()
			assert.Equal(t, 4, opens, "only the remaining automation runs again")
		})
	})

	t.Run("a failed sweep skips the tick and retries", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := newBareEngineFixture(t, stored(t)...)

			afterRemoval := mock.MatchedBy(func(ids []string) bool { return len(ids) == 1 })
			f.mDB.On("Query", mock.Anything, orphanSweepSQL, afterRemoval, ErrAutomationDeleted.Error()).
				Return(rowsYielding(0), errors.New("db down")).Once()

			f.scriptTicks()
			f.scriptOpenRun()
			f.scriptOpenItems()
			f.scriptCloseRun()

			f.startAndWake()

			opens, _, _ := f.snapshot()
			require.Equal(t, 2, opens)

			remove(f)

			opens, _, _ = f.snapshot()
			assert.Equal(t, 2, opens, "the tick that could not sweep starts nothing")
			assert.Len(t, f.sweepsSeen(), 1, "the failed sweep is not the scripted success")

			time.Sleep(time.Hour)
			synctest.Wait()

			opens, _, _ = f.snapshot()
			assert.Equal(t, 3, opens, "the next tick sweeps and runs the remaining automation")
			assert.Equal(t, []string{otherAutomationTestId}, f.sweepsSeen()[1])
		})
	})

	// A malformed value is indistinguishable from a removed one, so the sweep waits for it to
	// be readable again rather than dropping its work as deleted.
	t.Run("an unreadable automation holds the sweep", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := newEngineFixture(t,
				storedEnabledAutomation(t, automationTestId, `{}`),
				&model.Setting{Id: automationSettingId(otherAutomationTestId), Value: "not json"},
			)
			f.startAndWake()

			assert.Empty(t, f.sweepsSeen())

			opens, _, _ := f.snapshot()
			assert.Equal(t, 1, opens, "the readable automation still runs")
		})
	})
}

// claimingStore hands out scripted items oldest first and records what comes back.
type claimingStore struct {
	AutomationStore

	items    []*model.AutomationWorkItem
	claimErr error
	requeued []string
}

func (s *claimingStore) ClaimNextAutomationWorkItem(ctx context.Context, automationId, runId string) (*model.AutomationWorkItem, error) {
	if s.claimErr != nil || len(s.items) == 0 {
		return nil, s.claimErr
	}

	item := s.items[0]
	s.items = s.items[1:]
	item.RunId = runId
	item.State = model.AutomationWorkItemRunning

	return item, nil
}

func (s *claimingStore) RequeueAutomationWorkItem(ctx context.Context, itemId, cause string) error {
	s.requeued = append(s.requeued, itemId+": "+cause)

	return nil
}

func claimingRun(t *testing.T, store *claimingStore, cfg execpool.Config) *AutomationRun {
	t.Helper()

	pool := execpool.New(context.Background(), cfg)
	t.Cleanup(func() { _ = pool.Shutdown(context.Background()) })

	return &AutomationRun{
		Task:  enabledAutomation(automationTestId, "alert_triage"),
		RunId: "run-1",
		Store: store,
		Pool:  pool,
	}
}

func TestClaimAndSubmitDedupesOnTheClaimedItem(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &claimingStore{items: []*model.AutomationWorkItem{{Id: "item-old"}, {Id: "item-new"}}}
		run := claimingRun(t, store, execpool.Config{Name: "test", KeyLimitFunc: func(string) int { return 1 }})

		release := make(chan struct{})
		var worked atomic.Pointer[model.AutomationWorkItem]

		item, handle, err := run.ClaimAndSubmit(context.Background(), "Hunter", func(ctx context.Context, item *model.AutomationWorkItem) error {
			worked.Store(item)
			<-release

			return nil
		})
		require.NoError(t, err)
		require.NotNil(t, handle)
		assert.Equal(t, "item-old", item.Id, "the oldest pending item is taken first")
		assert.Equal(t, "run-1", item.RunId)

		synctest.Wait()
		assert.Same(t, item, worked.Load(), "the job works the item it was built from")
		assert.Equal(t, execpool.KeyStats{Running: 1}, run.Pool.Stats().Keys["Hunter"])

		_, err = run.Pool.Submit(execpool.Job{Key: "Hunter", DedupeKey: item.Id, Run: func(context.Context) error { return nil }})
		assert.ErrorIs(t, err, execpool.ErrDuplicate, "the dedupe key is the claimed item's id")

		next, _, err := run.ClaimAndSubmit(context.Background(), "Hunter", func(context.Context, *model.AutomationWorkItem) error { return nil })
		require.NoError(t, err)
		assert.Equal(t, "item-new", next.Id)
		assert.Equal(t, execpool.KeyStats{Running: 1, Queued: 1}, run.Pool.Stats().Keys["Hunter"])

		close(release)
		require.NoError(t, handle.Wait(context.Background()))
		assert.Empty(t, store.requeued)
	})
}

func TestClaimAndSubmitWithNothingPending(t *testing.T) {
	store := &claimingStore{}
	run := claimingRun(t, store, execpool.Config{Name: "test"})

	item, handle, err := run.ClaimAndSubmit(context.Background(), "Hunter", func(context.Context, *model.AutomationWorkItem) error { return nil })

	assert.NoError(t, err)
	assert.Nil(t, item)
	assert.Nil(t, handle)
	assert.Zero(t, run.Pool.Stats().Queued)
}

func TestClaimAndSubmitReportsClaimErrors(t *testing.T) {
	store := &claimingStore{claimErr: errors.New("postgres is down")}
	run := claimingRun(t, store, execpool.Config{Name: "test"})

	_, _, err := run.ClaimAndSubmit(context.Background(), "Hunter", func(context.Context, *model.AutomationWorkItem) error { return nil })

	assert.EqualError(t, err, "postgres is down")
}

// A claim the pool refuses would otherwise sit running with nothing running it.
func TestClaimAndSubmitRequeuesWhatThePoolRefuses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &claimingStore{items: []*model.AutomationWorkItem{{Id: "item-1"}, {Id: "item-2"}, {Id: "item-3"}}}
		run := claimingRun(t, store, execpool.Config{Name: "test", MaxConcurrent: 1, MaxQueueDepth: 1})

		release := make(chan struct{})
		block := func(context.Context, *model.AutomationWorkItem) error {
			<-release

			return nil
		}

		_, first, err := run.ClaimAndSubmit(context.Background(), "Hunter", block)
		require.NoError(t, err)
		_, _, err = run.ClaimAndSubmit(context.Background(), "Hunter", block)
		require.NoError(t, err)

		item, handle, err := run.ClaimAndSubmit(context.Background(), "Hunter", block)

		assert.ErrorIs(t, err, execpool.ErrQueueFull)
		assert.Nil(t, handle)
		require.NotNil(t, item)
		assert.Equal(t, []string{"item-3: " + execpool.ErrQueueFull.Error()}, store.requeued)

		close(release)
		require.NoError(t, first.Wait(context.Background()))
	})
}

// The job that holds a duplicate is still running it; a requeue would reset that claim under it.
func TestSubmitDoesNotRequeueADuplicate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &claimingStore{}
		run := claimingRun(t, store, execpool.Config{Name: "test"})
		item := &model.AutomationWorkItem{Id: "item-1"}

		release := make(chan struct{})
		block := func(context.Context, *model.AutomationWorkItem) error {
			<-release

			return nil
		}

		handle, err := run.Submit(context.Background(), "Hunter", item, block)
		require.NoError(t, err)

		dup, err := run.Submit(context.Background(), "Hunter", item, block)

		assert.ErrorIs(t, err, execpool.ErrDuplicate)
		assert.Nil(t, dup)
		assert.Empty(t, store.requeued)

		close(release)
		require.NoError(t, handle.Wait(context.Background()))
	})
}

// capturedLogger returns a context whose logger records into the handler, and the fields of
// the last line logged through it: an entry's fields are only merged when a line is emitted.
func capturedLogger() (context.Context, *memory.Handler) {
	h := memory.New()

	return log.NewContext(context.Background(), &log.Logger{Handler: h, Level: log.DebugLevel}), h
}

func lastLoggedFields(h *memory.Handler) log.Fields {
	if len(h.Entries) == 0 {
		return nil
	}

	return h.Entries[len(h.Entries)-1].Fields
}

func TestAutomationRunContextCarriesItsLogger(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newEngineFixture(t, storedEnabledAutomation(t, automationTestId, `{}`))
		ctx, h := capturedLogger()
		f.ac.srv.Context = ctx

		f.kind.executeFunc = func(ctx context.Context, _ *AutomationRun) error {
			log.FromContext(ctx).Info("probe")

			return nil
		}

		f.startAndWake()

		var probe log.Fields
		for _, entry := range h.Entries {
			if entry.Message == "probe" {
				probe = entry.Fields
			}
		}

		require.NotNil(t, probe)
		assert.Equal(t, automationTestId, probe["automationId"])
		assert.Equal(t, "run-1", probe["automationRunId"])
	})
}

func TestSubmitNamesTheItemInTheJobLogger(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &claimingStore{}
		run := claimingRun(t, store, execpool.Config{Name: "test"})
		item := &model.AutomationWorkItem{Id: "item-7", GroupKey: "rule.name:Foo", State: model.AutomationWorkItemApplying}

		ctx, h := capturedLogger()
		ctx = log.NewContext(ctx, log.FromContext(ctx).WithField("automationRunId", "run-1"))

		handle, err := run.Submit(ctx, "Hunter", item, func(ctx context.Context, got *model.AutomationWorkItem) error {
			assert.Same(t, item, got)
			log.FromContext(ctx).Info("probe")

			return nil
		})
		require.NoError(t, err)
		require.NoError(t, run.Await([]*execpool.Handle{handle}))

		fields := lastLoggedFields(h)
		require.NotNil(t, fields)
		assert.Equal(t, "run-1", fields["automationRunId"])
		assert.Equal(t, "item-7", fields["workItemId"])
		assert.Equal(t, "rule.name:Foo", fields["groupKey"])
		assert.Empty(t, store.requeued)
	})
}

func TestAwaitJoinsEveryJobError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &claimingStore{}
		run := claimingRun(t, store, execpool.Config{Name: "test"})

		var handles []*execpool.Handle

		for _, outcome := range []error{nil, errors.New("first"), nil, errors.New("second")} {
			handle, err := run.Submit(context.Background(), "Hunter", &model.AutomationWorkItem{Id: fmt.Sprint(len(handles))},
				func(context.Context, *model.AutomationWorkItem) error { return outcome })
			require.NoError(t, err)

			handles = append(handles, handle)
		}

		err := run.Await(handles)

		require.Error(t, err)
		assert.ErrorContains(t, err, "first")
		assert.ErrorContains(t, err, "second")
		assert.NoError(t, run.Await(nil))
	})
}

func TestAutomationEngineStatus(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newEngineFixture(t, storedEnabledAutomation(t, automationTestId, `{}`))

		status := f.ac.getAutomationEngineStatus()
		assert.False(t, status.Running)
		assert.Empty(t, status.ActiveAutomationIds)

		release := make(chan struct{})
		f.kind.executeFunc = func(ctx context.Context, _ *AutomationRun) error {
			<-release

			return nil
		}

		f.startAndWake()

		status = f.ac.getAutomationEngineStatus()
		assert.True(t, status.Running)
		assert.Equal(t, []string{automationTestId}, status.ActiveAutomationIds)
		assert.Zero(t, status.Pool.Running)

		close(release)
		synctest.Wait()

		assert.Empty(t, f.ac.getAutomationEngineStatus().ActiveAutomationIds)
	})
}
