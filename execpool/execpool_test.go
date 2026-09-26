// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package execpool

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/apex/log"
	"github.com/apex/log/handlers/discard"
	"github.com/stretchr/testify/assert"
)

// gate holds every job it hands out until open is called, so a test can inspect the
// pool while a known set of jobs is in flight.
type gate struct {
	mu      sync.Mutex
	started []string
	release chan struct{}
}

func newGate() *gate {
	return &gate{release: make(chan struct{})}
}

func (g *gate) job(key string) func(context.Context) error {
	return func(ctx context.Context) error {
		g.mu.Lock()
		g.started = append(g.started, key)
		g.mu.Unlock()

		select {
		case <-g.release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (g *gate) open() {
	close(g.release)
}

func (g *gate) startedKeys() []string {
	g.mu.Lock()
	defer g.mu.Unlock()

	return slices.Clone(g.started)
}

// newPool builds a pool inside the caller's bubble and guarantees it is shut down
// before the bubble exits, so synctest's "all goroutines must exit" check is a real
// leak assertion on every test that uses it.
func newPool(t *testing.T, cfg Config) *Pool {
	t.Helper()

	p := New(t.Context(), cfg)

	t.Cleanup(func() {
		assert.NoError(t, p.Shutdown(context.Background()))
	})

	return p
}

func submit(t *testing.T, p *Pool, job Job) *Handle {
	t.Helper()

	h, err := p.Submit(job)
	assert.NoError(t, err)

	return h
}

func TestPool_FIFOOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPool(t, Config{Name: "test", MaxConcurrent: 1})

		var mu sync.Mutex
		var order []string

		record := func(key string) func(context.Context) error {
			return func(context.Context) error {
				mu.Lock()
				order = append(order, key)
				mu.Unlock()

				return nil
			}
		}

		for _, key := range []string{"a", "b", "c"} {
			submit(t, p, Job{Key: key, Run: record(key)})
		}

		synctest.Wait()

		assert.Equal(t, []string{"a", "b", "c"}, order)
	})
}

func TestPool_GlobalLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPool(t, Config{Name: "test", MaxConcurrent: 2})
		g := newGate()

		for range 5 {
			submit(t, p, Job{Key: "a", Run: g.job("a")})
		}

		synctest.Wait()

		stats := p.Stats()
		assert.Equal(t, 2, stats.Running)
		assert.Equal(t, 3, stats.Queued)

		g.open()
		synctest.Wait()

		assert.Equal(t, 0, p.Stats().Running)
		assert.Len(t, g.startedKeys(), 5)
	})
}

func TestPool_ZeroMeansUnlimited(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPool(t, Config{Name: "test"})
		g := newGate()

		for range 5 {
			submit(t, p, Job{Key: "a", Run: g.job("a")})
		}

		synctest.Wait()

		stats := p.Stats()
		assert.Equal(t, 5, stats.Running)
		assert.Equal(t, 0, stats.Queued)

		g.open()
	})
}

func TestPool_KeyLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPool(t, Config{
			Name: "test",
			KeyLimitFunc: func(key string) int {
				if key == "a" {
					return 1
				}

				return 0 // unlimited
			},
		})
		g := newGate()

		for range 3 {
			submit(t, p, Job{Key: "a", Run: g.job("a")})
			submit(t, p, Job{Key: "b", Run: g.job("b")})
		}

		synctest.Wait()

		stats := p.Stats()
		assert.Equal(t, KeyStats{Running: 1, Queued: 2}, stats.Keys["a"])
		assert.Equal(t, KeyStats{Running: 3, Queued: 0}, stats.Keys["b"])

		g.open()
	})
}

func TestPool_KeyLimitHotReload(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var limit atomic.Int64
		limit.Store(1)

		p := newPool(t, Config{
			Name:         "test",
			KeyLimitFunc: func(string) int { return int(limit.Load()) },
		})
		g := newGate()

		for range 3 {
			submit(t, p, Job{Key: "a", Run: g.job("a")})
		}

		synctest.Wait()
		assert.Equal(t, 1, p.Stats().Running)

		// Raising the limit does not itself dispatch; the pool cannot observe the
		// change. The next Submit or completion picks it up.
		limit.Store(3)
		synctest.Wait()
		assert.Equal(t, 1, p.Stats().Running)

		submit(t, p, Job{Key: "b", Run: g.job("b")})
		synctest.Wait()

		assert.Equal(t, 4, p.Stats().Running)

		g.open()
	})
}

func TestPool_SaturatedKeyDoesNotBlockOthers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPool(t, Config{
			Name: "test",
			KeyLimitFunc: func(key string) int {
				if key == "a" {
					return 1
				}

				return 0
			},
		})
		g := newGate()

		for range 3 {
			submit(t, p, Job{Key: "a", Run: g.job("a")})
		}

		submit(t, p, Job{Key: "b", Run: g.job("b")})

		synctest.Wait()

		// "b" was queued behind two blocked "a" jobs; strict FIFO would have stalled it.
		assert.Contains(t, g.startedKeys(), "b")
		assert.Equal(t, KeyStats{Running: 1, Queued: 2}, p.Stats().Keys["a"])

		g.open()
	})
}

func TestPool_QueueFull(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPool(t, Config{Name: "test", MaxConcurrent: 1, MaxQueueDepth: 2})
		g := newGate()

		for range 3 {
			submit(t, p, Job{Key: "a", Run: g.job("a")})
		}

		synctest.Wait()

		h, err := p.Submit(Job{Key: "a", Run: g.job("a")})
		assert.Nil(t, h)
		assert.ErrorIs(t, err, ErrQueueFull)

		g.open()
	})
}

func TestPool_QueueDepthZeroUnlimited(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPool(t, Config{Name: "test", MaxConcurrent: 1})
		g := newGate()

		for range 50 {
			submit(t, p, Job{Key: "a", Run: g.job("a")})
		}

		synctest.Wait()
		assert.Equal(t, 49, p.Stats().Queued)

		g.open()
	})
}

func limitA(n int) func(string) int {
	return func(key string) int {
		if key == "a" {
			return n
		}

		return 0
	}
}

func TestPool_ImmediateStartsUnderKeyLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPool(t, Config{Name: "test", KeyLimitFunc: limitA(1)})
		g := newGate()

		submit(t, p, Job{Key: "a", Immediate: true, Run: g.job("a")})
		synctest.Wait()

		assert.Equal(t, KeyStats{Running: 1}, p.Stats().Keys["a"])

		g.open()
	})
}

func TestPool_ImmediateBusyAtKeyLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPool(t, Config{Name: "test", KeyLimitFunc: limitA(1)})
		g := newGate()

		submit(t, p, Job{Key: "a", DedupeKey: "one", Run: g.job("a")})
		synctest.Wait()

		h, err := p.Submit(Job{Key: "a", DedupeKey: "two", Immediate: true, Run: g.job("a")})
		assert.Nil(t, h)
		assert.ErrorIs(t, err, ErrBusy)

		stats := p.Stats()
		assert.Equal(t, KeyStats{Running: 1}, stats.Keys["a"])
		assert.Equal(t, uint64(1), stats.Busy)

		// The refused job left no dedupe hold behind.
		submit(t, p, Job{Key: "b", DedupeKey: "two", Run: g.job("b")})

		g.open()
	})
}

func TestPool_ImmediatePassesGlobalLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPool(t, Config{Name: "test", MaxConcurrent: 1})
		running := newGate()
		immediate := newGate()

		submit(t, p, Job{Key: "a", Run: running.job("a")})
		submit(t, p, Job{Key: "q", Run: running.job("q")})
		synctest.Wait()

		submit(t, p, Job{Key: "b", Immediate: true, Run: immediate.job("b")})
		synctest.Wait()

		assert.Equal(t, []string{"b"}, immediate.startedKeys())
		assert.Equal(t, []string{"a"}, running.startedKeys(), "the queued job stays behind the cap")

		stats := p.Stats()
		assert.Equal(t, 2, stats.Running)
		assert.Equal(t, 1, stats.Queued)

		running.open()
		synctest.Wait()

		assert.Equal(t, []string{"a"}, running.startedKeys(), "the immediate job still holds the only slot")
		assert.Equal(t, 1, p.Stats().Queued)

		immediate.open()
		synctest.Wait()

		assert.Equal(t, []string{"a", "q"}, running.startedKeys())
	})
}

func TestPool_ImmediateIgnoresQueueDepth(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPool(t, Config{Name: "test", MaxConcurrent: 1, MaxQueueDepth: 1})
		g := newGate()

		submit(t, p, Job{Key: "a", Run: g.job("a")})
		submit(t, p, Job{Key: "a", Run: g.job("a")})
		synctest.Wait()

		submit(t, p, Job{Key: "b", Immediate: true, Run: g.job("b")})
		synctest.Wait()

		assert.Contains(t, g.startedKeys(), "b")

		g.open()
	})
}

func TestPool_ImmediateDuplicateRefused(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPool(t, Config{Name: "test"})
		g := newGate()

		submit(t, p, Job{Key: "a", DedupeKey: "session", Immediate: true, Run: g.job("a")})
		synctest.Wait()

		h, err := p.Submit(Job{Key: "a", DedupeKey: "session", Immediate: true, Run: g.job("a")})
		assert.Nil(t, h)
		assert.ErrorIs(t, err, ErrDuplicate)

		g.open()
		synctest.Wait()

		submit(t, p, Job{Key: "a", DedupeKey: "session", Immediate: true, Run: g.job("a")})
	})
}

func TestPool_ImmediateCompletionAdmitsQueued(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPool(t, Config{Name: "test", KeyLimitFunc: limitA(1)})
		immediate := newGate()
		queued := newGate()

		submit(t, p, Job{Key: "a", Immediate: true, Run: immediate.job("a")})
		submit(t, p, Job{Key: "a", Run: queued.job("a")})
		synctest.Wait()

		assert.Equal(t, KeyStats{Running: 1, Queued: 1}, p.Stats().Keys["a"])

		immediate.open()
		synctest.Wait()

		assert.Equal(t, []string{"a"}, queued.startedKeys())

		queued.open()
	})
}

func TestPool_DuplicateDedupeKeyRefusedWhileRunning(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPool(t, Config{Name: "test"})
		g := newGate()

		submit(t, p, Job{Key: "a", DedupeKey: "task", Run: g.job("a")})
		synctest.Wait()

		h, err := p.Submit(Job{Key: "a", DedupeKey: "task", Run: g.job("a")})
		assert.Nil(t, h)
		assert.ErrorIs(t, err, ErrDuplicate)

		g.open()
	})
}

func TestPool_DuplicateDedupeKeyRefusedWhileQueued(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPool(t, Config{Name: "test", MaxConcurrent: 1})
		g := newGate()

		submit(t, p, Job{Key: "filler", Run: g.job("filler")})
		submit(t, p, Job{Key: "a", DedupeKey: "task", Run: g.job("a")})

		synctest.Wait()
		assert.Equal(t, 1, p.Stats().Queued)

		h, err := p.Submit(Job{Key: "a", DedupeKey: "task", Run: g.job("a")})
		assert.Nil(t, h)
		assert.ErrorIs(t, err, ErrDuplicate)

		g.open()
	})
}

func TestPool_DedupeKeyFreedAfterCompletion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPool(t, Config{Name: "test"})

		noop := func(context.Context) error { return nil }

		submit(t, p, Job{Key: "a", DedupeKey: "task", Run: noop})
		synctest.Wait()

		submit(t, p, Job{Key: "a", DedupeKey: "task", Run: noop})
		synctest.Wait()

		assert.Empty(t, p.dedupe)
	})
}

func TestPool_EmptyDedupeKeyNeverRefuses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// The fan-out case: several jobs on one agent, deduped on nothing. A single
		// combined key would refuse every job after the first.
		p := newPool(t, Config{Name: "test"})
		g := newGate()

		for range 5 {
			submit(t, p, Job{Key: "agent", Run: g.job("agent")})
		}

		synctest.Wait()

		assert.Equal(t, 5, p.Stats().Running)
		assert.Equal(t, uint64(0), p.Stats().Deduped)

		g.open()
	})
}

func TestPool_HandleReturnsJobError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPool(t, Config{Name: "test"})

		boom := errors.New("boom")
		h := submit(t, p, Job{Key: "a", Run: func(context.Context) error { return boom }})

		assert.ErrorIs(t, h.Wait(t.Context()), boom)
		assert.ErrorIs(t, h.Err(), boom)
	})
}

func TestPool_HandleWaitRespectsContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPool(t, Config{Name: "test"})
		g := newGate()

		h := submit(t, p, Job{Key: "a", Run: g.job("a")})

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		// Waiting gave up; the job itself is untouched and still running.
		assert.ErrorIs(t, h.Wait(ctx), context.Canceled)
		assert.Equal(t, 1, p.Stats().Running)

		g.open()
	})
}

// discardLogs silences the global logger for the duration of one test and restores it
// afterwards.
func discardLogs(t *testing.T) {
	t.Helper()

	prev := log.Log.(*log.Logger).Handler

	log.SetHandler(discard.Default)
	t.Cleanup(func() { log.SetHandler(prev) })
}

func TestPool_PanicBecomesError(t *testing.T) {
	// The recovered panic is logged at Error with a full stack trace.
	discardLogs(t)

	synctest.Test(t, func(t *testing.T) {
		p := newPool(t, Config{Name: "test", MaxConcurrent: 1})

		h := submit(t, p, Job{Key: "a", Run: func(context.Context) error { panic("kaboom") }})

		assert.ErrorContains(t, h.Wait(t.Context()), "job panicked: kaboom")

		// The slot was released, so the pool is still usable.
		next := submit(t, p, Job{Key: "a", Run: func(context.Context) error { return nil }})
		assert.NoError(t, next.Wait(t.Context()))

		assert.Equal(t, 0, p.Stats().Running)
	})
}

func TestPool_ShutdownDrainsQueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := New(t.Context(), Config{Name: "test", MaxConcurrent: 1})

		var done atomic.Int64

		for range 5 {
			submit(t, p, Job{Key: "a", Run: func(context.Context) error {
				done.Add(1)

				return nil
			}})
		}

		assert.NoError(t, p.Shutdown(context.Background()))
		assert.Equal(t, int64(5), done.Load())
	})
}

func TestPool_ShutdownRefusesNewSubmissions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := New(t.Context(), Config{Name: "test"})

		assert.NoError(t, p.Shutdown(context.Background()))

		h, err := p.Submit(Job{Key: "a", Run: func(context.Context) error { return nil }})
		assert.Nil(t, h)
		assert.ErrorIs(t, err, ErrShutdown)
	})
}

func TestPool_ShutdownTimeoutCancelsAndFailsQueued(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := New(t.Context(), Config{Name: "test", MaxConcurrent: 1})

		blocking := func(ctx context.Context) error {
			<-ctx.Done()

			return ctx.Err()
		}

		running := submit(t, p, Job{Key: "a", Run: blocking})

		var started atomic.Bool
		queued := submit(t, p, Job{Key: "a", Run: func(context.Context) error {
			started.Store(true)

			return nil
		}})

		synctest.Wait()
		assert.Equal(t, 1, p.Stats().Queued)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		assert.ErrorIs(t, p.Shutdown(ctx), context.DeadlineExceeded)

		// Nobody is left holding a handle that never closes.
		assert.ErrorIs(t, queued.Wait(context.Background()), ErrShutdown)
		assert.ErrorIs(t, running.Wait(context.Background()), context.Canceled)

		synctest.Wait()
		assert.False(t, started.Load(), "the running job's exit must not start the queued one after cancel")
	})
}

func TestPool_ParentCancelFailsQueuedWithoutRunningThem(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		p := New(ctx, Config{Name: "test", MaxConcurrent: 1})
		g := newGate()

		running := submit(t, p, Job{Key: "a", Run: g.job("a")})
		queued := submit(t, p, Job{Key: "b", Run: g.job("b")})

		synctest.Wait()
		cancel()
		synctest.Wait()

		assert.ErrorIs(t, running.Wait(context.Background()), context.Canceled)
		assert.ErrorIs(t, queued.Wait(context.Background()), ErrShutdown)
		assert.Equal(t, []string{"a"}, g.startedKeys())
		assert.Equal(t, Stats{PeakQueued: 1, PeakRunning: 1, Keys: map[string]KeyStats{}}, p.Stats())

		// Nothing is left, so Shutdown has nothing to wait for.
		assert.NoError(t, p.Shutdown(context.Background()))
	})
}

func TestPool_ParentCancelRefusesNewSubmissions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		p := New(ctx, Config{Name: "test"})

		cancel()

		h, err := p.Submit(Job{Key: "a", Run: func(context.Context) error { return nil }})
		assert.Nil(t, h)
		assert.ErrorIs(t, err, ErrShutdown)

		assert.NoError(t, p.Shutdown(context.Background()))
	})
}

func TestPool_ShutdownCancelsOnCleanPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := New(t.Context(), Config{Name: "test"})

		submit(t, p, Job{Key: "a", Run: func(context.Context) error { return nil }})

		assert.NoError(t, p.Shutdown(context.Background()))

		// The parent only releases the derived context once cancel runs, so a pool
		// that drained cleanly must still have cancelled.
		assert.ErrorIs(t, context.Cause(p.ctx), ErrShutdown)
	})
}

func TestPool_ShutdownIsIdempotent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := New(t.Context(), Config{Name: "test"})

		assert.NoError(t, p.Shutdown(context.Background()))
		assert.NoError(t, p.Shutdown(context.Background()))
	})
}

// TestPool_HangingJobDoesNotBlockShutdown deliberately leaves a goroutine running, so
// it cannot use a synctest bubble -- the bubble would (correctly) fail on the leak.
func TestPool_HangingJobDoesNotBlockShutdown(t *testing.T) {
	p := New(context.Background(), Config{Name: "test"})

	stuck := make(chan struct{})
	defer close(stuck)

	started := make(chan struct{})

	submit(t, p, Job{Key: "a", Run: func(context.Context) error {
		close(started)
		<-stuck // ignores its context on purpose

		return nil
	}})

	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	assert.ErrorIs(t, p.Shutdown(ctx), context.DeadlineExceeded)
}

func TestPool_StatsCountsQueuedAndRunning(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPool(t, Config{Name: "test", MaxConcurrent: 2})
		g := newGate()

		submit(t, p, Job{Key: "a", Run: g.job("a")})
		submit(t, p, Job{Key: "b", Run: g.job("b")})
		submit(t, p, Job{Key: "b", Run: g.job("b")})

		synctest.Wait()

		stats := p.Stats()
		assert.Equal(t, 2, stats.Running)
		assert.Equal(t, 1, stats.Queued)
		assert.Equal(t, KeyStats{Running: 1}, stats.Keys["a"])
		assert.Equal(t, KeyStats{Running: 1, Queued: 1}, stats.Keys["b"])

		g.open()
	})
}

func TestPool_NoResidueAfterDrain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := New(t.Context(), Config{Name: "test", MaxConcurrent: 3})

		keys := []string{"a", "b", "c", "d", "e"}

		for i := range 50 {
			key := keys[i%len(keys)]

			submit(t, p, Job{
				Key:       key,
				DedupeKey: key + "-" + string(rune('0'+i%7)),
				Run:       func(context.Context) error { return nil },
			})

			// Dedupe keys repeat across the run, so let each batch clear before
			// reusing one.
			if i%7 == 6 {
				synctest.Wait()
			}
		}

		assert.NoError(t, p.Shutdown(context.Background()))

		// Nothing retained for a key the pool has finished with -- this pool is
		// expected to run for a year without a restart.
		assert.Empty(t, p.running)
		assert.Empty(t, p.queued)
		assert.Empty(t, p.dedupe)
		assert.Nil(t, p.queue)
		assert.Empty(t, p.Stats().Keys)
	})
}

func TestPool_StatsCountersTrackRejections(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPool(t, Config{Name: "test", MaxConcurrent: 1, MaxQueueDepth: 1})
		g := newGate()

		submit(t, p, Job{Key: "a", DedupeKey: "task", Run: g.job("a")})
		submit(t, p, Job{Key: "a", Run: g.job("a")})

		synctest.Wait()

		_, err := p.Submit(Job{Key: "a", DedupeKey: "task", Run: g.job("a")})
		assert.ErrorIs(t, err, ErrDuplicate)

		_, err = p.Submit(Job{Key: "a", Run: g.job("a")})
		assert.ErrorIs(t, err, ErrQueueFull)

		stats := p.Stats()
		assert.Equal(t, uint64(1), stats.Deduped)
		assert.Equal(t, uint64(1), stats.Rejected)
		assert.Equal(t, 1, stats.PeakQueued)
		assert.Equal(t, 1, stats.PeakRunning)

		g.open()
	})
}

func TestPool_SubmitWithoutRunFunc(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPool(t, Config{Name: "test"})

		h, err := p.Submit(Job{Key: "a"})
		assert.Nil(t, h)
		assert.ErrorIs(t, err, ErrNoRun)
	})
}

// TestPool_ConcurrentSubmitAndStats runs outside a synctest bubble on purpose: the
// race detector is the assertion here, and a bubble serializes the scheduling that
// would expose a race.
func TestPool_ConcurrentSubmitAndStats(t *testing.T) {
	p := New(context.Background(), Config{
		Name:          "test",
		MaxConcurrent: 4,
		KeyLimitFunc:  func(string) int { return 2 },
	})

	keys := []string{"a", "b", "c", "d"}

	var wg sync.WaitGroup

	for i := range 8 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for j := range 25 {
				p.Submit(Job{
					Key: keys[(i+j)%len(keys)],
					Run: func(context.Context) error { return nil },
				})

				p.Stats()
			}
		}()
	}

	wg.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	assert.NoError(t, p.Shutdown(ctx))
	assert.Equal(t, 0, p.Stats().Running)
	assert.Empty(t, p.Stats().Keys)
}
