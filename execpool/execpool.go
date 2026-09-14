// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package execpool

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"github.com/apex/log"
)

var (
	ErrQueueFull = errors.New("execution pool queue is full")
	ErrDuplicate = errors.New("a job with this dedupe key is already queued or running")
	ErrShutdown  = errors.New("execution pool is shutting down")
	ErrNoRun     = errors.New("job has no Run function")
)

// Job is one unit of work submitted to a Pool.
type Job struct {
	// Key bounds concurrency and groups Stats: at most KeyLimitFunc(Key) jobs sharing
	// a Key run at once.
	Key string

	// DedupeKey, when non-empty, refuses the submission while another job with the
	// same DedupeKey is queued or running. It is deliberately separate from Key so a
	// caller can limit on one axis (an agent's concurrent instances) while deduping on
	// another (a single automation task)
	DedupeKey string

	// Run must respect its context. Shutdown cancels it but cannot force a goroutine
	// to stop, so a Run that ignores cancellation outlives the pool.
	Run func(ctx context.Context) error
}

type Config struct {
	// Name identifies this pool in log output, e.g. "automation".
	Name string

	// MaxQueueDepth caps jobs waiting to start, not counting running ones. 0 means
	// unlimited.
	MaxQueueDepth int

	// MaxConcurrent caps running jobs across all keys. 0 means unlimited.
	MaxConcurrent int

	// KeyLimitFunc reports the maximum number of concurrent jobs for a key; any
	// result <= 0, means unlimited. It runs under the pool lock on every dispatch,
	// so it must be cheap and must not call back into the Pool.
	//
	// It is a func rather than a setter so a caller's per-key limit can hot-reload
	// without the pool ever learning what a key means. A raised limit takes effect at
	// the next Submit or completion rather than instantly -- the pool has no way to
	// observe the change itself.
	KeyLimitFunc func(key string) int
}

type KeyStats struct {
	Queued  int
	Running int
}

type Stats struct {
	Queued  int
	Running int

	// Peak and cumulative counters run from New and answer the tuning questions the
	// logs only hint at: whether the queue is too short and whether the concurrency
	// limits are too tight.
	PeakQueued  int
	PeakRunning int
	Rejected    uint64
	Deduped     uint64

	Keys map[string]KeyStats
}

// Handle reports the outcome of one submitted job.
type Handle struct {
	done chan struct{}
	err  error
}

func (h *Handle) Done() <-chan struct{} { return h.done }

// Err reports the job's error, and is only meaningful once Done is closed
func (h *Handle) Err() error { return h.err }

// Wait blocks until the job finishes or ctx expires, whichever comes first. A ctx
// expiry does not cancel the job; it only stops waiting on it.
func (h *Handle) Wait(ctx context.Context) error {
	select {
	case <-h.done:
		return h.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

type entry struct {
	job      Job
	handle   *Handle
	enqueued time.Time
	blocked  bool // a dispatch pass has already skipped this entry
}

// admission records a job that had to wait before it started, for logging once the
// pool lock is released.
type admission struct {
	key    string
	waited time.Duration
}

// logBatch carries what a locked section decided to say. Emitting inside dispatch
// would hold the pool lock across log I/O and serialize every submission behind the
// logger, which bites hardest exactly when the pool is busiest.
type logBatch struct {
	admitted  []admission
	changed   bool // the saturation edge flipped
	saturated bool
	running   int
	queued    int
}

type Pool struct {
	cfg    Config
	ctx    context.Context
	cancel context.CancelCauseFunc

	mu       sync.Mutex
	queue    []*entry       // FIFO
	running  map[string]int // map[Key]running
	queued   map[string]int // map[Key]queued
	dedupe   map[string]int // map[DedupeKey]queued+running
	total    int            // running, across all keys
	shutdown bool
	drained  chan struct{} // closed once shutdown and nothing is queued or running

	saturated   bool // edge latch for the saturation log
	peakQueued  int
	peakRunning int
	rejected    uint64
	deduped     uint64
}

// New derives the pool's job context from parent. The caller must eventually call
// Shutdown, even if only at process exit: the derived context stays registered as a
// child of parent until it is cancelled.
func New(parent context.Context, cfg Config) *Pool {
	ctx, cancel := context.WithCancelCause(parent)

	return &Pool{
		cfg:     cfg,
		ctx:     ctx,
		cancel:  cancel,
		running: make(map[string]int),
		queued:  make(map[string]int),
		dedupe:  make(map[string]int),
		drained: make(chan struct{}),
	}
}

// Submit queues a job, starting it immediately if the limits allow. It reports
// ErrShutdown, ErrDuplicate or ErrQueueFull when the job is refused; on success the
// returned Handle closes when the job finishes.
func (p *Pool) Submit(job Job) (*Handle, error) {
	if job.Run == nil {
		return nil, ErrNoRun
	}

	p.mu.Lock()

	if p.shutdown {
		p.mu.Unlock()

		return nil, ErrShutdown
	}

	if job.DedupeKey != "" && p.dedupe[job.DedupeKey] > 0 {
		p.deduped++

		p.mu.Unlock()

		p.logger().WithFields(log.Fields{
			"key":       job.Key,
			"dedupeKey": job.DedupeKey,
		}).Debug("refused duplicate job")

		return nil, ErrDuplicate
	}

	if p.cfg.MaxQueueDepth > 0 && len(p.queue) >= p.cfg.MaxQueueDepth {
		p.rejected++
		depth := len(p.queue)

		p.mu.Unlock()

		p.logger().WithFields(log.Fields{
			"key":           job.Key,
			"queued":        depth,
			"maxQueueDepth": p.cfg.MaxQueueDepth,
		}).Warn("refused job, execution pool queue is full")

		return nil, ErrQueueFull
	}

	e := &entry{
		job:      job,
		handle:   &Handle{done: make(chan struct{})},
		enqueued: time.Now(),
	}

	p.queue = append(p.queue, e)
	p.queued[job.Key]++

	if job.DedupeKey != "" {
		p.dedupe[job.DedupeKey]++
	}

	if len(p.queue) > p.peakQueued {
		p.peakQueued = len(p.queue)
	}

	batch := p.dispatch()

	p.mu.Unlock()

	p.emit(batch)

	return e.handle, nil
}

// Stats reports a point-in-time snapshot. Keys holds only the keys with work
// outstanding right now.
func (p *Pool) Stats() Stats {
	p.mu.Lock()
	defer p.mu.Unlock()

	s := Stats{
		Queued:      len(p.queue),
		Running:     p.total,
		PeakQueued:  p.peakQueued,
		PeakRunning: p.peakRunning,
		Rejected:    p.rejected,
		Deduped:     p.deduped,
		Keys:        make(map[string]KeyStats, len(p.running)+len(p.queued)),
	}

	for k, n := range p.running {
		ks := s.Keys[k]
		ks.Running = n
		s.Keys[k] = ks
	}

	for k, n := range p.queued {
		ks := s.Keys[k]
		ks.Queued = n
		s.Keys[k] = ks
	}

	return s
}

// Shutdown stops admitting new jobs and waits for the queued and running ones to
// finish. If ctx expires first it cancels the running jobs, fails everything still
// queued, and returns ctx.Err() without waiting any longer. Calling it more than once
// is safe.
func (p *Pool) Shutdown(ctx context.Context) error {
	// Always cancel, even on the clean path: WithCancelCause registers this pool's
	// context as a child of the parent's, and a long-lived parent only lets go of it
	// when cancel runs.
	defer p.cancel(ErrShutdown)

	p.mu.Lock()

	already := p.shutdown
	p.shutdown = true
	queued, running := len(p.queue), p.total

	p.closeDrainedLocked()

	p.mu.Unlock()

	if !already {
		p.logger().WithFields(log.Fields{
			"queued":  queued,
			"running": running,
		}).Info("draining execution pool")
	}

	select {
	case <-p.drained:
		p.logger().Info("execution pool drained")

		return nil
	case <-ctx.Done():
	}

	// Out of time. Cancel whatever is running and fail everything still queued so no
	// caller is left waiting on a handle that will never close. Jobs that ignore their
	// context are not waited on; the pool cannot force a goroutine to stop.
	p.cancel(ErrShutdown)

	abandoned := p.abandonQueued()

	p.mu.Lock()
	stillRunning := p.total
	p.mu.Unlock()

	p.logger().WithFields(log.Fields{
		"abandoned":    abandoned,
		"stillRunning": stillRunning,
	}).Warn("execution pool shutdown timed out")

	return ctx.Err()
}

// dispatch starts every queued job that currently fits under the global and per-key
// limits, scanning in submission order. A job blocked by its key's limit is skipped
// rather than blocking the ones behind it -- strict FIFO would let a single saturated
// key stall every other key's work.
//
// The caller must hold mu, and must emit the returned batch only after releasing it.
func (p *Pool) dispatch() logBatch {
	var batch logBatch

	kept := p.queue[:0]

	for _, e := range p.queue {
		if !p.admissible(e.job.Key) {
			e.blocked = true
			kept = append(kept, e)

			continue
		}

		p.queued[e.job.Key]--
		if p.queued[e.job.Key] == 0 {
			delete(p.queued, e.job.Key)
		}

		p.running[e.job.Key]++
		p.total++

		if p.total > p.peakRunning {
			p.peakRunning = p.total
		}

		if e.blocked {
			batch.admitted = append(batch.admitted, admission{
				key:    e.job.Key,
				waited: time.Since(e.enqueued),
			})
		}

		go p.run(e)
	}

	// Release the tail so started entries are collectable, and drop the backing array
	// once the queue empties -- otherwise it stays at its high-water length for the
	// life of the pool.
	for i := len(kept); i < len(p.queue); i++ {
		p.queue[i] = nil
	}

	p.queue = kept
	if len(p.queue) == 0 {
		p.queue = nil
	}

	p.noteSaturationLocked(&batch)

	return batch
}

func (p *Pool) admissible(key string) bool {
	if p.cfg.MaxConcurrent > 0 && p.total >= p.cfg.MaxConcurrent {
		return false
	}

	if p.cfg.KeyLimitFunc != nil {
		if limit := p.cfg.KeyLimitFunc(key); limit > 0 && p.running[key] >= limit {
			return false
		}
	}

	return true
}

// noteSaturationLocked latches the transition into and out of "work is waiting".
// Reporting it per submission would flood the log exactly when the pool is busiest,
// so only the edge is recorded.
func (p *Pool) noteSaturationLocked(batch *logBatch) {
	saturated := len(p.queue) > 0

	if saturated == p.saturated {
		return
	}

	p.saturated = saturated

	batch.changed = true
	batch.saturated = saturated
	batch.running = p.total
	batch.queued = len(p.queue)
}

func (p *Pool) run(e *entry) {
	defer p.complete(e)

	// The pool started this goroutine, so it is the only place a job's panic can be
	// recovered -- an escaped panic would take down the whole process.
	defer func() {
		if r := recover(); r != nil {
			e.handle.err = fmt.Errorf("job panicked: %v", r)

			p.logger().WithFields(log.Fields{
				"key":   e.job.Key,
				"panic": r,
				"stack": string(debug.Stack()),
			}).Error("recovered panic from execution pool job")
		}
	}()

	e.handle.err = e.job.Run(p.ctx)
}

func (p *Pool) complete(e *entry) {
	p.mu.Lock()

	p.total--

	p.running[e.job.Key]--
	if p.running[e.job.Key] == 0 {
		delete(p.running, e.job.Key)
	}

	p.releaseDedupeLocked(e.job)

	batch := p.dispatch()

	p.closeDrainedLocked()

	p.mu.Unlock()

	// Closing done publishes err to anyone in Wait. It happens after the pool has let
	// go of the entry, so a waiter can never observe the pool still counting this job.
	close(e.handle.done)

	p.emit(batch)
}

func (p *Pool) releaseDedupeLocked(job Job) {
	if job.DedupeKey == "" {
		return
	}

	p.dedupe[job.DedupeKey]--
	if p.dedupe[job.DedupeKey] == 0 {
		delete(p.dedupe, job.DedupeKey)
	}
}

func (p *Pool) closeDrainedLocked() {
	if !p.shutdown || p.total != 0 || len(p.queue) != 0 {
		return
	}

	select {
	case <-p.drained:
	default:
		close(p.drained)
	}
}

// abandonQueued fails every still-queued job, reporting how many there were.
func (p *Pool) abandonQueued() int {
	p.mu.Lock()

	queued := p.queue
	p.queue = nil
	p.queued = make(map[string]int)

	for _, e := range queued {
		p.releaseDedupeLocked(e.job)
	}

	p.closeDrainedLocked()

	p.mu.Unlock()

	for _, e := range queued {
		e.handle.err = ErrShutdown
		close(e.handle.done)
	}

	return len(queued)
}

func (p *Pool) emit(b logBatch) {
	logger := p.logger()

	for _, a := range b.admitted {
		logger.WithFields(log.Fields{
			"key":    a.key,
			"waited": a.waited,
		}).Debug("admitted queued job")
	}

	if !b.changed {
		return
	}

	if b.saturated {
		logger.WithFields(log.Fields{
			"running":       b.running,
			"queued":        b.queued,
			"maxConcurrent": p.cfg.MaxConcurrent,
		}).Info("execution pool saturated, jobs are waiting")

		return
	}

	logger.WithField("running", b.running).Info("execution pool no longer saturated")
}

func (p *Pool) logger() *log.Entry {
	return log.FromContext(p.ctx).WithField("pool", p.cfg.Name)
}
