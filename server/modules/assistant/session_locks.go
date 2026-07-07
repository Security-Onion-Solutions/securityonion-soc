// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import "sync"

// sessionLocks is a mutex keyed by session id. Holding a session's lock around the
// tool-turn continuation (see continueWithToolResult) makes its load-check-save-dispatch
// decision atomic, so when several parallel tool results land for one model turn exactly
// one request continues the LLM's turn -- no stall, no double dispatch.
//
// Entries are reference-counted and pruned once no goroutine holds or is waiting on a
// session's lock.
type sessionLocks struct {
	mu      sync.Mutex
	entries map[string]*refMutex
}

// refMutex is a per-session mutex plus a count of the goroutines currently holding or
// waiting on it. The entry is deleted when refs falls to zero.
type refMutex struct {
	mu   sync.Mutex
	refs int
}

// acquire get-or-creates the entry for key and bumps its refcount, all under the
// manager lock so the entry cannot be pruned while this caller is interested. The
// caller must pair it with exactly one release (via unlock, or directly on a failed
// tryLock).
func (s *sessionLocks) acquire(key string) *refMutex {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.entries == nil {
		s.entries = make(map[string]*refMutex)
	}

	e := s.entries[key]
	if e == nil {
		e = &refMutex{}
		s.entries[key] = e
	}

	e.refs++

	return e
}

// release drops one reference to key's lock and prunes the entry once the last
// holder/waiter is gone.
func (s *sessionLocks) release(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e := s.entries[key]
	if e == nil {
		return
	}

	e.refs--
	if e.refs == 0 {
		delete(s.entries, key)
	}
}

func (s *sessionLocks) lock(key string) { s.acquire(key).mu.Lock() }

func (s *sessionLocks) unlock(key string) {
	s.mu.Lock()

	e := s.entries[key]

	s.mu.Unlock()
	if e == nil {
		return
	}

	e.mu.Unlock()

	s.release(key)
}

// tryLock acquires the session's lock without blocking, reporting whether it was
// acquired. A fresh client tool request uses this so a session that is already
// running a tool turn is rejected immediately (409) rather than left waiting -- a
// blocked request would burn its timeout and could persist its result only to be
// cancelled before the model's turn. On false the caller must NOT call unlock.
func (s *sessionLocks) tryLock(key string) bool {
	e := s.acquire(key)
	if e.mu.TryLock() {
		return true
	}

	s.release(key) // didn't get it -- drop the reference acquire took

	return false
}
