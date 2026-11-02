// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"sync"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"

	"github.com/apex/log"
)

// Changes within one window reach clients as a single event, sent as the window closes.
const automationActivityWindow = time.Second

// activityNotifier turns any number of change reports into at most one send per window,
// never dropping the last. notify does not block, so it is safe to call under a lock.
type activityNotifier struct {
	mu      sync.Mutex
	window  time.Duration
	send    func()
	timer   *time.Timer
	stopped bool
	// Only one send runs at a time: a Broadcast stuck on a slow client would otherwise
	// gather another goroutine every window.
	sending bool
	pending bool
}

func newActivityNotifier(window time.Duration, send func()) *activityNotifier {
	return &activityNotifier{window: window, send: send}
}

func (n *activityNotifier) notify() {
	n.mu.Lock()
	defer n.mu.Unlock()

	switch {
	case n.stopped || n.timer != nil:
	case n.sending:
		n.pending = true
	default:
		n.timer = time.AfterFunc(n.window, n.fire)
	}
}

// A change that races the send lands either before it, so the refetch sees it, or after,
// as pending for the next window.
func (n *activityNotifier) fire() {
	n.mu.Lock()
	n.timer = nil
	if n.stopped {
		n.mu.Unlock()
		return
	}
	n.sending = true
	n.mu.Unlock()

	n.send()

	n.mu.Lock()
	defer n.mu.Unlock()

	n.sending = false
	if n.pending && !n.stopped {
		n.pending = false
		n.timer = time.AfterFunc(n.window, n.fire)
	}
}

func (n *activityNotifier) stop() {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.stopped = true
	n.pending = false
	if n.timer != nil {
		n.timer.Stop()
		n.timer = nil
	}
}

func (ac *AssistantCoordinator) notifyAutomationActivity() {
	if ac.activityEvents != nil {
		ac.activityEvents.notify()
	}
}

// Sent to whoever may read automations, which is who may call the activity endpoint.
func (ac *AssistantCoordinator) broadcastAutomationActivity() {
	if ac.srv == nil {
		return
	}

	publish := ac.publishActivity
	if publish == nil {
		if ac.srv.Host == nil {
			return
		}

		publish = func(snapshot *model.AutomationActivity) {
			ac.srv.Host.Broadcast(AutomationActivityKind, "automations", snapshot)
		}
	}

	// A nil *database.Store is a non-nil interface.
	var store automationActivityStore
	if ac.store != nil {
		store = ac.store
	}

	// The server's context is the system identity; this view is the same for every reader.
	snapshot, err := ac.automationActivity(ac.srv.Context, store)
	if err != nil {
		log.WithError(err).Warn("unable to build automation activity to broadcast")
		return
	}

	publish(snapshot)
}
