// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"sync"
	"time"
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
}

func newActivityNotifier(window time.Duration, send func()) *activityNotifier {
	return &activityNotifier{window: window, send: send}
}

func (n *activityNotifier) notify() {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.stopped || n.timer != nil {
		return
	}

	n.timer = time.AfterFunc(n.window, n.fire)
}

// fire sends after clearing the timer, so a change it races with is already visible to the refetch.
func (n *activityNotifier) fire() {
	n.mu.Lock()
	n.timer = nil
	stopped := n.stopped
	n.mu.Unlock()

	if !stopped {
		n.send()
	}
}

func (n *activityNotifier) stop() {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.stopped = true
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
	if ac.srv != nil && ac.srv.Host != nil {
		ac.srv.Host.Broadcast(AutomationActivityKind, "automations", nil)
	}
}
