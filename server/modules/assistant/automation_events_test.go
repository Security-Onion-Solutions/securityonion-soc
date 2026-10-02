// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/server"

	"github.com/stretchr/testify/assert"
)

func TestActivityNotifierSendsOncePerWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var sends atomic.Int32
		n := newActivityNotifier(time.Second, func() { sends.Add(1) })

		for range 5 {
			n.notify()
		}

		time.Sleep(time.Second - time.Millisecond)
		synctest.Wait()
		assert.Equal(t, int32(0), sends.Load(), "nothing before the window closes")

		time.Sleep(time.Millisecond)
		synctest.Wait()
		assert.Equal(t, int32(1), sends.Load(), "the burst went out once")

		n.notify()
		time.Sleep(time.Second)
		synctest.Wait()
		assert.Equal(t, int32(2), sends.Load(), "a later change gets its own send")
	})
}

func TestActivityNotifierStops(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var sends atomic.Int32
		n := newActivityNotifier(time.Second, func() { sends.Add(1) })

		n.notify()
		n.stop()
		n.notify()
		time.Sleep(2 * time.Second)
		synctest.Wait()

		assert.Equal(t, int32(0), sends.Load())
	})
}

func TestAgentPhaseChangesReachTheNotifier(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var sends atomic.Int32
		ac := &AssistantCoordinator{activityEvents: newActivityNotifier(time.Second, func() { sends.Add(1) })}

		ac.setAgentPhase("s-1", "s-1", "Investigator", "waiting_llm")
		time.Sleep(time.Second)
		synctest.Wait()
		assert.Equal(t, int32(1), sends.Load())

		ac.clearAgentPhase("s-1")
		time.Sleep(time.Second)
		synctest.Wait()
		assert.Equal(t, int32(2), sends.Load())
	})
}

func TestAutomationActivityWithoutNotifierOrHost(t *testing.T) {
	ac := &AssistantCoordinator{}
	ac.notifyAutomationActivity()
	ac.broadcastAutomationActivity()

	ac.srv = &server.Server{}
	ac.broadcastAutomationActivity()
}
