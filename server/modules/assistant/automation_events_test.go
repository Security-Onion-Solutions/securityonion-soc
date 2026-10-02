// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// A Broadcast stuck on a slow client must not gather a goroutine per window.
func TestActivityNotifierKeepsOneSendAtATime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var calls, inFlight, maxInFlight atomic.Int32
		n := newActivityNotifier(time.Second, func() {
			calls.Add(1)
			if c := inFlight.Add(1); c > maxInFlight.Load() {
				maxInFlight.Store(c)
			}
			<-release
			inFlight.Add(-1)
		})

		n.notify()
		for range 10 {
			time.Sleep(time.Second)
			synctest.Wait()
			n.notify()
		}

		assert.Equal(t, int32(1), calls.Load(), "the stuck send is the only one")

		close(release)
		synctest.Wait()
		time.Sleep(time.Second)
		synctest.Wait()

		assert.Equal(t, int32(2), calls.Load(), "the changes made meanwhile go out once, a window later")
		assert.Equal(t, int32(1), maxInFlight.Load())
	})
}

func TestActivityNotifierStopDropsChangesPendingBehindASend(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var calls atomic.Int32
		n := newActivityNotifier(time.Second, func() {
			calls.Add(1)
			<-release
		})

		n.notify()
		time.Sleep(time.Second)
		synctest.Wait()
		n.notify()
		n.stop()

		close(release)
		time.Sleep(2 * time.Second)
		synctest.Wait()

		assert.Equal(t, int32(1), calls.Load())
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
		assert.Len(t, ac.AgentSessionPhases(), 1, "the phase lock is free again")
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

func TestAutomationActivityRecordsWhenItWasBuilt(t *testing.T) {
	before := time.Now()
	activity, err := newActivityCoordinator(t).automationActivity(context.Background(), &fakeActivityStore{})
	require.NoError(t, err)

	assert.False(t, activity.GeneratedAt.Before(before))
}

func TestAutomationActivityIsBroadcastWhole(t *testing.T) {
	ac := newActivityCoordinator(t)
	var published []*model.AutomationActivity
	ac.publishActivity = func(snapshot *model.AutomationActivity) { published = append(published, snapshot) }

	ac.broadcastAutomationActivity()

	require.Len(t, published, 1)
	assert.False(t, published[0].GeneratedAt.IsZero())
	assert.NotNil(t, published[0].Runs)
}
