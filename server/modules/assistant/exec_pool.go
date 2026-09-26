// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"errors"
	"sync"

	"github.com/security-onion-solutions/securityonion-soc/execpool"
	"github.com/security-onion-solutions/securityonion-soc/server"

	"github.com/apex/log"
)

func (ac *AssistantCoordinator) newExecPool() *execpool.Pool {
	return execpool.New(ac.srv.Context, execpool.Config{
		Name:          "assistant",
		MaxQueueDepth: ac.automationMaxQueuedItems,
		MaxConcurrent: ac.automationMaxConcurrentItems,
		KeyLimitFunc:  ac.agentConcurrencyLimit,
	})
}

func (ac *AssistantCoordinator) stopExecPool(ctx context.Context) {
	if ac.execPool == nil {
		return
	}

	if err := ac.execPool.Shutdown(ctx); err != nil {
		log.FromContext(ac.srv.Context).WithError(err).Warn("assistant execution pool did not drain")
	}
}

// agentConcurrencyLimit is the pool's KeyLimitFunc; it runs under the pool lock, so it only reads the agent map.
func (ac *AssistantCoordinator) agentConcurrencyLimit(name string) int {
	ac.agentMu.RLock()
	defer ac.agentMu.RUnlock()

	return ac.agents[name].MaxConcurrentInstances
}

// AcquireTurnSlot holds a pool slot for one user turn, keyed by the agent or model the turn
// runs on, until release is called. It never waits: a full agent is ErrAgentBusy and a turn
// already running for the session is ErrToolTurnBusy.
func (ac *AssistantCoordinator) AcquireTurnSlot(ctx context.Context, sessionId string, selector string) (release func(), err error) {
	if ac.execPool == nil {
		return func() {}, nil
	}

	done := make(chan struct{})

	_, err = ac.execPool.Submit(execpool.Job{
		Key:       ac.execPoolKey(selector),
		DedupeKey: sessionId,
		Immediate: true,
		Run: func(ctx context.Context) error {
			select {
			case <-done:
			case <-ctx.Done():
			}

			return nil
		},
	})

	switch {
	case errors.Is(err, execpool.ErrBusy):
		return nil, server.ErrAgentBusy
	case errors.Is(err, execpool.ErrDuplicate):
		return nil, server.ErrToolTurnBusy
	case err != nil:
		return nil, err
	}

	return sync.OnceFunc(func() { close(done) }), nil
}

// execPoolKey is the agent's name, or the canonical model selector when the selector names no agent.
func (ac *AssistantCoordinator) execPoolKey(selector string) string {
	agentParams, modelParams := ac.resolveSelector(selector)

	switch {
	case agentParams != nil:
		return agentParams.Name
	case modelParams != nil:
		return modelParams.Selector()
	default:
		return selector
	}
}
