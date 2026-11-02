// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func applyGetSessionsOpts(opts ...GetSessionsOpt) *GetSessionsOpts {
	gso := &GetSessionsOpts{}
	for _, opt := range opts {
		opt(gso)
	}

	return gso
}

func TestGetSessionsWithAutomationSessions(t *testing.T) {
	t.Parallel()

	assert.False(t, applyGetSessionsOpts().IncludeAutomationSessions())
	assert.True(t, applyGetSessionsOpts(GetSessionsWithAutomationSessions(true)).IncludeAutomationSessions())
	assert.False(t, applyGetSessionsOpts(GetSessionsWithAutomationSessions(false)).IncludeAutomationSessions())

	// the two exclusions are independent opts
	both := applyGetSessionsOpts(GetSessionsWithAutomationSessions(true))
	assert.False(t, both.IncludeMemorySessions())
}
