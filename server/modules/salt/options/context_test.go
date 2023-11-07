// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package options

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// nolint: staticcheck // test file
func TestTimeout(t *testing.T) {
	ctx := WithTimeoutMs(nil, 100)
	assert.NotNil(t, ctx)

	timeout := GetTimeoutMs(ctx)
	assert.Equal(t, 100, timeout)

	timeout = GetTimeoutMs(nil)
	assert.Equal(t, 0, timeout)

	bg := context.Background()
	timeout = GetTimeoutMs(bg)
	assert.Equal(t, 0, timeout)
}
