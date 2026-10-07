// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRuleError(t *testing.T) {
	t.Parallel()

	code := errors.New("ERROR_TEST")
	reason := errors.New("document 2 is not a Sigma filter")
	err := fmt.Errorf("wrapped: %w", NewRuleError(code, reason))

	assert.ErrorIs(t, err, code)
	assert.ErrorIs(t, err, reason)

	// the detail, never the code, so an unmapped RuleError is still masked
	assert.Equal(t, "wrapped: document 2 is not a Sigma filter", err.Error())

	var ruleErr *RuleError
	assert.ErrorAs(t, err, &ruleErr)
	assert.Equal(t, code, ruleErr.Code)

	assert.NoError(t, NewRuleError(code, nil))
}
