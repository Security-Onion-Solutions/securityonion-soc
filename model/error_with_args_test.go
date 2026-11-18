// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var errTestCode = errors.New("ERROR_TEST")

func TestErrorWithArgs_Error(t *testing.T) {
	assert.Equal(t, `{"code":"ERROR_TEST"}`, NewErrorWithArgs(errTestCode, nil).Error())
	assert.Equal(t, `{"a":1,"b":"two","code":"ERROR_TEST"}`, NewErrorWithArgs(errTestCode, map[string]interface{}{"b": "two", "a": 1}).Error())
	assert.Equal(t, `{"code":"ERROR_TEST","detail":"x must be set"}`, NewErrorWithArgs(errTestCode, map[string]interface{}{ErrorArgDetail: "x must be set"}).Error())
}

func TestErrorWithArgs_Error_UnmarshalableArg(t *testing.T) {
	assert.Equal(t, "ERROR_TEST", NewErrorWithArgs(errTestCode, map[string]interface{}{"bad": make(chan int)}).Error())
}

func TestErrorWithArgs_Unwrap(t *testing.T) {
	err := NewErrorWithArgs(errTestCode, map[string]interface{}{"count": 2})
	assert.ErrorIs(t, err, errTestCode)

	wrapped := fmt.Errorf("context: %w", err)
	assert.ErrorIs(t, wrapped, errTestCode)

	var argsErr *ErrorWithArgs
	assert.True(t, errors.As(wrapped, &argsErr))
	assert.Equal(t, 2, argsErr.Args["count"])
}

func TestErrorWithArgs_MarshalJSON(t *testing.T) {
	bytes, err := json.Marshal(NewErrorWithArgs(errTestCode, map[string]interface{}{"line": 3}))
	assert.NoError(t, err)
	assert.JSONEq(t, `{"code":"ERROR_TEST","line":3}`, string(bytes))

	bytes, err = json.Marshal(NewErrorWithArgs(errTestCode, nil))
	assert.NoError(t, err)
	assert.JSONEq(t, `{"code":"ERROR_TEST"}`, string(bytes))
}

func TestErrorWithArgs_MarshalJSON_CodeNotOverridden(t *testing.T) {
	bytes, err := json.Marshal(NewErrorWithArgs(errTestCode, map[string]interface{}{"code": "ERROR_OTHER"}))
	assert.NoError(t, err)
	assert.JSONEq(t, `{"code":"ERROR_TEST"}`, string(bytes))
}
