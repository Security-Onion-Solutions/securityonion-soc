// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package web

import (
  "context"
  "github.com/stretchr/testify/assert"
  "net/http"
  "testing"
)

func TestPreprocessPriority(tester *testing.T) {
  handler := NewBasePreprocessor()
  assert.Zero(tester, handler.PreprocessPriority())
}

func TestPreprocess(tester *testing.T) {
  handler := NewBasePreprocessor()
  request, _ := http.NewRequest("GET", "", nil)
  ctx, statusCode, err := handler.Preprocess(context.Background(), request)
  assert.NoError(tester, err)
  assert.Zero(tester, statusCode)

  actualId := ctx.Value(ContextKeyRequestId).(string)
  assert.Len(tester, actualId, 36, "Expected valid UUID")
}
