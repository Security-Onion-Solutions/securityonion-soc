// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package web

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStaticAssetPreprocessorPriority(tester *testing.T) {
	handler := NewStaticAssetPreprocessor()
	assert.Equal(tester, 10, handler.PreprocessPriority())
}

func TestStaticAssetPreprocessor(tester *testing.T) {
	handler := NewStaticAssetPreprocessor()

	// Static asset GET request should succeed
	req, _ := http.NewRequest(http.MethodGet, "/js/app.js", nil)
	ctx, statusCode, err := handler.Preprocess(context.Background(), req)
	assert.NoError(tester, err)
	assert.Zero(tester, statusCode)
	assert.NotNil(tester, ctx)

	// Static asset HEAD request should succeed
	req, _ = http.NewRequest(http.MethodHead, "/favicon.ico", nil)
	ctx, statusCode, err = handler.Preprocess(context.Background(), req)
	assert.NoError(tester, err)
	assert.Zero(tester, statusCode)

	// Non-GET/HEAD request should fail
	req, _ = http.NewRequest(http.MethodPost, "/js/app.js", nil)
	ctx, statusCode, err = handler.Preprocess(context.Background(), req)
	assert.Error(tester, err)
	assert.Equal(tester, http.StatusUnauthorized, statusCode)

	// API path should fail
	req, _ = http.NewRequest(http.MethodGet, "/api/users", nil)
	ctx, statusCode, err = handler.Preprocess(context.Background(), req)
	assert.Error(tester, err)
	assert.Equal(tester, http.StatusUnauthorized, statusCode)

	// WebSocket path should fail
	req, _ = http.NewRequest(http.MethodGet, "/ws", nil)
	ctx, statusCode, err = handler.Preprocess(context.Background(), req)
	assert.Error(tester, err)
	assert.Equal(tester, http.StatusUnauthorized, statusCode)
}
