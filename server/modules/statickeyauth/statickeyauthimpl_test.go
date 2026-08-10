// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package statickeyauth

import (
	"context"
	"net/http"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

func TestValidateAuthorization(tester *testing.T) {
	validateAuthorization(tester, "abc", true)
	validateAuthorization(tester, "a", false)
	validateAuthorization(tester, "", false)
}

func validateAuthorization(tester *testing.T, key string, expected bool) {
	ai := NewStaticKeyAuthImpl(server.NewFakeAuthorizedServer(nil))
	ai.Init("abc")
	actual := ai.validateAuthorization(context.Background(), key)
	assert.Equal(tester, expected, actual)
}

func TestValidateApiKey(tester *testing.T) {
	validateKey(tester, "", false)
	validateKey(tester, "basic xyz", false)
	validateKey(tester, "basic", false)
	validateKey(tester, "abc", true)
	validateKey(tester, "basic abc", true)
}

func validateKey(tester *testing.T, key string, expected bool) {
	ai := NewStaticKeyAuthImpl(server.NewFakeAuthorizedServer(nil))
	ai.apiKey = "abc"
	actual := ai.validateApiKey(key)
	assert.Equal(tester, expected, actual)
}

func TestAuthImplInit(tester *testing.T) {
	ai := NewStaticKeyAuthImpl(server.NewFakeAuthorizedServer(nil))
	err := ai.Init("abc")
	if assert.Nil(tester, err) {
		assert.Equal(tester, "abc", ai.apiKey)
	}
}

func TestPreprocessPriority(tester *testing.T) {
	handler := NewStaticKeyAuthImpl(server.NewFakeAuthorizedServer(nil))
	assert.Equal(tester, 100, handler.PreprocessPriority())
}

func TestPreprocess(tester *testing.T) {
	ai := NewStaticKeyAuthImpl(server.NewFakeAuthorizedServer(nil))
	ai.apiKey = "123"
	request, _ := http.NewRequest("GET", "", nil)
	request.Header.Set("authorization", ai.apiKey)
	ctx, statusCode, err := ai.Preprocess(context.Background(), request)
	if assert.Nil(tester, err) {
		assert.Zero(tester, statusCode)
		if assert.NotNil(tester, ctx) {
			requestorId := ctx.Value(web.ContextKeyRequestorId)
			assert.Equal(tester, server.AGENT_ID, requestorId)
		}
	}
}
