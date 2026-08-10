// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package hydra

import (
	"context"
	"net/http"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

func TestPreprocessPriority(tester *testing.T) {
	handler := NewHydraPreprocessor(nil)
	assert.Equal(tester, 120, handler.PreprocessPriority())
}
func TestPreprocess(tester *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_API, 0, 0, "", "")
	expectedId := "112233"

	client := model.NewClient()
	client.Id = expectedId
	clientstore := NewHydraClientstore(server.NewFakeAuthorizedServer(make(map[string][]string)))
	_ = clientstore.Init("some/url")
	hydraClientsIntrospectResponseJson := `
	{
		"active": true,
		"client_id": "112233"
	}`
	clientstore.client.MockStringResponse(hydraClientsIntrospectResponseJson, 200, nil)
	hydraClientsResponseJson := `
	{
		"client_id": "112233"
	}`
	clientstore.client.MockStringResponse(hydraClientsResponseJson, 200, nil)

	handler := NewHydraPreprocessor(clientstore)
	request, _ := http.NewRequest("GET", "", nil)

	request.Header.Set("Authorization", "Bearer abc")

	ctx, statusCode, err := handler.Preprocess(context.Background(), request)
	if assert.Nil(tester, err) {
		assert.Zero(tester, statusCode)
		assert.NotNil(tester, ctx)
	}

	requestorId := ctx.Value(web.ContextKeyRequestorId)
	if assert.NotNil(tester, requestorId) {
		assert.Equal(tester, expectedId, requestorId)
	}
}

func TestPreprocessNoBearerProvided(tester *testing.T) {
	clientstore := NewHydraClientstore(server.NewFakeAuthorizedServer(make(map[string][]string)))
	_ = clientstore.Init("some/url")
	handler := NewHydraPreprocessor(clientstore)
	request, _ := http.NewRequest("GET", "", nil)

	request.Header.Set("Authorization", "abc")

	ctx, statusCode, err := handler.Preprocess(context.Background(), request)
	assert.NotNil(tester, err)
	assert.Equal(tester, statusCode, http.StatusUnauthorized)
	assert.NotNil(tester, ctx)
}

func TestPreprocessAPIDisabledBearerProvided(tester *testing.T) {
	clientstore := NewHydraClientstore(server.NewFakeAuthorizedServer(make(map[string][]string)))
	_ = clientstore.Init("some/url")
	handler := NewHydraPreprocessor(clientstore)
	request, _ := http.NewRequest("GET", "", nil)

	request.Header.Set("Authorization", "Bearer abc")

	ctx, statusCode, err := handler.Preprocess(context.Background(), request)
	assert.NotNil(tester, err)
	assert.Equal(tester, statusCode, http.StatusServiceUnavailable)
	assert.NotNil(tester, ctx)
}

func TestPreprocessAPIEnabledMissingBearerToken(tester *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_API, 1, 0, "", "")
	clientstore := NewHydraClientstore(server.NewFakeAuthorizedServer(make(map[string][]string)))
	_ = clientstore.Init("some/url")
	handler := NewHydraPreprocessor(clientstore)
	request, _ := http.NewRequest("GET", "", nil)

	request.Header.Set("Authorization", "Bearer ")

	ctx, statusCode, err := handler.Preprocess(context.Background(), request)
	assert.NotNil(tester, err)
	assert.Equal(tester, statusCode, http.StatusUnauthorized)
	assert.NotNil(tester, ctx)
}
