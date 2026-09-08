// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package kratos

import (
	"context"
	"net/http"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

func TestPreprocessPriority(tester *testing.T) {
	handler := NewKratosPreprocessor(nil)
	assert.Equal(tester, 110, handler.PreprocessPriority())
}
func TestPreprocess(tester *testing.T) {
	expectedId := "112233"

	user := model.NewUser()
	user.Id = expectedId
	userstore := NewKratosUserstore(server.NewFakeAuthorizedServer(make(map[string][]string)))
	userstore.Init("some/adminurl", "some/publicurl")

	// ValidateSession mock response
	whoamiResp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	whoamiResp.Header.Set(HeaderKratosAuthenticatedIdentityId, expectedId)
	userstore.publicClient.MockResponse(whoamiResp, nil)

	kratosUsersResponseJson := `
    [
      {
        "credentials": {},
        "id": "112233",
        "recovery_addresses": [],
        "state": "active",
        "traits": {
          "email": "",
          "firstname": "",
          "lastname": "",
          "note": ""
        },
        "verifiable_addresses": []
      }
    ]`
	userstore.client.MockStringResponse(kratosUsersResponseJson, 200, nil)
	kratosUserResponseJson := `
	{
		"credentials": {},
		"id": "112233",
		"recovery_addresses": [],
		"state": "active",
		"traits": {
			"email": "",
			"firstname": "",
			"lastname": "",
			"note": ""
		},
		"verifiable_addresses": []
	}`
	userstore.client.MockStringResponse(kratosUserResponseJson, 200, nil)

	handler := NewKratosPreprocessor(userstore)
	request, _ := http.NewRequest("GET", "", nil)
	request.AddCookie(&http.Cookie{Name: "ory_kratos_session", Value: "session123"})

	ctx, statusCode, err := handler.Preprocess(context.Background(), request)
	if assert.Nil(tester, err) {
		assert.Zero(tester, statusCode)
		assert.NotNil(tester, ctx)
	}

	actualId := ctx.Value(web.ContextKeyRequestorId)
	assert.Equal(tester, expectedId, actualId)

	requestorId := ctx.Value(web.ContextKeyRequestorId)
	if assert.NotNil(tester, requestorId) {
		assert.Equal(tester, expectedId, requestorId)
	}
}

func TestPreprocessWithAuthorizationHeader(tester *testing.T) {
	handler := NewKratosPreprocessor(nil)
	request, _ := http.NewRequest("GET", "", nil)
	request.Header.Set("Authorization", "Bearer token123")

	ctx, statusCode, err := handler.Preprocess(context.Background(), request)
	assert.Equal(tester, http.StatusUnauthorized, statusCode)
	if assert.Error(tester, err) {
		assert.Equal(tester, "Unexpected authorization header", err.Error())
	}
	assert.Equal(tester, context.Background(), ctx)
}
