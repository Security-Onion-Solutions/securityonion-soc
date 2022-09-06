// Copyright Jason Ertel (github.com/jertel).
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
	userstore.Init("some/url")
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

	handler := NewKratosPreprocessor(userstore)
	request, _ := http.NewRequest("GET", "", nil)

	request.Header.Set("x-user-id", expectedId)

	ctx, statusCode, err := handler.Preprocess(context.Background(), request)
	if assert.Nil(tester, err) {
		assert.Zero(tester, statusCode)
		assert.NotNil(tester, ctx)
	}

	requestor := ctx.Value(web.ContextKeyRequestor)
	assert.NotNil(tester, requestor)

	actualId := requestor.(*model.User).Id
	assert.Equal(tester, expectedId, actualId)

	requestorId := ctx.Value(web.ContextKeyRequestorId)
	if assert.NotNil(tester, requestorId) {
		assert.Equal(tester, expectedId, requestorId)
	}
}
