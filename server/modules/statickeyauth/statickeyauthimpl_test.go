// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package statickeyauth

import (
	"context"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func TestValidateAuthorization(tester *testing.T) {
	validateAuthorization(tester, "abc", "1.1.1.1", true)
	validateAuthorization(tester, "a", "1.1.1.1", false)
	validateAuthorization(tester, "", "1.1.1.1", false)
	validateAuthorization(tester, "", "172.17.1.1", false)
	validateAuthorization(tester, "", "172.17.0.1", true)
	validateAuthorization(tester, "abc", "172.17.0.1", true)
}

func validateAuthorization(tester *testing.T, key string, ip string, expected bool) {
	ai := NewStaticKeyAuthImpl(server.NewFakeAuthorizedServer(nil))
	ai.Init("abc", "172.17.0.0/24")
	actual := ai.validateAuthorization(context.Background(), key, ip)
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
	err := ai.Init("abc", "1")
	assert.Error(tester, err)
	err = ai.Init("abc", "1.2.3.4/16")
	if assert.Nil(tester, err) {
		assert.Equal(tester, "abc", ai.apiKey)
		assert.Equal(tester, "1.2.0.0/16", ai.anonymousNetwork.String())
	}
}

func TestPreprocessPriority(tester *testing.T) {
	handler := NewStaticKeyAuthImpl(server.NewFakeAuthorizedServer(nil))
	assert.Equal(tester, 100, handler.PreprocessPriority())
}

func TestPreprocess(tester *testing.T) {
	ai := NewStaticKeyAuthImpl(server.NewFakeAuthorizedServer(nil))
	err := ai.Init("abc", "1")
	assert.Error(tester, err)
	ai.apiKey = "123"
	request, _ := http.NewRequest("GET", "", nil)
	request.Header.Set("authorization", ai.apiKey)
	ctx, statusCode, err := ai.Preprocess(context.Background(), request)
	if assert.Nil(tester, err) {
		assert.Zero(tester, statusCode)
		if assert.NotNil(tester, ctx) {
			requestor := ctx.Value(web.ContextKeyRequestor)
			if assert.NotNil(tester, requestor) {
				sensorUser := requestor.(*model.User)
				assert.NotNil(tester, sensorUser)
				assert.Equal(tester, "agent", sensorUser.Id)
				assert.Equal(tester, "agent", sensorUser.Email)
			}
		}
	}

}
