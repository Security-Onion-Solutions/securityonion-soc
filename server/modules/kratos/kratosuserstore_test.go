// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package kratos

import (
	"context"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestUserstoreInit(tester *testing.T) {
	ai := NewKratosUserstore(nil)
	err := ai.Init("abc")
	assert.Nil(tester, err)
}

func TestUnauthorized(tester *testing.T) {
	userStore := NewKratosUserstore(server.NewFakeUnauthorizedServer())

	_, err := userStore.GetUsers(context.Background())
	ensureUnauthorized(tester, err)

	_, err = userStore.GetUser(context.Background(), "some-id")
	ensureUnauthorized(tester, err)
}

func ensureUnauthorized(tester *testing.T, err error) {
	var authErr *model.Unauthorized
	assert.ErrorAs(tester, err, &authErr)
}
