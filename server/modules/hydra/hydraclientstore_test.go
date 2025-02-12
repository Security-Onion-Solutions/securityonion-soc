// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package hydra

import (
	"context"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/stretchr/testify/assert"
)

func TestClientstoreInit(tester *testing.T) {
	ai := NewHydraClientstore(nil)
	err := ai.Init("abc")
	assert.Nil(tester, err)
}

func TestUnauthorized(tester *testing.T) {
	clientStore := NewHydraClientstore(server.NewFakeUnauthorizedServer())

	clients, err := clientStore.GetClients(context.Background())
	assert.Nil(tester, err)
	assert.Len(tester, clients, 0)

	client, err := clientStore.GetClient(context.Background(), "some-id")
	assert.Nil(tester, err)
	assert.Nil(tester, client)
}
