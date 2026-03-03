// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifyClient(tester *testing.T) {
	client := NewClient()
	assert.Nil(tester, client.Verify())

	client.Id = "This is way too long of a string, I mean it's just absurd to think someone would actually type such an obnoxiously long value here, right? Right?"
	assert.ErrorContains(tester, client.Verify(), "ERROR_CLIENT_ID_TOO_LONG")
	client.Id = "socl_bob"

	client.Name = "This is way too long of a string, I mean it's just absurd to think someone would actually type such an obnoxiously long value here, right? Right?"
	assert.ErrorContains(tester, client.Verify(), "ERROR_NAME_TOO_LONG")
	client.Name = "Bob"

	client.Note = "This is way too long of a string, I mean it's just absurd to think someone would actually type such an obnoxiously long value here, right? Right?"
	assert.ErrorContains(tester, client.Verify(), "ERROR_NOTE_TOO_LONG")
	client.Note = "Great guy, that Bob."

	client.Permissions = append(client.Permissions, "This is way too long of a string, I mean it's just absurd to think someone would actually type such an obnoxiously long value here, right? Right?")
	assert.ErrorContains(tester, client.Verify(), "ERROR_PERMISSION_TOO_LONG")
	client.Permissions = []string{"test/read"}

	assert.Nil(tester, client.Verify())
}

func TestIsClient(tester *testing.T) {
	assert.True(tester, IsClient("socl_123"))
	assert.True(tester, IsClient("socl_"))
	assert.False(tester, IsClient("socl"))
	assert.False(tester, IsClient("123"))
	assert.False(tester, IsClient(""))
}
