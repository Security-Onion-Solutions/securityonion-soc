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

func TestVerifyUser(tester *testing.T) {
	user := NewUser()
	assert.Nil(tester, user.Verify())

	user.Id = "This is way too long of a string, I mean it's just absurd to think someone would actually type such an obnoxiously long value here, right? Right?"
	assert.ErrorContains(tester, user.Verify(), "ERROR_USER_ID_TOO_LONG")
	user.Id = "1210614a-36ca-4df8-84c6-69f774424d5b"

	user.FirstName = "This is way too long of a string, I mean it's just absurd to think someone would actually type such an obnoxiously long value here, right? Right?"
	assert.ErrorContains(tester, user.Verify(), "ERROR_FIRSTNAME_TOO_LONG")
	user.FirstName = "Bob"

	user.LastName = "This is way too long of a string, I mean it's just absurd to think someone would actually type such an obnoxiously long value here, right? Right?"
	assert.ErrorContains(tester, user.Verify(), "ERROR_LASTNAME_TOO_LONG")
	user.LastName = "Smith"

	user.Note = "This is way too long of a string, I mean it's just absurd to think someone would actually type such an obnoxiously long value here, right? Right?"
	assert.ErrorContains(tester, user.Verify(), "ERROR_NOTE_TOO_LONG")
	user.Note = "Great guy, that Bob."

	user.Roles = append(user.Roles, "This is way too long of a string, I mean it's just absurd to think someone would actually type such an obnoxiously long value here, right? Right?")
	assert.ErrorContains(tester, user.Verify(), "ERROR_ROLE_TOO_LONG")
	user.Roles = []string{"test/read"}

	assert.Nil(tester, user.Verify())
}
