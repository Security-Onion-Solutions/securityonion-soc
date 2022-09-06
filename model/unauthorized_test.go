// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewUnauthorized(tester *testing.T) {
	event := NewUnauthorized("mysubject", "myop", "mytarget")
	assert.NotZero(tester, event.CreateTime)
	assert.Equal(tester, "mysubject", event.Subject)
	assert.Equal(tester, "myop", event.Operation)
	assert.Equal(tester, "mytarget", event.Target)
}
