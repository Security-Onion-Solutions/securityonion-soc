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

func TestNewGridMember(tester *testing.T) {
	// Test typical use case
	member := NewGridMember("foo_bar", "rejected", "aa:bb")
	assert.Equal(tester, "foo_bar", member.Id)
	assert.Equal(tester, "foo", member.Name)
	assert.Equal(tester, "bar", member.Role)
	assert.Equal(tester, "aa:bb", member.Fingerprint)
	assert.Equal(tester, "rejected", member.Status)

	// Test hostname with underscore corner case
	member = NewGridMember("foo_bar_car", "rejected", "aa:bb")
	assert.Equal(tester, "foo_bar_car", member.Id)
	assert.Equal(tester, "foo_bar", member.Name)
	assert.Equal(tester, "car", member.Role)
	assert.Equal(tester, "aa:bb", member.Fingerprint)
	assert.Equal(tester, "rejected", member.Status)
}
