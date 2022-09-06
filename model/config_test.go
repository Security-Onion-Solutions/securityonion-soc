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

func TestString(tester *testing.T) {
	setting := NewSetting("MyId")
	assert.Equal(tester, "MyId", setting.Id)
}

func TestIsValidMinionId(tester *testing.T) {
	assert.True(tester, IsValidMinionId("foo"))
	assert.True(tester, IsValidMinionId("foo-bar"))
	assert.True(tester, IsValidMinionId("Foo-bar_car"))
	assert.True(tester, IsValidMinionId("Foo.bar_car"))
	assert.False(tester, IsValidMinionId(""))
	assert.False(tester, IsValidMinionId("Foo bar"))
	assert.False(tester, IsValidMinionId(" "))
	assert.False(tester, IsValidMinionId("foo|bars"))
}

func TestIsValidSettingId(tester *testing.T) {
	assert.True(tester, IsValidSettingId("foo"))
	assert.True(tester, IsValidSettingId("foo-bar"))
	assert.True(tester, IsValidSettingId("Foo-bar_car"))
	assert.True(tester, IsValidSettingId("Foo.bar_car"))
	assert.True(tester, IsValidSettingId("Foo.bar.:car:"))
	assert.False(tester, IsValidSettingId(""))
	assert.False(tester, IsValidSettingId("Foo bar"))
	assert.False(tester, IsValidSettingId(" "))
	assert.False(tester, IsValidSettingId("foo|bars"))
}
