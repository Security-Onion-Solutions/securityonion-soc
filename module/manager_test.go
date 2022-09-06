// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package module

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMeetsPrerequisites(tester *testing.T) {
	mgr := NewModuleManager()
	mcm := make(ModuleConfigMap)

	prereqs := make([]string, 0)
	prereqs = append(prereqs, "foo")
	prereqs = append(prereqs, "bar")

	actual := mgr.meetsPrerequisites(prereqs, mcm)
	assert.False(tester, actual)

	mcm["foo"] = make(ModuleConfig)
	actual = mgr.meetsPrerequisites(prereqs, mcm)
	assert.False(tester, actual)

	mcm["bar"] = make(ModuleConfig)
	actual = mgr.meetsPrerequisites(prereqs, mcm)
	assert.True(tester, actual)
}
