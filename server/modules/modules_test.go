// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package modules

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/stretchr/testify/assert"
)

func TestBuildModuleMap(tester *testing.T) {
	mm := BuildModuleMap(nil)
	findModule(tester, mm, "elastic")
	findModule(tester, mm, "elasticcases")
	findModule(tester, mm, "filedatastore")
	findModule(tester, mm, "salt")
	findModule(tester, mm, "httpcase")
	findModule(tester, mm, "kratos")
	findModule(tester, mm, "influxdb")
	findModule(tester, mm, "sostatus")
	findModule(tester, mm, "statickeyauth")
	findModule(tester, mm, "thehive")
}

func findModule(tester *testing.T, mm map[string]module.Module, module string) {
	_, ok := mm[module]
	assert.True(tester, ok)
}
