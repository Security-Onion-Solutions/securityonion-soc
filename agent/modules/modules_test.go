// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package modules

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/module"
)

func TestBuildModuleMap(tester *testing.T) {
	mm := BuildModuleMap(nil)
	findModule(tester, mm, "analyze")
	findModule(tester, mm, "importer")
	findModule(tester, mm, "statickeyauth")
	findModule(tester, mm, "stenoquery")
}

func findModule(tester *testing.T, mm map[string]module.Module, module string) {
	if _, ok := mm[module]; !ok {
		tester.Errorf("missing module %s", module)
	}
}
