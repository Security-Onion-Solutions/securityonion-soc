// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package modules

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/stretchr/testify/assert"
)

func TestBuildModuleMap(t *testing.T) {
	mm := BuildModuleMap(&server.Server{})
	findModule(t, mm, "elastic")
	findModule(t, mm, "elasticcases")
	findModule(t, mm, "filedatastore")
	findModule(t, mm, "salt")
	findModule(t, mm, "httpcase")
	findModule(t, mm, "kratos")
	findModule(t, mm, "influxdb")
	findModule(t, mm, "sostatus")
	findModule(t, mm, "statickeyauth")
	findModule(t, mm, "thehive")
	findModule(t, mm, "suricataengine")
	findModule(t, mm, "elastalertengine")
	findModule(t, mm, "strelkaengine")
}

func findModule(t *testing.T, mm map[string]module.Module, module string) {
	_, ok := mm[module]
	assert.True(t, ok)
}
