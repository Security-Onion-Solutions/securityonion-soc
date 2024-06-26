// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package syntax

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidate_Yaml(tester *testing.T) {
	for _, syntax := range []string{"yaml", "yml"} {
		assert.NoError(tester, Validate("valid: yaml", syntax))
		assert.EqualError(tester, Validate("invalid yaml", syntax), "ERROR_MALFORMED_YAML -> yaml: unmarshal errors:\n  line 1: cannot unmarshal !!str `invalid...`")
	}
}
