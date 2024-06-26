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

func TestValidate_Jinja(tester *testing.T) {
	for _, input := range []string{"Testing Jinja {{ test }}", "Alternative {% test %} form", "comments {# this is a comment #}"} {
		assert.EqualError(tester, Validate(input, "na"), "ERROR_JINJA_NOT_SUPPORTED")
	}
}

func TestValidate_NoJinja(tester *testing.T) {
	for _, input := range []string{"Testing Jinja {\"foo\":\"bar\"}", "Alternative %% foo"} {
		assert.NoError(tester, Validate(input, "na"))
	}
}
