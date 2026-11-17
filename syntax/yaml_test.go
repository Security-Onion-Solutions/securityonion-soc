// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
		assert.NoError(tester, Validate("- one\n- two", syntax))
		assert.NoError(tester, Validate("map_of_list:\n  - one\n  - two", syntax))
		assert.EqualError(tester, Validate("[ lksdgf invalid yaml", syntax), "ERROR_MALFORMED_YAML 1")
	}
}

func TestValidateYaml_MalformedLine(tester *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "parser error on later line", value: "a: 1\nb: 2\nc: [\n", want: "ERROR_MALFORMED_YAML 3"},
		{name: "tab indentation", value: "a:\n\tb: 1", want: "ERROR_MALFORMED_YAML 2"},
		{name: "duplicate key", value: "a: 1\na: 2", want: "ERROR_MALFORMED_YAML 2"},
		{name: "no line in parser error", value: "a: \x01", want: "ERROR_MALFORMED_YAML"},
	}

	for _, test := range tests {
		tester.Run(test.name, func(t *testing.T) {
			err := ValidateYaml(test.value)
			assert.EqualError(t, err, test.want)
			assert.ErrorIs(t, err, ErrMalformedYaml)
		})
	}
}
