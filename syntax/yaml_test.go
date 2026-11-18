// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package syntax

import (
	"errors"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/stretchr/testify/assert"
)

func TestValidate_Yaml(tester *testing.T) {
	for _, syntax := range []string{"yaml", "yml"} {
		assert.NoError(tester, Validate("valid: yaml", syntax))
		assert.NoError(tester, Validate("- one\n- two", syntax))
		assert.NoError(tester, Validate("map_of_list:\n  - one\n  - two", syntax))
		assert.ErrorIs(tester, Validate("[ lksdgf invalid yaml", syntax), ErrMalformedYamlLine)
	}
}

func TestValidateYaml_MalformedLine(tester *testing.T) {
	tests := []struct {
		name  string
		value string
		line  int
	}{
		{name: "parser error on first line", value: "[ lksdgf invalid yaml", line: 1},
		{name: "parser error on later line", value: "a: 1\nb: 2\nc: [\n", line: 3},
		{name: "tab indentation", value: "a:\n\tb: 1", line: 2},
		{name: "duplicate key", value: "a: 1\na: 2", line: 2},
	}

	for _, test := range tests {
		tester.Run(test.name, func(t *testing.T) {
			err := ValidateYaml(test.value)
			assert.ErrorIs(t, err, ErrMalformedYamlLine)

			var argsErr *model.ErrorWithArgs
			if assert.True(t, errors.As(err, &argsErr)) {
				assert.Equal(t, "ERROR_MALFORMED_YAML_LINE", argsErr.Code)
				assert.Equal(t, map[string]interface{}{"line": test.line}, argsErr.Args)
			}
		})
	}
}

func TestValidateYaml_MalformedNoLine(tester *testing.T) {
	err := ValidateYaml("a: \x01")
	assert.Equal(tester, ErrMalformedYaml, err)
}
