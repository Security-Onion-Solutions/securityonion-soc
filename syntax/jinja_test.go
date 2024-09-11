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

func TestEscapeUnescapeJinja(tester *testing.T) {
	value := "{% testing %} {{ this }} {# comment #}"
	new_value := EscapeJinja(value)
	expected := "[SO_JINJA_ML_START] testing [SO_JINJA_ML_END] [SO_JINJA_SL_START] this [SO_JINJA_SL_END] [SO_JINJA_CM_START] comment [SO_JINJA_CM_END]"
	assert.Equal(tester, expected, new_value)

	new_value = UnescapeJinja(new_value)
	assert.Equal(tester, value, new_value)
}
