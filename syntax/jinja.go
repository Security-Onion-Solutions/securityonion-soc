// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package syntax

import (
	"strings"
)

func EscapeJinja(value string) string {
	value = strings.ReplaceAll(value, "{{", "[SO_JINJA_SL_START]")
	value = strings.ReplaceAll(value, "}}", "[SO_JINJA_SL_END]")

	value = strings.ReplaceAll(value, "{#", "[SO_JINJA_CM_START]")
	value = strings.ReplaceAll(value, "#}", "[SO_JINJA_CM_END]")

	value = strings.ReplaceAll(value, "{%", "[SO_JINJA_ML_START]")
	value = strings.ReplaceAll(value, "%}", "[SO_JINJA_ML_END]")

	return value
}

func UnescapeJinja(value string) string {
	value = strings.ReplaceAll(value, "[SO_JINJA_SL_START]", "{{")
	value = strings.ReplaceAll(value, "[SO_JINJA_SL_END]", "}}")

	value = strings.ReplaceAll(value, "[SO_JINJA_CM_START]", "{#")
	value = strings.ReplaceAll(value, "[SO_JINJA_CM_END]", "#}")

	value = strings.ReplaceAll(value, "[SO_JINJA_ML_START]", "{%")
	value = strings.ReplaceAll(value, "[SO_JINJA_ML_END]", "%}")

	return value
}
