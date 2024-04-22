// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package util

import "strings"

func Unquote(value string) string {
	if strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
		value = strings.TrimSuffix(strings.TrimPrefix(value, `"`), `"`)
	} else if strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'") {
		value = strings.TrimSuffix(strings.TrimPrefix(value, "'"), "'")
	}

	return value
}

func TabsToSpaces(s string, spaceCount uint) string {
	lines := strings.Split(s, "\n")
	fakeTab := strings.Repeat(" ", int(spaceCount))

	for i := range lines {
		tabs := 0
		for _, c := range lines[i] {
			if c == '\t' {
				tabs++
			} else {
				break
			}
		}

		if tabs != 0 {
			lines[i] = strings.Repeat(fakeTab, tabs) + strings.TrimLeft(lines[i], "\t")
		}
	}

	return strings.Join(lines, "\n")
}

func ComparePtrs[T comparable](a, b *T) bool {
	if a == nil && b == nil {
		return true
	} else if a == nil || b == nil {
		return false
	}

	return *a == *b
}
