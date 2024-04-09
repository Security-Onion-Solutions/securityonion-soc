// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package util

import "strings"

func Ptr[T any](x T) *T {
	return &x
}

func Copy[T any](x *T) *T {
	if x == nil {
		return nil
	}

	return Ptr(*x)
}

func TabsToSpaces(s string) string {
	lines := strings.Split(s, "\n")
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
			lines[i] = strings.Repeat("  ", tabs) + strings.TrimSpace(lines[i])
		}
	}

	return strings.Join(lines, "\n")
}
