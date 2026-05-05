// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package util

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

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

func ToUUID(s string) string {
	// Convert a string to a UUID deterministically

	// hash the string, get 32 bytes
	hash := sha256.Sum256([]byte(s))

	// 32 bytes => 16 bytes
	for i := 0; i < 16; i++ {
		hash[i] = hash[i] ^ hash[16+i]
	}
	h := hash[:16]

	// 16 bytes => 15 bytes
	h[0] = h[0] ^ h[15]
	h = h[:15]

	// 15 bytes => 30 hex chars
	hx := hex.EncodeToString(h)

	// 00000000-0000-4000-b000-000000000000
	return fmt.Sprintf("%s-%s-4%s-b%s-%s", hx[:8], hx[8:12], hx[12:15], hx[15:18], hx[18:])
}

func EscapeLucene(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	return value
}

func EscapePainless(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "'", "\\'")
	return value
}
