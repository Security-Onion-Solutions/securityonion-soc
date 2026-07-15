// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package util

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnquote(t *testing.T) {
	table := []struct {
		Name     string
		Input    string
		Expected string
	}{
		{
			Name:     "Empty",
			Input:    "",
			Expected: "",
		}, {
			Name:     "Unquoted",
			Input:    "foo",
			Expected: "foo",
		}, {
			Name:     "DoubleQuoted",
			Input:    `"foo"`,
			Expected: "foo",
		}, {
			Name:     "SingleQuoted",
			Input:    "'foo'",
			Expected: "foo",
		}, {
			Name:     "Double DoubleQuoted",
			Input:    `""foo""`,
			Expected: `"foo"`,
		}, {
			Name:     "Double SingleQuoted",
			Input:    `''foo''`,
			Expected: `'foo'`,
		}, {
			Name:     "Lopsided Quotes A",
			Input:    `"foo'`,
			Expected: `"foo'`,
		}, {
			Name:     "Lopsided Quotes B",
			Input:    `'foo"`,
			Expected: `'foo"`,
		}, {
			Name:     "Intermingled Quotes A",
			Input:    `"foo'"bar"`,
			Expected: `foo'"bar`,
		}, {
			Name:     "Intermingled Quotes B",
			Input:    `'foo'"bar'`,
			Expected: `foo'"bar`,
		},
	}

	for _, test := range table {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			actual := Unquote(test.Input)

			assert.Equal(t, test.Expected, actual)
		})
	}
}

func TestTabsToSpaces(t *testing.T) {
	tests := []struct {
		Name       string
		SpaceCount uint
		Input      string
		Output     string
	}{
		{
			Name:       "Empty",
			SpaceCount: 2,
			Input:      "",
			Output:     "",
		},
		{
			Name:       "No Tabs",
			SpaceCount: 2,
			Input:      "foo",
			Output:     "foo",
		},
		{
			Name:       "Single Tab",
			SpaceCount: 2,
			Input:      "\tfoo",
			Output:     "  foo",
		},
		{
			Name:       "Multiple Tabs",
			SpaceCount: 2,
			Input:      "\t\tfoo",
			Output:     "    foo",
		},
		{
			Name:       "Multiple Lines",
			SpaceCount: 2,
			Input:      "\tfoo\n\tbar",
			Output:     "  foo\n  bar",
		},
		{
			Name:       "Mixed Tabs and Spaces",
			SpaceCount: 2,
			Input:      "\t  foo \t",
			Output:     "    foo \t",
		},
		{
			Name:       "Multilevel Tabs",
			SpaceCount: 2,
			Input:      "\tfoo\n\t\tbar",
			Output:     "  foo\n    bar",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			actual := TabsToSpaces(test.Input, test.SpaceCount)

			assert.Equal(t, test.Output, actual)
		})
	}
}

func TestCompare(t *testing.T) {
	x := Ptr("X")
	o := Ptr("O")
	z := Ptr("0")
	var n *string

	assert.True(t, ComparePtrs(x, x))
	assert.True(t, ComparePtrs(n, n))
	assert.False(t, ComparePtrs(x, o))
	assert.False(t, ComparePtrs(n, o))
	assert.False(t, ComparePtrs(x, n))
	assert.False(t, ComparePtrs(o, n))
	assert.False(t, ComparePtrs(z, x))
	assert.False(t, ComparePtrs(z, o))
	assert.False(t, ComparePtrs(o, z))
	assert.False(t, ComparePtrs(x, z))
}

func TestToUUID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "b51e85a6-fc67-48f5-b83e-6e6dd3e13d01"},
		{"test", "21399f9a-a347-4ff4-b94b-7286b575aada"},
		{"example", "2b9a9ab7-92d6-48ce-bac9-a94603dc33ff"},
	}

	for _, test := range tests {
		got := ToUUID(test.input)
		assert.Equal(t, test.expected, got)
	}
}

func TestToUUID_FormatCheck(t *testing.T) {
	uuid := ToUUID("format-check")
	matched, err := regexp.MatchString(`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-b[a-f0-9]{3}-[a-f0-9]{12}$`, uuid)
	assert.NoError(t, err)
	assert.True(t, matched)
}

func TestToUUID_ConsistencyCheck(t *testing.T) {
	got := ToUUID("repeat-test")
	for i := 0; i < 1000; i++ {
		assert.Equal(t, got, ToUUID("repeat-test"))
	}
}

func TestEscapeLucene(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Empty", "", ""},
		{"Simple", "simple", "simple"},
		{"Backslash", `back\slash`, `back\\slash`},
		{"Quote", `quote"me`, `quote\"me`},
		{"Multiple Quotes", `""quote""`, `\"\"quote\"\"`},
		{"Mixed", `\"quote\"\\`, `\\\"quote\\\"\\\\`},
		{"Attack - OR", `foo" OR 1=1`, `foo\" OR 1=1`},
		{"Attack - AND", `foo" AND "bar"="bar`, `foo\" AND \"bar\"=\"bar`},
		{"Attack - Wildcard", `foo" *`, `foo\" *`},
		{"Attack - Semicolon", `foo"; DROP INDEX index;`, `foo\"; DROP INDEX index;`},
		{"Attack - Path Traversal", `../../etc/passwd"`, `../../etc/passwd\"`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := EscapeLucene(test.input)
			assert.Equal(t, test.expected, got)
		})
	}
}

func TestEscapePainless(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Empty", "", ""},
		{"Simple", "simple", "simple"},
		{"Backslash", `back\slash`, `back\\slash`},
		{"Single Quote", `it's me`, `it\'s me`},
		{"Double Quotes", `quote "me"`, `quote "me"`}, // Painless uses single quotes for strings in our usage
		{"Mixed", `\'quote\'\\`, `\\\'quote\\\'\\\\`},
		{"Attack - Escape", `'; ctx._source.event.severity = 'critical'; '`, `\'; ctx._source.event.severity = \'critical\'; \'`},
		{"Attack - System Exit", `'; System.exit(0); '`, `\'; System.exit(0); \'`},
		{"Attack - Loop", `'; while(true); '`, `\'; while(true); \'`},
		{"Attack - Comments", `'; // comment`, `\'; // comment`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := EscapePainless(test.input)
			assert.Equal(t, test.expected, got)
		})
	}
}

func TestSanitizeNic(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Empty", "", ""},
		{"Simple", "eth0", "eth0"},
		{"Space", "eth 0", "eth-0"},
		{"Ampersand", "eth&0", "eth-0"},
		{"Underscore", "eth_0", "eth_0"},
		{"Equal", "eth=0", "eth-0"},
		{"Plus", "eth+0", "eth-0"},
		{"Colon", "eth:0", "eth-0"},
		{"Slash", "eth/0", "eth-0"},
		{"Double Dot", "eth..0", "eth-0"},
		{"Trim Leading Space", "  eth0", "eth0"},
		{"Trim Trailing Space", "eth0  ", "eth0"},
		{"Trim Both", "  eth0  ", "eth0"},
		{"Multiple separators", "eth_0/1:2", "eth_0-1-2"},
		{"Path traversal - Relative linux", "../../etc/passwd", "----etc-passwd"},
		{"Path traversal - Absolute linux", "/etc/passwd", "-etc-passwd"},
		{"Path traversal - Windows", `..\..\windows\win.ini`, `----windows-win.ini`},
		{"Path traversal - Relative dots", "...", "-."},
		{"Path traversal - Dot", ".", "."},
		{"Path traversal - Double Dot", "..", "-"},
		{"Path traversal - Quad Dot", "....", "--"},
		{"Path traversal - Windows drive", `C:\boot.ini`, `C--boot.ini`},
		{"Device files", "/dev/urandom", "-dev-urandom"},
		{"Path traversal - Spaced dots", ".. /.. /etc/passwd", "------etc-passwd"},
		{"Path traversal - Combined", `eth0\..\..\..\etc\passwd`, `eth0-------etc-passwd`},
		{"Unicode standard - Japanese", "eth0日本語", "eth0---"},
		{"Unicode emoji", "eth0😀", "eth0-"},
		{"Unicode spaces - Ideographic space", "\u3000eth0\u3000", "eth0"},
		{"Unicode fullwidth separators", "eth0／1：2＝3", "eth0-1-2-3"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := SanitizeNic(test.input)
			assert.Equal(t, test.expected, got)
		})
	}
}

