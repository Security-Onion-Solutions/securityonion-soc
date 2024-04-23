// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package util

import (
	"testing"

	"github.com/tj/assert"
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
