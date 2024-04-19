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
	var n *string

	assert.True(t, Compare(x, x))
	assert.True(t, Compare(n, n))
	assert.False(t, Compare(x, o))
	assert.False(t, Compare(n, o))
	assert.False(t, Compare(x, n))
	assert.False(t, Compare(o, n))
}
