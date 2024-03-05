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
