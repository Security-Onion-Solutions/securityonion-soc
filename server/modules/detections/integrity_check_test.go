package detections

import (
	"sort"
	"testing"

	"github.com/tj/assert"
)

func TestDiffLists(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Name     string
		A        []string
		B        []string
		ExpOnlyA []string
		ExpOnlyB []string
		ExpBoth  []string
	}{
		{
			Name:     "empty lists",
			A:        []string{},
			B:        []string{},
			ExpOnlyA: []string{},
			ExpOnlyB: []string{},
			ExpBoth:  []string{},
		},
		{
			Name:     "A empty",
			A:        []string{},
			B:        []string{"a", "b", "c"},
			ExpOnlyA: []string{},
			ExpOnlyB: []string{"a", "b", "c"},
			ExpBoth:  []string{},
		},
		{
			Name:     "B empty",
			A:        []string{"a", "b", "c"},
			B:        []string{},
			ExpOnlyA: []string{"a", "b", "c"},
			ExpOnlyB: []string{},
			ExpBoth:  []string{},
		},
		{
			Name:     "A and B same",
			A:        []string{"a", "b", "c"},
			B:        []string{"a", "b", "c"},
			ExpOnlyA: []string{},
			ExpOnlyB: []string{},
			ExpBoth:  []string{"a", "b", "c"},
		},
		{
			Name:     "A and B different",
			A:        []string{"a", "b", "c"},
			B:        []string{"d", "e", "f"},
			ExpOnlyA: []string{"a", "b", "c"},
			ExpOnlyB: []string{"d", "e", "f"},
			ExpBoth:  []string{},
		},
		{
			Name:     "A and B some overlap",
			A:        []string{"a", "b", "c"},
			B:        []string{"b", "c", "d"},
			ExpOnlyA: []string{"a"},
			ExpOnlyB: []string{"d"},
			ExpBoth:  []string{"b", "c"},
		},
		{
			Name:     "A and B same elements, different order",
			A:        []string{"a", "b", "c"},
			B:        []string{"c", "b", "a"},
			ExpOnlyA: []string{},
			ExpOnlyB: []string{},
			ExpBoth:  []string{"a", "b", "c"},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			onlyA, onlyB, both := DiffLists(test.A, test.B)

			sort.Strings(onlyA)
			sort.Strings(onlyB)
			sort.Strings(both)
			sort.Strings(test.ExpOnlyA)
			sort.Strings(test.ExpOnlyB)
			sort.Strings(test.ExpBoth)

			assert.Equal(t, test.ExpOnlyA, onlyA)
			assert.Equal(t, test.ExpOnlyB, onlyB)
			assert.Equal(t, test.ExpBoth, both)
		})
	}
}
