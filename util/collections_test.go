package util

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTruncateMap(t *testing.T) {
	errMap := map[string]error{
		"db6c06c4-bf3b-421c-aa88-15672b88c743": errors.New("error 1"),
		"db92dd33-a3ad-49cf-8c2c-608c3e30ace0": errors.New("error 2"),
		"dbc1f800-0fe0-4bc0-9c66-292c2abe3f78": errors.New("error 3"),
		"Random key":                           errors.New("random value"),
	}

	// Test truncating to one element
	truncatedErrMap := TruncateMap(errMap, 2)
	assert.Equal(t, 2, len(truncatedErrMap), "Truncated map should have exactly two elements.")

	// Ensure the key in the truncated map exists in the original map and has the correct error message
	for key, val := range truncatedErrMap {
		assert.Equal(t, errMap[key], val, "Error messages should match for truncated keys.")
	}

	// Test truncating to more elements than exist in the map
	truncatedErrMap = TruncateMap(errMap, 10)
	assert.Equal(t, len(errMap), len(truncatedErrMap), "Truncated map should equal the original map in size when the limit exceeds the number of map elements.")

	// Test truncating to zero elements
	truncatedErrMap = TruncateMap(errMap, 0)
	assert.Equal(t, 0, len(truncatedErrMap), "Truncated map should have no elements when limit is 0.")
}

func TestTruncateList(t *testing.T) {
	tests := []struct {
		Name       string
		Array      []int
		TruncateTo uint
		ExpArray   []int
	}{
		{
			Name:       "Empty",
			Array:      []int{},
			TruncateTo: 10,
			ExpArray:   []int{},
		},
		{
			Name:       "Below Limit",
			Array:      []int{0},
			TruncateTo: 10,
			ExpArray:   []int{0},
		},
		{
			Name:       "At Limit",
			Array:      []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			TruncateTo: 10,
			ExpArray:   []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		},
		{
			Name:       "Above Limit",
			Array:      []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			TruncateTo: 5,
			ExpArray:   []int{0, 1, 2, 3, 4},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			truncated := TruncateList(test.Array, test.TruncateTo)
			assert.Equal(t, test.ExpArray, truncated)
		})
	}
}
