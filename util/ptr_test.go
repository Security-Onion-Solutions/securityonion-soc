package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEqual(t *testing.T) {
	x := 10
	y := "Hello"

	x1 := &x
	x2 := &x

	y1 := &y
	y2 := &y

	// pointing to the exact same things
	assert.True(t, Equal(x1, x2))
	assert.True(t, Equal(y1, y2))

	x2 = nil
	y2 = Copy[string](nil)

	// nil != non-nil
	assert.False(t, Equal(x1, x2))
	assert.False(t, Equal(y1, y2))

	x1 = nil
	y1 = nil

	// nil == nil
	assert.True(t, Equal(x1, x2))
	assert.True(t, Equal(y1, y2))

	x1 = Ptr(x)
	y1 = Ptr(y)

	x2 = Ptr(20)
	y2 = Ptr("World")

	// non-nil, but different values
	assert.False(t, Equal(x1, x2))
	assert.False(t, Equal(y1, y2))

	x2 = Copy(x1)
	y2 = Copy(y1)

	// pointing to different addresses holding the same values
	assert.True(t, Equal(x1, x2))
	assert.True(t, Equal(y1, y2))
}
