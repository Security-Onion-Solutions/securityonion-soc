package util_test

import (
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/util"

	"github.com/stretchr/testify/assert"
)

func TestOverlap(t *testing.T) {
	first := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	second := time.Date(2021, 1, 2, 0, 0, 0, 0, time.UTC)
	third := time.Date(2021, 1, 3, 0, 0, 0, 0, time.UTC)
	forth := time.Date(2021, 1, 4, 0, 0, 0, 0, time.UTC)

	assert.False(t, util.Overlap(first, second, third, forth))
	assert.False(t, util.Overlap(third, forth, first, second))
	assert.False(t, util.Overlap(second, first, forth, third))
	assert.False(t, util.Overlap(first, first, second, second))
	assert.False(t, util.Overlap(first, second, third, third))
	assert.True(t, util.Overlap(first, forth, second, third))
	assert.True(t, util.Overlap(second, third, first, forth))
	assert.True(t, util.Overlap(first, second, second, third))
	assert.True(t, util.Overlap(first, third, second, forth))
	assert.True(t, util.Overlap(second, forth, first, third))
	assert.True(t, util.Overlap(first, forth, first, third))
	assert.True(t, util.Overlap(first, forth, second, forth))
	assert.True(t, util.Overlap(first, forth, first, forth))
	assert.True(t, util.Overlap(first, forth, forth, forth))
	assert.True(t, util.Overlap(first, forth, first, first))
}
