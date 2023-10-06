package options

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// nolint: staticcheck // test file
func TestTimeout(t *testing.T) {
	ctx := WithTimeoutMs(nil, 100)
	assert.NotNil(t, ctx)

	timeout := GetTimeoutMs(ctx)
	assert.Equal(t, 100, timeout)

	timeout = GetTimeoutMs(nil)
	assert.Equal(t, 0, timeout)

	bg := context.Background()
	timeout = GetTimeoutMs(bg)
	assert.Equal(t, 0, timeout)
}
