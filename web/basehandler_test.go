package web

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConvertErrorToSafeString(tester *testing.T) {
	assert.Equal(tester, "ERROR_FOO", ConvertErrorToSafeString(errors.New("ERROR_FOO")))
	assert.Equal(tester, GENERIC_ERROR_MESSAGE, ConvertErrorToSafeString(errors.New("ERROR2_FOO")))
}
