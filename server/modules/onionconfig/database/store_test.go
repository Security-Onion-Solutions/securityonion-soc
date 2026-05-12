// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeValue_EmptyString(t *testing.T) {
	b, err := encodeValue("")
	assert.NoError(t, err)
	assert.Equal(t, "null", string(b))
}

func TestEncodeValue_NullString(t *testing.T) {
	b, err := encodeValue("null")
	assert.NoError(t, err)
	assert.Equal(t, "null", string(b))
}

func TestEncodeValue_AlreadyValidJSON(t *testing.T) {
	b, err := encodeValue(`{"key":"value"}`)
	assert.NoError(t, err)
	assert.Equal(t, `{"key":"value"}`, string(b))
}

func TestEncodeValue_PlainString(t *testing.T) {
	b, err := encodeValue("hello world")
	assert.NoError(t, err)
	assert.Equal(t, `"hello world"`, string(b))
}

func TestEncodeValue_NumberJSON(t *testing.T) {
	b, err := encodeValue("42")
	assert.NoError(t, err)
	assert.Equal(t, "42", string(b))
}

func TestEncodeValue_BoolJSON(t *testing.T) {
	b, err := encodeValue("true")
	assert.NoError(t, err)
	assert.Equal(t, "true", string(b))
}
