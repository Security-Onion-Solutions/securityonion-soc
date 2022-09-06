// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package statickeyauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInitStaticKeyAuth(tester *testing.T) {
	cfg := make(map[string]interface{})
	auth := NewStaticKeyAuth(nil)
	err := auth.Init(cfg)
	assert.Error(tester, err)

	cfg["apiKey"] = "123"
	err = auth.Init(cfg)
	assert.Error(tester, err)
	assert.Equal(tester, "123", auth.apiKey)
}
