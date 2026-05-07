// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRelPathFromId(t *testing.T) {
	assert.Equal(t, "foo/bar/test.md", RelPathFromId("foo.bar.test__md"))
	assert.Equal(t, "____/____/____/etc/passwd", RelPathFromId("____.____.____.etc.passwd"))
	assert.Equal(t, "____./____./____./etc/passwd", RelPathFromId("______.______.______.etc.passwd"))
}
