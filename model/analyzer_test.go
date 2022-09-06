// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
  "github.com/stretchr/testify/assert"
  "testing"
)

func TestGetModule(tester *testing.T) {
  analyzer := NewAnalyzer("id", "path")
  assert.Equal(tester, "id.id", analyzer.GetModule())
  assert.Equal(tester, "path/site-packages", analyzer.GetSitePackagesPath())
  assert.Equal(tester, "path/source-packages", analyzer.GetSourcePackagesPath())
  assert.Equal(tester, "path/requirements.txt", analyzer.GetRequirementsPath())
}
