// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package generichttp

import (
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/stretchr/testify/assert"
  "io"
  "testing"
  "time"
)

func TestConvertCaseToReader(tester *testing.T) {
  socCase := model.NewCase()
  socCase.Id = "123"
  tm, _ := time.Parse("2006-01-03 13:04 PM", "2006-01-03 13:04 PM")
  socCase.CreateTime = &tm
  socCase.Title = "MyTitle"
  socCase.Description = "My \"Description\" is this."
  socCase.Severity = "medium"

  source := `ID: {{ .Id }}; Title: {{ .Title }}; Desc: {{ .Description | js }}; Sev: {{ .Severity }}; Time: {{ .CreateTime.Format "15:04" }}`

  reader, err1 := convertCaseToReader(source, socCase)
  assert.NoError(tester, err1)

  bytes, err2 := io.ReadAll(reader)
  assert.NoError(tester, err2)

  converted := string(bytes)
  assert.Equal(tester, "ID: 123; Title: MyTitle; Desc: My \\\"Description\\\" is this.; Sev: medium; Time: 00:00", converted)
}
