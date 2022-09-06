// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package thehive

import (
  "context"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/server"
  "github.com/stretchr/testify/assert"
  "testing"
)

func TestCreateUnauthorized(tester *testing.T) {
  casestore := NewTheHiveCasestore(server.NewFakeUnauthorizedServer())
  casestore.Init("some/url", "somekey", true)
  socCase := model.NewCase()
  newCase, err := casestore.Create(context.Background(), socCase)
  assert.Error(tester, err)
  assert.Nil(tester, newCase)
}

func TestCreate(tester *testing.T) {
  casestore := NewTheHiveCasestore(server.NewFakeAuthorizedServer(nil))
  casestore.Init("some/url", "somekey", true)
  caseResponse := `
    {
      "caseId": 123,
      "title": "my title"
    }`
  casestore.client.MockStringResponse(caseResponse, 200, nil)
  socCase := model.NewCase()
  newCase, err := casestore.Create(context.Background(), socCase)
  assert.NoError(tester, err)

  assert.Equal(tester, "my title", newCase.Title)
  assert.Equal(tester, "123", newCase.Id)
}
