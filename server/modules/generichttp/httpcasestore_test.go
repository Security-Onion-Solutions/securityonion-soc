// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package generichttp

import (
  "context"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/module"
  "github.com/security-onion-solutions/securityonion-soc/server"
  "github.com/stretchr/testify/assert"
  "testing"
)

func TestCreateUnauthorized(tester *testing.T) {
  casestore := NewHttpCasestore(server.NewFakeUnauthorizedServer())
  casestore.Init("some/url", true, nil, nil)
  socCase := model.NewCase()
  newCase, err := casestore.Create(context.Background(), socCase)
  assert.Error(tester, err)
  assert.Nil(tester, newCase)
}

func TestCreate(tester *testing.T) {
  casestore := NewHttpCasestore(server.NewFakeAuthorizedServer(nil))
  cfg := make(module.ModuleConfig)
  params := NewGenericHttpParams(cfg, "create")
  casestore.Init("some/url", true, nil, params)
  caseResponse := ""
  casestore.client.MockStringResponse(caseResponse, 200, nil)
  socCase := model.NewCase()
  newCase, err := casestore.Create(context.Background(), socCase)
  assert.NoError(tester, err)
  assert.Nil(tester, newCase)
}

func TestCreateFail(tester *testing.T) {
  casestore := NewHttpCasestore(server.NewFakeAuthorizedServer(nil))
  cfg := make(module.ModuleConfig)
  params := NewGenericHttpParams(cfg, "create")
  casestore.Init("some/url", true, nil, params)
  caseResponse := ""
  casestore.client.MockStringResponse(caseResponse, 500, nil)
  socCase := model.NewCase()
  newCase, err := casestore.Create(context.Background(), socCase)
  assert.Error(tester, err)
  assert.Nil(tester, newCase)
}
