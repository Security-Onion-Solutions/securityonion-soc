// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

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
