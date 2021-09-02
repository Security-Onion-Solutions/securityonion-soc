// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package kratos

import (
  "context"
  "github.com/security-onion-solutions/securityonion-soc/fake"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/web"
  "net/http"
  "testing"
)

func TestPreprocessPriority(tester *testing.T) {
  handler := NewKratosPreprocessor(nil)
  if handler.PreprocessPriority() != 110 {
    tester.Error("expected 110 priority")
  }
}
func TestPreprocess(tester *testing.T) {
  expectedId := "112233"

  user := model.NewUser()
  user.Id = expectedId
  userstore := NewKratosUserstore(fake.NewAuthorizedServer(make(map[string][]string)))
  userstore.Init("some/url")
  kratosUsersResponseJson := `
    [
      {
        "credentials": {},
        "id": "112233",
        "recovery_addresses": [],
        "state": "active",
        "traits": {
          "email": "",
          "firstname": "",
          "lastname": ""
        },
        "verifiable_addresses": []
      }
    ]`
  userstore.client.MockStringResponse(kratosUsersResponseJson, 200, nil)

  handler := NewKratosPreprocessor(userstore)
  request, _ := http.NewRequest("GET", "", nil)

  request.Header.Set("x-user-id", expectedId)

  ctx, statusCode, err := handler.Preprocess(context.Background(), request)
  if err != nil {
    tester.Errorf("Unexpected error: %v", err)
  }
  if statusCode != 0 {
    tester.Errorf("expected 0 statusCode but got %d", statusCode)
  }
  if ctx == nil {
    tester.Errorf("Unexpected nil context return")
  }

  requestor := ctx.Value(web.ContextKeyRequestor)
  if requestor == nil {
    tester.Errorf("Expected non-nil requestor")
  }
  actualId := requestor.(*model.User).Id
  if actualId != expectedId {
    tester.Errorf("expected %s but got %s", expectedId, actualId)
  }

  requestorId := ctx.Value(web.ContextKeyRequestorId)
  if requestorId == nil {
    tester.Errorf("Expected non-nil requestor ID")
  }
  if requestorId != expectedId {
    tester.Errorf("expected %s but got %s", expectedId, requestorId)
  }
}
