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
  "errors"
  "github.com/security-onion-solutions/securityonion-soc/fake"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "testing"
)

func TestUserstoreInit(tester *testing.T) {
  ai := NewKratosUserstore(nil)
  err := ai.Init("abc")
  if err != nil {
    tester.Errorf("unexpected Init error")
  }
}

func TestUnauthorized(tester *testing.T) {
  userStore := NewKratosUserstore(fake.NewUnauthorizedServer())

  _, err := userStore.GetUsers(context.Background())
  ensureUnauthorized(tester, err)

  _, err = userStore.GetUser(context.Background(), "some-id")
  ensureUnauthorized(tester, err)
}

func ensureUnauthorized(tester *testing.T, err error) {
  var authErr *model.Unauthorized
  if err == nil || !errors.As(err, &authErr) {
    tester.Errorf("Expected unauthorized error but got %v", err)
  }
}
