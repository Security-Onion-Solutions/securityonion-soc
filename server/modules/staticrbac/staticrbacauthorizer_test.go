// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package staticrbac

import (
  "context"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/web"
  "github.com/stretchr/testify/assert"
  "testing"
)

func prepareTest(tester *testing.T, email string) (*StaticRbacAuthorizer, context.Context, *model.User) {
  ctx := context.Background()
  user := model.NewUser()
  user.Email = email
  ctx = context.WithValue(ctx, web.ContextKeyRequestor, user)

  auth := NewStaticRbacAuthorizer()
  roleFiles := []string{"rbac_permissions.test", "rbac_roles.test"}
  auth.Init(roleFiles, DEFAULT_SCAN_INTERVAL_MS)

  assert.Equal(tester, DEFAULT_SCAN_INTERVAL_MS, auth.scanIntervalMs)
  assert.Equal(tester, roleFiles, auth.roleFiles)

  auth.scanFiles()

  return auth, ctx, user
}

func TestCheckContextOperationAuthorized_EmptyContext(tester *testing.T) {
  ctx := context.Background()
  auth := NewStaticRbacAuthorizer()
  err := auth.CheckContextOperationAuthorized(ctx, "myop", "mytarget")
  assert.Error(tester, err, "Expected error due to missing context data")
}

func TestCheckContextOperationAuthorized_Collision(tester *testing.T) {
  ctx := context.Background()
  user := model.NewUser()
  user.Email = "mytarget/myop"
  ctx = context.WithValue(ctx, web.ContextKeyRequestor, user)

  auth := NewStaticRbacAuthorizer()
  err := auth.CheckContextOperationAuthorized(ctx, "myop", "mytarget")
  assert.Error(tester, err)
}

func TestCheckContextOperationAuthorized_Fail(tester *testing.T) {
  ctx := context.Background()
  ctx = context.WithValue(ctx, web.ContextKeyRequestor, model.NewUser())

  auth := NewStaticRbacAuthorizer()
  err := auth.CheckContextOperationAuthorized(ctx, "myop", "mytarget")
  var unauthErr *model.Unauthorized
  assert.ErrorAs(tester, err, &unauthErr)
}

func TestCheckContextOperationAuthorized_FailRemoved(tester *testing.T) {
  auth, ctx, _ := prepareTest(tester, "some@one.invalid")

  err := auth.CheckContextOperationAuthorized(ctx, "bar", "foo")
  assert.NoError(tester, err)

  err = auth.CheckContextOperationAuthorized(ctx, "action", "another")
  var unauthErr *model.Unauthorized
  assert.ErrorAs(tester, err, &unauthErr)
}

func TestCheckContextOperationAuthorized_Success(tester *testing.T) {
  auth, ctx, _ := prepareTest(tester, "some@where.invalid")

  err := auth.CheckContextOperationAuthorized(ctx, "action", "another")
  assert.NoError(tester, err)

  err = auth.CheckContextOperationAuthorized(ctx, "action", "some")
  var unauthErr *model.Unauthorized
  assert.ErrorAs(tester, err, &unauthErr)
}

func TestIsAuthorized(tester *testing.T) {
  auth := NewStaticRbacAuthorizer()

  roleMap := make(map[string][]string)
  roleMap["clerk"] = []string{"register/operates", "tables/maintains"}
  roleMap["baker"] = []string{"cakes/bake", "icing/decorates"}
  roleMap["chef"] = []string{"recipes/create", "menus/create"}
  roleMap["henry"] = []string{"baker"}
  roleMap["tom"] = []string{"chef"}
  roleMap["alice"] = []string{}

  auth.UpdateRoleMap(roleMap)

  var testTable = []struct {
    subject    string
    permission string
    authorized bool
  }{
    {"henry", "cakes/bake", true},
    {"henry", "pies/bake", false},
    {"henry", "register/operates", false},
    {"alice", "pies/bake", false},
    {"alice", "cakes/bake", false},
    {"alice", "register/operates", false},
    {"tom", "cakes/bake", false},
    {"tom", "recipes/create", true},
    {"tom", "register/operates", false},
  }

  for _, test := range testTable {
    tester.Run("subject="+test.subject+", permission="+test.permission, func(t *testing.T) {
      actual := auth.isAuthorized(test.subject, test.permission)
      assert.Equal(tester, test.authorized, actual)
    })
  }
}

func TestGetAssignments_Self(tester *testing.T) {
  auth, ctx, user := prepareTest(tester, "some@one.invalid")

  roleMap, err := auth.GetAssignments(ctx)
  assert.NoError(tester, err)
  assert.Contains(tester, roleMap, user.Email)

  var expectedRoles = [...]string{"user"}
  assert.ElementsMatch(tester, expectedRoles, roleMap[user.Email])
}

func TestPopulateUserRoles(tester *testing.T) {
  auth, ctx, user := prepareTest(tester, "some@one.invalid")

  err := auth.PopulateUserRoles(ctx, user)
  assert.NoError(tester, err)

  var expectedRoles = [...]string{"user"}
  assert.ElementsMatch(tester, expectedRoles, user.Roles)
}
