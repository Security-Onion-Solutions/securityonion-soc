// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package staticrbac

import (
  "context"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/server"
  "github.com/security-onion-solutions/securityonion-soc/web"
  "github.com/stretchr/testify/assert"
  "testing"
)

func prepareTest(tester *testing.T, email string, id string) (*StaticRbacAuthorizer, context.Context, *model.User) {
  ctx := context.Background()
  user := model.NewUser()
  user.Email = email
  user.Id = id
  ctx = context.WithValue(ctx, web.ContextKeyRequestor, user)

  auth := NewStaticRbacAuthorizer(server.NewFakeAuthorizedServer(nil))
  userFiles := []string{"rbac_users.test"}
  roleFiles := []string{"rbac_permissions.test", "rbac_roles.test"}
  auth.Init(userFiles, roleFiles, DEFAULT_SCAN_INTERVAL_MS)

  assert.Equal(tester, DEFAULT_SCAN_INTERVAL_MS, auth.scanIntervalMs)
  assert.Equal(tester, roleFiles, auth.roleFiles)
  assert.Equal(tester, userFiles, auth.userFiles)

  auth.scanNow()

  return auth, ctx, user
}

func TestCheckContextOperationAuthorized_EmptyContext(tester *testing.T) {
  ctx := context.Background()
  auth := NewStaticRbacAuthorizer(server.NewFakeAuthorizedServer(nil))
  err := auth.CheckContextOperationAuthorized(ctx, "myop", "mytarget")
  assert.Error(tester, err, "Expected error due to missing context data")
}

func TestCheckContextOperationAuthorized_Collision(tester *testing.T) {
  ctx := context.Background()
  user := model.NewUser()
  user.Email = "mytarget/myop"
  user.Id = "a1-id"
  ctx = context.WithValue(ctx, web.ContextKeyRequestor, user)

  auth := NewStaticRbacAuthorizer(server.NewFakeAuthorizedServer(nil))
  err := auth.CheckContextOperationAuthorized(ctx, "myop", "mytarget")
  assert.Error(tester, err)
}

func TestCheckContextOperationAuthorized_Fail(tester *testing.T) {
  ctx := context.Background()
  ctx = context.WithValue(ctx, web.ContextKeyRequestor, model.NewUser())

  auth := NewStaticRbacAuthorizer(server.NewFakeAuthorizedServer(nil))
  err := auth.CheckContextOperationAuthorized(ctx, "myop", "mytarget")
  var unauthErr *model.Unauthorized
  assert.ErrorAs(tester, err, &unauthErr)
}

func TestCheckContextOperationAuthorized_FailRemoved(tester *testing.T) {
  auth, ctx, _ := prepareTest(tester, "some@one.invalid", "a1-id")

  err := auth.CheckContextOperationAuthorized(ctx, "bar", "foo")
  assert.NoError(tester, err)

  err = auth.CheckContextOperationAuthorized(ctx, "action", "another")
  var unauthErr *model.Unauthorized
  assert.ErrorAs(tester, err, &unauthErr)
}

func TestCheckContextOperationAuthorized_Success(tester *testing.T) {
  auth, ctx, _ := prepareTest(tester, "some@where.invalid", "a0-id")

  err := auth.CheckContextOperationAuthorized(ctx, "action", "another")
  assert.NoError(tester, err)

  err = auth.CheckContextOperationAuthorized(ctx, "action", "some")
  var unauthErr *model.Unauthorized
  assert.ErrorAs(tester, err, &unauthErr)
}

func TestIsAuthorized(tester *testing.T) {
  auth := NewStaticRbacAuthorizer(server.NewFakeAuthorizedServer(nil))

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
  auth, ctx, user := prepareTest(tester, "some@one.invalid", "a1-id")

  roleMap, err := auth.GetAssignments(ctx)
  assert.NoError(tester, err)
  assert.Contains(tester, roleMap, auth.identifyUser(user))

  var expectedRoles = [...]string{"user"}
  assert.ElementsMatch(tester, expectedRoles, roleMap[auth.identifyUser(user)])
}

func TestPopulateUserRoles(tester *testing.T) {
  auth, ctx, user := prepareTest(tester, "some@one.invalid", "a1-id")

  err := auth.PopulateUserRoles(ctx, user)
  assert.NoError(tester, err)

  var expectedRoles = [...]string{"user"}
  assert.ElementsMatch(tester, expectedRoles, user.Roles)
}

func TestAddRemoveRole(tester *testing.T) {
  auth, ctx, user := prepareTest(tester, "some@one.invalid", "a1-id")

  // Fresh, shouldn't have fruity
  roles, err := auth.GetAssignments(ctx)
  assert.NoError(tester, err)
  assert.Len(tester, roles[auth.identifyUser(user)], 1)
  assert.NotContains(tester, roles[auth.identifyUser(user)], "fruity")

  auth.AddRoleToUser(user, "fruity")

  // Now should have fruity
  roles, err = auth.GetAssignments(ctx)
  assert.NoError(tester, err)
  assert.Len(tester, roles[auth.identifyUser(user)], 2)
  assert.Contains(tester, roles[auth.identifyUser(user)], "fruity")

  auth.AddRoleToUser(user, "fruity")

  // Make sure it's not duplicated
  roles, err = auth.GetAssignments(ctx)
  assert.NoError(tester, err)
  assert.Len(tester, roles[auth.identifyUser(user)], 2)
  assert.Contains(tester, roles[auth.identifyUser(user)], "fruity")

  auth.RemoveRoleFromUser(user, "fruity")

  // Should no longer have fruity
  roles, err = auth.GetAssignments(ctx)
  assert.NoError(tester, err)
  assert.Len(tester, roles[auth.identifyUser(user)], 1)
  assert.NotContains(tester, roles[auth.identifyUser(user)], "fruity")

  auth.RemoveRoleFromUser(user, "fruity")

  // Should not remove an item that doesn't exist
  roles, err = auth.GetAssignments(ctx)
  assert.NoError(tester, err)
  assert.Len(tester, roles[auth.identifyUser(user)], 1)
  assert.NotContains(tester, roles[auth.identifyUser(user)], "fruity")
}

func TestGetRoles(tester *testing.T) {
  auth, ctx, _ := prepareTest(tester, "some@one.invalid", "a1-id")

  roles := auth.GetRoles(ctx)

  var expectedRoles = [...]string{"anotherrole", "fifthrole", "somerole", "superuser", "user"}
  assert.ElementsMatch(tester, expectedRoles, roles)
}
