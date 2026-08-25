// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package staticrbac

import (
	"context"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

func prepareTest(tester *testing.T, email string, id string) (*StaticRbacAuthorizer, context.Context, *model.User) {
	ctx := context.Background()
	user := model.NewUser()
	user.Email = email
	user.Id = id
	ctx = context.WithValue(ctx, web.ContextKeyRequestorId, id)

	auth := NewStaticRbacAuthorizer(server.NewFakeAuthorizedServer(nil))
	userFiles := []string{"rbac_users.test"}
	roleFiles := []string{"rbac_permissions.test", "rbac_roles.test"}
	auth.Init(userFiles, roleFiles, DEFAULT_SCAN_INTERVAL_MS, "defrole")

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

func TestCheckContextOperationAuthorized_Fail(tester *testing.T) {
	ctx := context.Background()
	ctx = context.WithValue(ctx, web.ContextKeyRequestorId, "someId")

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

func TestGetRolesForAuthId(tester *testing.T) {
	auth, ctx, user := prepareTest(tester, "some@one.invalid", "a1-id")

	err, roles := auth.GetRolesForAuthId(ctx, user.Id)
	assert.NoError(tester, err)

	var expectedRoles = [...]string{"user"}
	assert.ElementsMatch(tester, expectedRoles, roles)
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

type MockAdminUserstore struct {
	AddRoleCalls int
}

func (m *MockAdminUserstore) AddUser(ctx context.Context, user *model.User) error {
	return nil
}
func (m *MockAdminUserstore) DeleteUser(ctx context.Context, id string) error {
	return nil
}
func (m *MockAdminUserstore) UpdateProfile(ctx context.Context, user *model.User) error {
	return nil
}
func (m *MockAdminUserstore) ResetPassword(ctx context.Context, id string, password string) error {
	return nil
}
func (m *MockAdminUserstore) EnableUser(ctx context.Context, id string) error {
	return nil
}
func (m *MockAdminUserstore) DisableUser(ctx context.Context, id string) error {
	return nil
}
func (m *MockAdminUserstore) AddRole(ctx context.Context, id string, role string, bypassAuthCheck bool) error {
	m.AddRoleCalls++
	return nil
}
func (m *MockAdminUserstore) DeleteRole(ctx context.Context, id string, role string) error {
	return nil
}
func (m *MockAdminUserstore) SyncUsers(ctx context.Context) error {
	return nil
}

func TestEnsureDefaultRoleForUser_CreatesDefaultRole(tester *testing.T) {
	auth, ctx, user := prepareTest(tester, "newuser@one.invalid", "new-user-id")
	mockUserstore := &MockAdminUserstore{}
	auth.server.AdminUserstore = mockUserstore

	// Ensure no existing roles
	_ = auth.EnsureDefaultRoleForUser(ctx)
	assert.Equal(tester, 1, mockUserstore.AddRoleCalls)
	auth.AddRoleToUser(user, "defrole")

	// Verify it was added to memory so next call doesn't hit store again
	mockUserstore.AddRoleCalls = 0
	_ = auth.EnsureDefaultRoleForUser(ctx)
	assert.Equal(tester, 0, mockUserstore.AddRoleCalls)

	// Verify the role is actually returned
	_, roles := auth.GetRolesForAuthId(ctx, user.Id)
	assert.Contains(tester, roles, "defrole")
}

func TestEnsureDefaultRoleForUser_SkipClient(tester *testing.T) {
	auth, ctx, user := prepareTest(tester, "", "socl_myclient")
	mockUserstore := &MockAdminUserstore{}
	auth.server.AdminUserstore = mockUserstore

	// Ensure no existing roles
	err := auth.EnsureDefaultRoleForUser(ctx)
	assert.NoError(tester, err)
	assert.Equal(tester, 0, mockUserstore.AddRoleCalls)

	// Verify the role is NOT returned
	_, roles := auth.GetRolesForAuthId(ctx, user.Id)
	assert.NotContains(tester, roles, "defrole")
}

func TestSubgridPermissionsWithRealRbacFiles(tester *testing.T) {
	auth := NewStaticRbacAuthorizer(server.NewFakeAuthorizedServer(nil))
	roleFiles := []string{"../../../rbac/permissions", "../../../rbac/roles"}
	userFiles := []string{}
	err := auth.Init(userFiles, roleFiles, DEFAULT_SCAN_INTERVAL_MS, "user")
	assert.NoError(tester, err)

	testCases := []struct {
		name             string
		role             string
		canReadSubgrid   bool
		canWriteSubgrid  bool
	}{
		{
			name:            "superuser has subgrid read and write",
			role:            "superuser",
			canReadSubgrid:  true,
			canWriteSubgrid: true,
		},
		{
			name:            "subgrid-admin has subgrid read and write",
			role:            "subgrid-admin",
			canReadSubgrid:  true,
			canWriteSubgrid: true,
		},
		{
			name:            "subgrid-monitor has subgrid read only",
			role:            "subgrid-monitor",
			canReadSubgrid:  true,
			canWriteSubgrid: false,
		},
		{
			name:            "analyst has no subgrid access",
			role:            "analyst",
			canReadSubgrid:  false,
			canWriteSubgrid: false,
		},
	}

	for _, tc := range testCases {
		tester.Run(tc.name, func(t *testing.T) {
			user := model.NewUser()
			user.Id = "user-" + tc.role
			auth.AddRoleToUser(user, tc.role)

			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, user.Id)

			readErr := auth.CheckContextOperationAuthorized(ctx, "read", "subgrid")
			if tc.canReadSubgrid {
				assert.NoError(t, readErr, "Expected read subgrid authorized for %s", tc.role)
			} else {
				assert.Error(t, readErr, "Expected read subgrid unauthorized for %s", tc.role)
			}

			writeErr := auth.CheckContextOperationAuthorized(ctx, "write", "subgrid")
			if tc.canWriteSubgrid {
				assert.NoError(t, writeErr, "Expected write subgrid authorized for %s", tc.role)
			} else {
				assert.Error(t, writeErr, "Expected write subgrid unauthorized for %s", tc.role)
			}
		})
	}
}
