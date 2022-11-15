// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
  "context"
  "errors"
  "github.com/security-onion-solutions/securityonion-soc/config"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/rbac"
)

type FakeUserstore struct {
  users []*model.User
}

func (impl *FakeUserstore) GetUsers(ctx context.Context) ([]*model.User, error) {
  return impl.users, nil
}

func (impl *FakeUserstore) GetUserById(ctx context.Context, id string) (*model.User, error) {
  for _, user := range impl.users {
    if user.Id == id {
      return user, nil
    }
  }
  return nil, errors.New("not found")
}

type FakeRolestore struct {
  roleMap map[string][]string
}

func (impl *FakeRolestore) Reload() {
}

func (impl *FakeRolestore) GetAssignments(ctx context.Context) (map[string][]string, error) {
  return impl.roleMap, nil
}

func (impl *FakeRolestore) PopulateUserRoles(ctx context.Context, user *model.User) error {
  user.Roles = impl.roleMap[user.Email]
  return nil
}

func (impl *FakeRolestore) GetRoles(ctx context.Context) []string {
  roles := make([]string, 0, 0)
  for role := range impl.roleMap {
    roles = append(roles, role)
  }
  return roles
}

func NewFakeServer(authorized bool, roleMap map[string][]string) *Server {
  cfg := &config.ServerConfig{}
  srv := NewServer(cfg, "")
  srv.Authorizer = &rbac.FakeAuthorizer{
    Authorized: authorized,
  }
  srv.Rolestore = &FakeRolestore{
    roleMap: roleMap,
  }

  users := make([]*model.User, 0, 0)
  users = append(users, &model.User{
    Id:    "user-id-1",
    Email: "user1@somewhere.invalid",
  })
  users = append(users, &model.User{
    Id:    "user-id-2",
    Email: "user2@somewhere.invalid",
  })
  srv.Userstore = &FakeUserstore{
    users: users,
  }
  return srv
}

func NewFakeAuthorizedServer(roleMap map[string][]string) *Server {
  return NewFakeServer(true, roleMap)
}

func NewFakeUnauthorizedServer() *Server {
  return NewFakeServer(false, make(map[string][]string))
}
