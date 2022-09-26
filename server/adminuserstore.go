// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
  "context"
  "github.com/security-onion-solutions/securityonion-soc/model"
)

type AdminUserstore interface {
  Add(ctx context.Context, user *model.User) error
  Delete(ctx context.Context, id string) error
  UpdateProfile(ctx context.Context, user *model.User) error
  ResetPassword(ctx context.Context, id string, password string) error
  Enable(ctx context.Context, id string) error
  Disable(ctx context.Context, id string) error
  AddRole(ctx context.Context, id string, role string) error
  DeleteRole(ctx context.Context, id string, role string) error
}
