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

type Rolestore interface {
  Reload()
  GetAssignments(ctx context.Context) (map[string][]string, error)
  PopulateUserRoles(ctx context.Context, user *model.User) error

  /**
   * Return only top-level roles (roles that are not a child of another role.
   */
  GetRoles(ctx context.Context) []string
}
