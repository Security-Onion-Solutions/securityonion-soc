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

/**
 * Note that this interface is intended for direct interface into the auth system for reads only.
 * For synchronization reasons, user administration (writes) is fulfilled by the AdminUserstore.
 */
type Userstore interface {
  GetUsers(ctx context.Context) ([]*model.User, error)
  GetUserById(ctx context.Context, id string) (*model.User, error)
}
