// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package rbac

import (
  "context"
  "github.com/security-onion-solutions/securityonion-soc/model"
)

type Authorizer interface {
  CheckContextOperationAuthorized(ctx context.Context, operation string, target string) error
  CheckUserOperationAuthorized(user *model.User, operation string, target string) error
}
