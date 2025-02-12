// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package rbac

import (
	"context"
)

type Authorizer interface {
	CheckContextOperationAuthorized(ctx context.Context, operation string, target string) error
	CheckUserOperationAuthorized(userId string, operation string, target string) error
}
