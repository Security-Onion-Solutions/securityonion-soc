// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
)

type Rolestore interface {
	Reload()
	GetAssignments(ctx context.Context) (map[string][]string, error)
	GetRolesForAuthId(ctx context.Context, id string) (error, []string)

	/**
	 * Return only top-level roles (roles that are not a child of another role.
	 */
	GetRoles(ctx context.Context) []string

	GetPermissions(ctx context.Context) map[string][]string

	EnsureDefaultRoleForUser(ctx context.Context) error
}
