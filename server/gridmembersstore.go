// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

type GridMembersstore interface {
	GetMembers(ctx context.Context) ([]*model.GridMember, error)
	ManageMember(ctx context.Context, operation string, id string) error
	SendFile(ctx context.Context, node string, from string, to string, cleanup bool) error
	Import(ctx context.Context, node string, file string, importer string) (*string, error)
}
