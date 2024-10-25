// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

type AdminClientstore interface {
	AddClient(ctx context.Context, client *model.Client) (string, error)
	DeleteClient(ctx context.Context, id string) error
	GenerateSecret(ct context.Context, id string) (string, error)
	UpdateClient(ctx context.Context, client *model.Client) error
	AddRole(ctx context.Context, id string, role string) error
	DeleteRole(ctx context.Context, id string, role string) error
	SyncClients(ctx context.Context) error
}
