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

type Metrics interface {
	GetGridEps(ctx context.Context) int
	UpdateNodeMetrics(ctx context.Context, node *model.Node) bool
}
