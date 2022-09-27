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

type Configstore interface {
  GetSettings(ctx context.Context) ([]*model.Setting, error)
  UpdateSetting(ctx context.Context, setting *model.Setting, remove bool) error
  SyncSettings(ctx context.Context) error
}
