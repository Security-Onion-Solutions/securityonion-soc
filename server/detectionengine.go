// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

type DetectionEngine interface {
	ValidateRule(rule string) (string, error)
	SyncLocalDetections(ctx context.Context, detections []*model.Detection) (errMap map[string]string, err error)
	ConvertRule(ctx context.Context, detect *model.Detection) (string, error)
	ExtractDetails(detect *model.Detection) error
}
