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

type Detectionstore interface {
	CreateDetection(ctx context.Context, detect *model.Detection) (*model.Detection, error)
	GetDetection(ctx context.Context, detectId string) (*model.Detection, error)
	UpdateDetection(ctx context.Context, detect *model.Detection) (*model.Detection, error)
	UpdateDetectionField(ctx context.Context, id string, field string, value any) (*model.Detection, bool, error)
	DeleteDetection(ctx context.Context, detectID string) (*model.Detection, error)
	GetAllCommunitySIDs(ctx context.Context) (map[string]*model.Detection, error) // map[detection.PublicId]detection
}
