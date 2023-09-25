package server

import (
	"context"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

type DetectionEngine interface {
	ValidateRule(rule string) (string, error)
	SyncDetections(ctx context.Context, detections []*model.Detection) (errMap map[string]string, err error)
}
