package server

import (
	"context"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

type DetectionEngine interface {
	ValidateRule(rule string) (string, error)
	ParseRules(content string) ([]*model.Detection, error)
	SyncLocalDetections(ctx context.Context, detections []*model.Detection) (errMap map[string]string, err error)
	SyncCommunityDetections(ctx context.Context, detections []*model.Detection) (errMap map[string]string, err error)
}
