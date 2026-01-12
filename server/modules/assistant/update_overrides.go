// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

func init() {
	t := &UpdateOverridesTool{}
	knownTools[t.GetName()] = t
}

type UpdateOverridesTool struct{}

func (t *UpdateOverridesTool) GetName() string {
	return "update_overrides"
}

func (t *UpdateOverridesTool) GetDescription() string {
	return `Updates overrides for a single detection by replacing its entire overrides array.

OPERATIONS SUPPORTED:
- Add new override: Include it in the array
- Modify override: Change specific fields in the array
- Enable/disable: Set isEnabled to true/false
- Delete override: Omit it from the array
- Multiple operations: Combine any of the above

CRITICAL REQUIREMENTS:
- Provide EXACTLY ONE of: soc_id OR public_id (NEVER both)
- Pass the COMPLETE updated overrides array (including unchanged overrides)`
}

func (t *UpdateOverridesTool) GetSchema() model.JSONSchema {
	return model.JSONSchema{
		Json: &model.ToolSchema{
			Type: "object",
			Properties: map[string]model.ToolSchemaProperty{
				"soc_id": {
					Type:        "string",
					Description: `Server-assigned detection ID (so_detection.id field).`,
				},
				"public_id": {
					Type:        "string",
					Description: `Grid-wide detection ID (so_detection.publicId field).`,
				},
				"overrides": {
					Type: "array",
					Items: map[string]model.ToolSchemaProperty{
						"override": {
							Description: "Individual override object. Include only fields relevant to the override type.",
							Type:        "object",
							Items: map[string]model.ToolSchemaProperty{
								"isEnabled": {
									Type: "boolean",
								},
								"createdAt": {
									Type: "string",
								},
								"updatedAt": {
									Type: "string",
								},
								"type": {
									Type: "string",
								},
								"note": {
									Type: "string",
								},
								"regex": {
									Type: "string",
								},
								"value": {
									Type: "string",
								},
								"track": {
									Type: "string",
								},
								"ip": {
									Type: "string",
								},
								"thresholdType": {
									Type: "string",
								},
								"count": {
									Type: "integer",
								},
								"seconds": {
									Type: "integer",
								},
								"customFilter": {
									Type: "string",
								},
							},
						},
					},
					Description: `COMPLETE overrides array for the detection (from so_detection.overrides). Must include ALL overrides, even unchanged ones.`,
				},
			},
		},
	}
}

type updateOverridesArgs struct {
	SocId     string           `json:"soc_id" example:"gQKCepgBAWAm-kn2lYs2"`
	PublicId  string           `json:"public_id" example:"dcbe6004-f6e0-4579-9f98-9576201ffb29"`
	Overrides []map[string]any `json:"overrides"`
}

func (t *UpdateOverridesTool) Execute(ctx context.Context, srv *server.Server, params string, auxData string) (result *model.ToolResponse, err error) {
	logger := log.FromContext(ctx)

	logger.WithField("toolParameters", params).Info("running tool for assistant")

	err = srv.CheckAuthorized(ctx, "write", "detections")
	if err != nil {
		return nil, fmt.Errorf("user is not authorized to write detections: %w", err)
	}

	userId := ctx.Value(web.ContextKeyRequestorId).(string)

	args := &updateOverridesArgs{}
	result = &model.ToolResponse{
		ToolName:       t.GetName(),
		OnBehalfOfUser: userId,
	}

	start := time.Now()
	defer func() {
		if result != nil {
			result.TimeToExecute = time.Since(start)
		}
	}()

	err = json.Unmarshal([]byte(params), args)
	if err != nil {
		return nil, fmt.Errorf("couldn't unmarshal params: %w", err)
	}

	result.Parameters = args

	updatedOverrides := populateOverridesFromMaps(args.Overrides, true)

	var detect *model.Detection

	if args.PublicId != "" {
		detect, err = srv.Detectionstore.GetDetectionByPublicId(ctx, args.PublicId)
		if err != nil {
			return nil, fmt.Errorf("failed to get detection by Public ID %s: %w", args.PublicId, err)
		}
	} else {
		detect, err = srv.Detectionstore.GetDetection(ctx, args.SocId)
		if err != nil {
			return nil, fmt.Errorf("failed to get detection by SOC ID %s: %w", args.SocId, err)
		}
	}

	now := time.Now()

	for _, over := range updatedOverrides {
		if over.CreatedAt.IsZero() {
			over.CreatedAt = now
		}
		update := true
		for i, oldOver := range detect.Overrides {
			if over.Equal(oldOver) {
				update = false
				detect.Overrides = append(detect.Overrides[:i], detect.Overrides[i+1:]...)
				break
			}
		}
		if over.UpdatedAt.IsZero() || update {
			over.UpdatedAt = now
		}
	}

	detect.Overrides = updatedOverrides

	err = detect.Validate()
	if err != nil {
		logger.WithError(err).WithField("detectionPublicId", detect.PublicID).Error("invalid override")
		return nil, fmt.Errorf("invalid override for detection with Public ID %s: %w", detect.PublicID, err)
	}

	engInt, ok := srv.DetectionEngines.Load(detect.Engine)
	if !ok {
		logger.WithField("detectionEngine", detect.Engine).Error("unsupported engine")
		return nil, fmt.Errorf("unsupported engine %s", detect.Engine)
	}

	engine := engInt.(server.DetectionEngine)

	detect.Kind = ""
	detect.Operation = ""

	tempPublicId := detect.PublicID
	detect, err = srv.Detectionstore.UpdateDetection(ctx, detect)
	if err != nil {
		logger.WithError(err).WithField("detectionPublicId", tempPublicId).Error("failed to update overrides")
		return nil, fmt.Errorf("failed to update overrides for detection with Public ID %s: %w", tempPublicId, err)
	}

	errMap, err := engine.SyncLocalDetections(ctx, []*model.Detection{detect})
	if err != nil {
		logger.WithError(err).WithField("detectionPublicId", detect.PublicID).Error("unable to sync detection")
		return nil, fmt.Errorf("unable to sync detection with Public ID %s: %w", detect.PublicID, err)
	}

	if len(errMap) != 0 {
		logger.WithFields(log.Fields{
			"detectionPublicId": detect.PublicID,
			"errMap":            errMap,
		}).Error("unable to sync detection")
		return nil, fmt.Errorf("unable to sync detection with Public ID %s: %v", detect.PublicID, errMap)
	}

	err = engine.MergeAuxiliaryData(detect)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"detectionEngine": detect.Engine,
			"detectionId":     detect.Id,
		}).Error("unable to merge auxiliary data into detection")
	}

	result.Result = detect

	return result, nil
}
