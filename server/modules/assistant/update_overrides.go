// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
	return `Updates overrides for a single detection by replacing its entire overrides array. Can add, modify, enable/disable, or delete overrides.

CRITICAL REQUIREMENTS:
- Provide EXACTLY ONE of: soc_id OR public_id (NEVER both)
- Pass the COMPLETE updated overrides array (including unchanged overrides)
- DO NOT modify createdAt or updatedAt fields in existing overrides
- DO NOT include createdAt or updatedAt in new overrides

OPERATIONS SUPPORTED:
- Add new override: Include it in the array
- Modify override: Change specific fields in the array
- Enable/disable: Set isEnabled to true/false
- Delete override: Omit it from the array
- Multiple operations: Combine any of the above

OVERRIDE TYPES BY ENGINE:

Suricata (3 types):
1. "modify": Changes rule content
   - Fields: type, isEnabled, note, regex, value
2. "suppress": Prevents alerts for specific IPs
   - Fields: type, isEnabled, note, track (by_src|by_dst|by_either), ip (CIDR or variable)
3. "threshold": Rate-limits alerts
   - Fields: type, isEnabled, note, thresholdType (threshold|limit|both), track (by_src|by_dst), count (>0), seconds (>0)

Sigma (1 type):
1. "customFilter": Adds filter conditions
   - Fields: type, isEnabled, note, customFilter

Common fields: isEnabled (bool), type (string), note (string, optional)
YARA: No overrides supported`
}

func (t *UpdateOverridesTool) GetSchema() model.JSONSchema {
	return model.JSONSchema{
		Json: &model.ToolSchema{
			Type: "object",
			Properties: map[string]model.ToolSchemaProperty{
				"soc_id": {
					Type:        "string",
					Description: `Server-assigned detection ID (so_detection.id field). Use soc_id OR public_id, not both.`,
				},
				"public_id": {
					Type:        "string",
					Description: `Grid-wide detection ID (so_detection.publicId field). Use soc_id OR public_id, not both.`,
				},
				"overrides": {
					Type: "array",
					Items: map[string]model.ToolSchemaProperty{
						"override": {
							Description: "Individual override object. Include only fields relevant to the override type.",
							Type:        "object",
							Items: map[string]model.ToolSchemaProperty{
								"isEnabled": {
									Type:        "boolean",
									Description: "Whether override is active",
								},
								"createdAt": {
									Type:        "string",
									Description: "Creation timestamp. Keep existing value for old overrides, omit for new ones.",
								},
								"updatedAt": {
									Type:        "string",
									Description: "Last modified timestamp. Keep existing value for old overrides, omit for new ones.",
								},
								"type": {
									Type:        "string",
									Description: "Override type: Suricata: modify|suppress|threshold, Sigma: customFilter",
								},
								"note": {
									Type:        "string",
									Description: "Optional description/comment",
								},
								"regex": {
									Type:        "string",
									Description: "Suricata modify: regex pattern to match in rule",
								},
								"value": {
									Type:        "string",
									Description: "Suricata modify: replacement value",
								},
								"track": {
									Type:        "string",
									Description: "Suricata suppress/threshold: by_src|by_dst (threshold) or by_src|by_dst|by_either (suppress)",
								},
								"ip": {
									Type:        "string",
									Description: "Suricata suppress: IP/CIDR or variable to suppress",
								},
								"thresholdType": {
									Type:        "string",
									Description: "Suricata threshold: threshold|limit|both",
								},
								"count": {
									Type:        "integer",
									Description: "Suricata threshold: occurrences before alert, must be >0",
								},
								"seconds": {
									Type:        "integer",
									Description: "Suricata threshold: time window in seconds, must be >0",
								},
								"customFilter": {
									Type:        "string",
									Description: "Sigma customFilter: filter expression to apply",
								},
							},
						},
					},
					Description: `COMPLETE overrides array for the detection (from so_detection.overrides). Must include ALL overrides, even unchanged ones.

Example (modify first override's track field):
[
		{
				"type": "threshold",
				"isEnabled": true,
				"track": "by_dst",
				"thresholdType": "both",
				"count": 10,
				"seconds": 60,
				"note": "",
				"createdAt": "2025-06-11T11:32:33.528762983-04:00",
				"updatedAt": "2025-06-11T11:32:33.528762983-04:00"
		},
		{
				"type": "modify",
				"isEnabled": true,
				"regex": "rev:1;",
				"value": "rev:2;",
				"note": "Override Note",
				"createdAt": "2025-06-11T11:32:39.70697702-04:00",
				"updatedAt": "2025-06-11T11:32:39.70697702-04:00"
		}
]

To delete an override: omit it from the array
To add an override: include it without createdAt/updatedAt`,
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
