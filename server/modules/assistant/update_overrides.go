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
	return `Update an existing detection's overrides per the user's request by modifying its overrides field. This detection will be accessed with either its SOC Id or Public Id.
	*IMPORTANT* You MUST provide ONE of soc_id or public_id, but NEVER both. The types of overrides and the fields for each override can vary between the Suricata and Sigma languages.
	YARA does not have overrides. The 5 fields that all overrides do share in common, no matter the language, are "isEnabled", "createdAt", "updatedAt", "type", and "note".
	The "note" field is the only one that can be empty. Here is a run-down of the language-specific override types and their respective fields and potential values:
	Suricata:
	- 3 different values for "type": "modify", "suppress", and "threshold"
	  - "modify" overrides also have the fields "regex" and "value".
	  - "suppress" overrides also have the fields "track" and "ip". The "track" field can ONLY take ONE of the following 3 values: "by_dst", "by_src", or "by_either". The "ip" field can be in CIDR notation or a Suricata variable.
	  - "threshold" overrides also have the fields "thresholdType", "track", "count", and "seconds". The "track" field can only take one of 2 values: "by_dst" or "by_src". The "thresholdType" field can only take one of 3 values: "threshold", "limit", or "both".
	Sigma:
	- Only 1 value for "type": "customFilter"
	  - "customFilter" overrides also have a field called "customFilter", where you put the actual filter.
	Here are a couple important things to note. This tool only operates on a single detection, not multiple at once. This tool can be used to accomplish tasks such as adding a new override to a detection,
	enabling/disabling an existing override, modifying a particular field inside of an override, and deleting an override, among other tasks. Note that you can also perform multiple of these tasks at once
	if the user's request warrants it.
	*IMPORTANT* When updating an override, DO NOT modify the createdAt or updatedAt fields. Additionally, when creating a new override, DO NOT include createdAt or updatedAt fields for the new override.`
}

func (t *UpdateOverridesTool) GetSchema() model.JSONSchema {
	return model.JSONSchema{
		Json: &model.ToolSchema{
			Type: "object",
			Properties: map[string]model.ToolSchemaProperty{
				"soc_id": {
					Type:        "string",
					Description: `The ID assigned to this detection by the server. This is often referred to as the "SOC ID" or "_id". In a detection, this is the "so_detection.id" field.`,
				},
				"public_id": {
					Type:        "string",
					Description: `The public ID shared across all Security Onion grids. In a detection, this is the "so_detection.publicId" field.`,
				},
				"overrides": {
					Type: "array",
					Items: map[string]model.ToolSchemaProperty{
						"override": {
							Description: "Each of these objects represents an individual override.",
							Type:        "object",
							Items: map[string]model.ToolSchemaProperty{
								"isEnabled": {
									Type:        "boolean",
									Description: "Indicates whether this override is enabled.",
								},
								"createdAt": {
									Type:        "string",
									Description: "The date and time when this override was created. This field should not be included for newly created overrides, and it also should not be modified.",
								},
								"updatedAt": {
									Type:        "string",
									Description: "The date and time when this override was last modified. This field should not be included for newly created overrides, and it also should not be modified.",
								},
								"type": {
									Type:        "string",
									Description: "The type of override; available values vary between detection engines.",
								},
								"note": {
									Type:        "string",
									Description: "An optional operational note for this override.",
								},
								"regex": {
									Type:        "string",
									Description: "(suricata only) Regular expression for matching modify overrides.",
								},
								"value": {
									Type:        "string",
									Description: "(suricata only) The value needing to match the regex in order for this override to apply.",
								},
								"track": {
									Type:        "string",
									Description: "(suricata only) Track type for suppress and threshold overrides (by_either only applies to suppress overrides).",
								},
								"ip": {
									Type:        "string",
									Description: "(suricata only) The IP address or network value.",
								},
								"thresholdType": {
									Type:        "string",
									Description: "(suricata only) Threshold type, for threshold overrides.",
								},
								"count": {
									Type:        "integer",
									Description: "(suricata only) For treshold overrides, this is the number of occurrences allowed, within the given seconds interval, before this detection triggers an alert. Must be non-negative and greater than 0.",
								},
								"seconds": {
									Type:        "integer",
									Description: "(suricata only) For treshold overrides, this is the number of seconds that the occurrence threshold must occur within. Must be non-negative and greater than 0.",
								},
								"customFilter": {
									Type:        "string",
									Description: "(elastalert only) The custom filter applied to Sigma detections before the detection will trigger an alert.",
								},
							},
						},
					},
					Description: `The entire updated overrides block for the detection, as an array of objects. Here's an example overrides block:
[
	{
		"note": "",
		"createdAt": "2025-06-11T11:32:33.528762983-04:00",
		"seconds": 60,
		"isEnabled": true,
		"count": 10,
		"type": "threshold",
		"track": "by_src",
		"thresholdType": "both",
		"updatedAt": "2025-06-11T11:32:33.528762983-04:00"
	},
	{
		"note": "Override Note",
		"createdAt": "2025-06-11T11:32:39.70697702-04:00",
		"regex": "rev:1;",
		"isEnabled": true,
		"type": "modify",
		"value": "rev:2;",
		"updatedAt": "2025-06-11T11:32:39.70697702-04:00"
	}
]
					The overrides block is located at the so_detection.overrides field of a detection. This particular overrides argument will be the updated overrides field of the original detection that the user wants to update.
					For instance, if the user wants to update the first override above to track by destination instead of by source, you would take the current overrides block, find the first override, and change the value of the "track"
					field in that override to "by_dst". Then, you will pass the entire updated overrides block, including the overrides that weren't actually updated, as this argument, as an array of objects.`,
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
