// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
)

func init() {
	t := &UpdateDetectionContentTool{}
	knownTools[t.GetName()] = t
}

type UpdateDetectionContentTool struct{}

func (t *UpdateDetectionContentTool) GetName() string {
	return "update_detection_content"
}

func (t *UpdateDetectionContentTool) GetDescription() string {
	return `Update an existing detection per the user's request by modifying its content field. Note that only custom detections (those with so_detection.isCommunity: false) can be
	modified in this way. This detection will be accessed with either its SOC Id or Public Id. *IMPORTANT* You MUST provide ONE of soc_id or public_id, but NEVER both.
	Modifying the content field of a detection can update the values of certain attributes of a detection. These attributes and the ways in which they are specified
	in the content field can vary for the 3 different languages. Here is a run-down of which attributes can be set/updated in the content field for the 3 different languages:
	Sigma:
	- so_detection.title: this will follow "title: " in the sigma rule
	- so_detection.description: this will follow "description: "
	- so_detection.sourceCreated: this will follow "date: "
	- so_detection.severity: this will follow "level: "
	- so_detection.category: this will be under logsource.category
	- so_detection.product: this will be under logsource.product
	Suricata:
	- so_detection.title: this will follow "msg:"
	- so_detection.severity: this will follow "signature severity" under the metadata field. Note that "minor" corresponds to low and "major" corresponds to high.
	- so_detection.sourceCreated: this is under metadata and follows "created_at"
	- so_detection.sourceUpdated: this is under metadata and follows "updated_at"
	YARA:
	- so_detection.title: this will be at the top of the rule block, and will follow "rule ". Note that this must be unique, as it is also the Public Id.
	- so_detection.description: this will be under metadata and will follow "description = "
	- so_detection.sourceCreated: this will be under metadata and will follow "date = "
	*IMPORTANT*: Note that if the user asks you to modify anything else about the content field, such as references, it is totally fine to take a swing at it. The above run-down isn't a strict set of
	rules, but instead is a loose guide to follow to help you. In fact, the actual behavior of a rule, which is outlined in the content field, is not at all tied to the attributes above.
	However, it will be very common for users to ask you to modify a rule's behavior, and you should definitely help them out with that by editing the content field, even though the above
	attributes might not be explicitly modified.`
}

func (t *UpdateDetectionContentTool) GetSchema() model.JSONSchema {
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
				"content": {
					Type: "string",
					Description: `The underlying detection rule source content. (e.g., "title: CobaltStrike Named Pipe\nid: ...\n logsource:\n ...\ncondition: selection\nfalsepositives:\n...")
					For a detection, this is the so_detection.content field. This particular content argument will be the updated content field of the original detection that the user wants to update.
					For instance, if the user wants to update the severity of a suricata rule to "high", you would take the rule's current content field, and change the value of the "level" field inside this
					content field to "high". Then, you will pass the entire updated content field as this argument.`,
				},
			},
			Required: []string{"search_filter"},
		},
	}
}

type updateDetectionContentArgs struct {
	SocId    string `json:"soc_id" example:"gQKCepgBAWAm-kn2lYs2"`
	PublicId string `json:"public_id" example:"dcbe6004-f6e0-4579-9f98-9576201ffb29"`
	Content  string `json:"content" example:"title: CobaltStrike Named Pipe\nid: ...\n logsource:\n ...\ncondition: selection\nfalsepositives:\n..."`
}

func (t *UpdateDetectionContentTool) Execute(ctx context.Context, srv *server.Server, params string, auxData string) (result *model.ToolResponse, err error) {
	logger := log.FromContext(ctx)

	logger.WithField("toolParameters", params).Info("running tool for assistant")

	userId := ctx.Value(web.ContextKeyRequestorId).(string)

	args := &updateDetectionContentArgs{}
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
		return nil, err
	}

	result.Parameters = args

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

	detect.Content = args.Content

	err = detect.Validate()
	if err != nil {
		logger.WithError(err).Error("invalid detection")
		return nil, fmt.Errorf("invalid detection")
	}

	engInt, ok := srv.DetectionEngines.Load(detect.Engine)
	if !ok {
		logger.WithField("detectionEngine", detect.Engine).Error("unsupported engine")
		return nil, fmt.Errorf("unsupported engine")
	}

	engine := engInt.(server.DetectionEngine)

	_, err = engine.ValidateRule(detect.Content)
	if err != nil {
		logger.WithError(err).WithField("detectionContent", detect.Content).Error("invalid rule")
		return nil, fmt.Errorf("invalid rule: %w", err)
	}

	err = engine.ExtractDetails(detect)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"detectionEngine":   detect.Engine,
			"detectionPublicId": detect.PublicID,
		}).Error("unable to extract details from detection")
		return nil, fmt.Errorf("unable to extract details for detection: %w", err)
	}

	_, err = engine.ApplyFilters(detect)
	if err != nil {
		logger.WithError(err).Error("unable to apply filters for detection")
		return nil, fmt.Errorf("unable to apply filters for detection: %w", err)
	}

	err = (server.DetectionHandler).PrepareForSave(ctx, detect, engine)
	if err != nil {
		if err.Error() == "Object not found" {
			web.Respond(w, r, http.StatusNotFound, nil)
		} else if errors.Is(err, errPublicIdExists) {
			web.Respond(w, r, http.StatusConflict, err)
		} else if err.Error() == "rule does not contain a public Id" {
			web.Respond(w, r, http.StatusBadRequest, "missingPublicIdErr")
		} else {
			web.Respond(w, r, http.StatusBadRequest, err)
		}

		return
	}

	errMap, err := engine.SyncLocalDetections(ctx, []*model.Detection{detect})
	if err != nil {
		logger.WithError(err).Error("unable to sync detection")
		return nil, fmt.Errorf("unable to sync detection: %w", err)
	}

	if len(errMap) != 0 {
		logger.WithField("errMap", errMap).Error("unable to sync detection")
		return nil, fmt.Errorf("unable to sync detection")
	}

	result.Result = detect

	return result, nil
}
