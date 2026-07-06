// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"errors"
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
	return `Updates a custom detection's content field (only detections with so_detection.isCommunity: false). Provide ONE of soc_id or public_id to identify the detection.

Content field attribute mappings by language:
Sigma: title (title:), description (description:), sourceCreated (date:), severity (level:), category (logsource.category), product (logsource.product)
Suricata: title (msg:), severity (metadata signature_severity, minor=low/major=high), sourceCreated (metadata created_at), sourceUpdated (metadata updated_at)
YARA: title (rule name, must be unique), description (metadata description =), sourceCreated (metadata date =)

You can modify any aspect of the content field including rule behavior, references, and logic - the above mappings are guidelines, not restrictions. Returns the updated detection.`
}

func (t *UpdateDetectionContentTool) GetSchema() model.JSONSchema {
	return model.JSONSchema{
		Json: &model.ToolSchema{
			Type: "object",
			Properties: map[string]model.ToolSchemaProperty{
				"soc_id": {
					Type:        "string",
					Description: `Server-assigned detection ID (so_detection.id field). Also called "SOC ID" or "_id".`,
				},
				"public_id": {
					Type:        "string",
					Description: `Grid-wide detection identifier (so_detection.publicId field).`,
				},
				"content": {
					Type:        "string",
					Description: `Complete updated detection rule source (so_detection.content field). Modify the original content with requested changes and provide the entire updated content string.`,
				},
			},
		},
	}
}

type updateDetectionContentArgs struct {
	SocId    string `json:"soc_id" example:"gQKCepgBAWAm-kn2lYs2"`
	PublicId string `json:"public_id" example:"dcbe6004-f6e0-4579-9f98-9576201ffb29"`
	Content  string `json:"content" example:"title: CobaltStrike Named Pipe\nid: ...\n logsource:\n ...\ncondition: selection\nfalsepositives:\n..."`
}

func (t *UpdateDetectionContentTool) Execute(ctx context.Context, srv *server.Server, req *model.ToolRequest) (result *model.ToolResponse, err error) {
	logger := log.FromContext(ctx).WithFields(log.Fields{
		"sessionId": req.SessionId,
		"toolUseId": req.ToolUseId,
	})

	logger.WithField("toolParameters", req.Params).Info("running tool for assistant")

	err = srv.CheckAuthorized(ctx, "write", "detections")
	if err != nil {
		logger.WithError(err).Error("user is not authorized to write detections")
		return nil, errors.New("ERROR_PERMISSION_DENIED")
	}

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

	err = json.Unmarshal([]byte(req.Params), args)
	if err != nil {
		logger.WithError(err).WithField("toolParams", req.Params).Error("failed to unmarshal tool params")
		return nil, errors.New("ERROR_ASSISTANT_UNMARSHAL_PARAMS")
	}

	result.Parameters = args

	var detect *model.Detection

	if args.PublicId != "" {
		detect, err = srv.Detectionstore.GetDetectionByPublicId(ctx, args.PublicId)
		if err != nil {
			logger.WithError(err).WithField("detectionPublicId", args.PublicId).Error("unable to retrieve detection by public Id")
			return nil, err
		}
	} else {
		detect, err = srv.Detectionstore.GetDetection(ctx, args.SocId)
		if err != nil {
			logger.WithError(err).WithField("socId", args.SocId).Error("unable to retrieve detection by Id")
			return nil, err
		}
	}

	if detect.IsCommunity {
		logger.WithField("publicId", detect.PublicID).Error("cannot update a community rule")
		return nil, errors.New("ERROR_DETECTION_CANNOT_UPDATE_COMMUNITY")
	}

	detect.Content = args.Content

	err = detect.Validate()
	if err != nil {
		logger.WithError(err).WithField("detectionPublicId", detect.PublicID).Error("invalid detection")
		return nil, err
	}

	engInt, ok := srv.DetectionEngines.Load(detect.Engine)
	if !ok {
		logger.WithField("detectionEngine", detect.Engine).Error("unsupported engine")
		return nil, errors.New("ERROR_UNSUPPORTED_ENGINE")
	}

	engine := engInt.(server.DetectionEngine)

	_, err = engine.ValidateRule(detect.Content)
	if err != nil {
		logger.WithError(err).WithField("detectionContent", detect.Content).Error("invalid rule")
		return nil, err
	}

	err = engine.ExtractDetails(detect)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"detectionEngine":   detect.Engine,
			"detectionPublicId": detect.PublicID,
		}).Error("unable to extract details from detection")
		return nil, err
	}

	_, err = engine.ApplyFilters(detect)
	if err != nil {
		logger.WithError(err).WithField("detectionPublicId", detect.PublicID).Error("unable to apply filters for detection")
		return nil, err
	}

	detect.Kind = ""
	detect.Operation = ""

	tempPublicId := detect.PublicID
	detect, err = srv.Detectionstore.UpdateDetection(ctx, detect)
	if err != nil {
		logger.WithError(err).WithField("detectionPublicId", tempPublicId).Error("failed to update detection")
		return nil, err
	}

	errMap, err := engine.SyncLocalDetections(ctx, []*model.Detection{detect})
	if err != nil {
		logger.WithError(err).WithField("detectionPublicId", detect.PublicID).Error("unable to sync detection")
		return nil, errors.New("ERROR_DETECTION_SYNC_FAILED")
	}

	if len(errMap) != 0 {
		logger.WithFields(log.Fields{
			"detectionPublicId": detect.PublicID,
			"errMap":            errMap,
		}).Error("unable to sync detection")
		
		return nil, errors.New("ERROR_DETECTION_SYNC_FAILED")
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
