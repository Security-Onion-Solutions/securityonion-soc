// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
)

func init() {
	t := &CreateDetectionTool{}
	knownTools[t.GetName()] = t
}

type CreateDetectionTool struct{}

func (t *CreateDetectionTool) GetName() string {
	return "create_detection"
}

func (t *CreateDetectionTool) GetDescription() string {
	return `Create a new detection for the given alert(s) (or other event(s)/topic(s)) at hand.`
}

func (t *CreateDetectionTool) GetSchema() model.JSONSchema {
	return model.JSONSchema{
		Json: &model.ToolSchema{
			Type: "object",
			Properties: map[string]model.ToolSchemaProperty{
				"language": {
					Type:        "string",
					Description: `The language that this detection uses. This must be "sigma", "suricata", or "yara".`,
				},
				"license": {
					Type:        "string",
					Description: `The license that applies to this detection. (e.g., "DRL") *IMPORTANT*: The license should be left blank unless explicitly instructed by the user what the license should be.`,
				},
				"content": {
					Type:        "string",
					Description: `The underlying detection rule source content. (e.g., "title: CobaltStrike Named Pipe\nid: ...\n logsource:\n ...\ncondition: selection\nfalsepositives:\n...")`,
				},
			},
		},
	}
}

type createDetectionArgs struct {
	Language string `json:"language" enums:"sigma,suricata,yara"`
	License  string `json:"license" example:"DRL"`
	Content  string `json:"content" example:"title: CobaltStrike Named Pipe\nid: ...\n logsource:\n ...\ncondition: selection\nfalsepositives:\n..."`
}

func (t *CreateDetectionTool) Execute(ctx context.Context, srv *server.Server, req *model.ToolRequest) (result *model.ToolResponse, err error) {
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

	args := &createDetectionArgs{}
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

	detect := &model.Detection{}
	detect.Language = model.SigLanguage(strings.ToLower(string(args.Language)))
	detect.License = args.License
	detect.Content = args.Content

	detect.Ruleset = detections.RULESET_CUSTOM

	switch detect.Language {
	case "sigma":
		detect.Engine = model.EngineNameElastAlert
	case "yara":
		detect.Engine = model.EngineNameStrelka
	case "suricata":
		detect.Engine = model.EngineNameSuricata
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

	user, err := srv.TryGetUser(ctx)
	if err != nil {
		logger.WithError(err).Error("unable to retrieve user from context")
		return nil, err
	}

	if user != nil {
		// Don't trust the client to send the correct author, grab it from the context, unless the user is nil (API client)
		detect.Author = detections.MakeUser(user)
	}

	_, err = engine.ApplyFilters(detect)
	if err != nil {
		logger.WithError(err).WithField("detectionPublicId", detect.PublicID).Error("unable to apply filters for detection")
		return nil, err
	}

	tempPublicId := detect.PublicID
	detect, err = srv.Detectionstore.CreateDetection(ctx, detect)
	if err != nil {
		logger.WithError(err).WithField("detectionPublicId", tempPublicId).Error("failed to create detection")
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

	result.Result = detect

	return result, nil
}
