// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"fmt"
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
					Description: `The license that applies to this detection. (e.g., "DRL")`,
				},
				"content": {
					Type:        "string",
					Description: `The underlying detection rule source content. (e.g., "title: CobaltStrike Named Pipe\nid: ...\n logsource:\n ...\ncondition: selection\nfalsepositives:\n...")`,
				},
			},
			Required: []string{"search_filter"},
		},
	}
}

type createDetectionArgs struct {
	Language string `json:"language" enums:"sigma,suricata,yara"`
	License  string `json:"license" example:"DRL"`
	Content  string `json:"content" example:"title: CobaltStrike Named Pipe\nid: ...\n logsource:\n ...\ncondition: selection\nfalsepositives:\n..."`
}

func (t *CreateDetectionTool) Execute(ctx context.Context, srv *server.Server, params string, auxData string) (result *model.ToolResponse, err error) {
	logger := log.FromContext(ctx)

	logger.WithField("toolParameters", params).Info("running tool for assistant")

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

	err = json.Unmarshal([]byte(params), args)
	if err != nil {
		return nil, err
	}

	result.Parameters = args

	detect := &model.Detection{}
	detect.Language = model.SigLanguage(strings.ToLower(string(args.Language)))
	detect.License = args.License
	detect.Content = args.Content

	for _, over := range detect.Overrides {
		if over.CreatedAt.IsZero() {
			over.CreatedAt = time.Now()
		}

		if over.UpdatedAt.IsZero() {
			over.UpdatedAt = time.Now()
		}
	}

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

	user, err := srv.Userstore.GetUserById(ctx, userId)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve user: %w", err)
	}
	detect.Author = detections.MakeUser(user)

	_, err = engine.ApplyFilters(detect)
	if err != nil {
		logger.WithError(err).Error("unable to apply filters for detection")
		return nil, fmt.Errorf("unable to apply filters for detection: %w", err)
	}

	detect, err = srv.Detectionstore.CreateDetection(ctx, detect)
	if err != nil {
		logger.WithError(err).Error("failed to create detection")
		return nil, fmt.Errorf("failed to create detection: %w", err)
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
