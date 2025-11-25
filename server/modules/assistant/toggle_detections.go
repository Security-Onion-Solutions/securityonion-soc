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

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

func init() {
	t := &ToggleDetectionsTool{}
	knownTools[t.GetName()] = t
}

type ToggleDetectionsTool struct{}

func (t *ToggleDetectionsTool) GetName() string {
	return "toggle_detections"
}

func (t *ToggleDetectionsTool) GetDescription() string {
	return "Enable or disable Security Onion detections by searching with an OQL filter. " +
		"Use a 999-day date range unless specified otherwise."
}

func (t *ToggleDetectionsTool) GetSchema() model.JSONSchema {
	return model.JSONSchema{
		Json: &model.ToolSchema{
			Type: "object",
			Properties: map[string]model.ToolSchemaProperty{
				"search_filter": {
					Type:        "string",
					Description: "OQL query to find detections. Search any relevant fields available in the detection schema.",
				},
				"enable": {
					Type:        "boolean",
					Description: "true to enable detections, false to disable them.",
				},
				"range_start": {
					Type: "string",
				},
				"range_end": {
					Type: "string",
				},
				"range_format": {
					Type: "string",
				},
				"limit": {
					Type:        "integer",
					Description: "Maximum detections to return. Only use when user specifies a limit (e.g., \"enable the 5 most recent suricata detections\").",
				},
			},
			Required: []string{"search_filter"},
		},
	}
}

type toggleDetectionsArgs struct {
	SearchFilter string `json:"search_filter"`
	Enable       bool   `json:"enable"`
	RangeStart   string `json:"range_start,omitempty"`
	RangeEnd     string `json:"range_end,omitempty"`
	RangeFormat  string `json:"range_format,omitempty"`
	Limit        int    `json:"limit"`
}

func (t *ToggleDetectionsTool) Execute(ctx context.Context, srv *server.Server, params string, auxData string) (result *model.ToolResponse, err error) {
	logger := log.FromContext(ctx)

	logger.WithField("toolParameters", params).Info("running tool for assistant")

	err = srv.CheckAuthorized(ctx, "write", "detections")
	if err != nil {
		return nil, fmt.Errorf("user is not authorized to write detections: %w", err)
	}

	userId := ctx.Value(web.ContextKeyRequestorId).(string)

	args := &toggleDetectionsArgs{}
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

	query := args.SearchFilter

	if query != "" && !strings.Contains(query, "NOT metadata.raw_index:") {
		query = fmt.Sprintf(`(%s) AND NOT metadata.raw_index:"logs-soc-so"`, query)
	} else if query == "" {
		query = `NOT metadata.raw_index:"logs-soc-so"`
	}

	var detectLimit int
	if args.Limit > 0 {
		detectLimit = args.Limit
	} else {
		detectLimit = 10000
	}

	detectEvents, err := srv.Detectionstore.QueryWithRange(ctx, query, args.RangeStart, args.RangeEnd, args.RangeFormat, detectLimit)
	if err != nil {
		return nil, fmt.Errorf("unable to search for detections with query %s: %w", query, err)
	}

	detects, err := srv.Detectionstore.ConvertEventsToDetections(ctx, detectEvents)
	if err != nil {
		return nil, fmt.Errorf("unable to convert events to detections: %w", err)
	}

	if len(detects) == 0 {
		result.Result = "No detections found"
		return result, nil
	}

	logger.WithField("detectionsFound", len(detects)).Info("query executed successfully")

	bulkStats, err := srv.Detectionstore.BulkUpdateDetections(ctx, args.Enable, detects, logger)
	if err != nil {
		logger.WithError(err).Error("error updating detections")
		return nil, fmt.Errorf("error updating detections: %w", err)
	}

	syncDetects := bulkStats.NeedToSync
	syncStart := time.Now()
	errMap := map[string]string{}
	errList := []error{}

	byEngine := map[model.EngineName][]*model.Detection{}
	for _, detectCurr := range syncDetects {
		byEngine[detectCurr.Engine] = append(byEngine[detectCurr.Engine], detectCurr)
	}

	srv.DetectionEngines.Range(func(n, engineInt interface{}) bool {
		name := n.(model.EngineName)
		engine := engineInt.(server.DetectionEngine)

		if len(byEngine[name]) != 0 {
			var eMap map[string]string

			eMap, err = engine.SyncLocalDetections(ctx, byEngine[name])
			for sid, e := range eMap {
				errMap[sid] = e
			}
			if err != nil {
				errList = append(errList, err)
			}
		}

		return true
	})

	if len(errList) != 0 {
		logger.WithError(err).Error("unable to sync detections")
		return nil, fmt.Errorf("unable to sync detections: %v", errList)
	}

	if len(errMap) != 0 {
		logger.WithField("errMap", errMap).Error("unable to sync detections")
		return nil, fmt.Errorf("unable to sync detections: %v", errMap)
	}

	syncDur := time.Since(syncStart)

	var opString string
	if args.Enable {
		opString = "Enabled"
	} else {
		opString = "Disabled"
	}

	result.Result = fmt.Sprintf(
		"Successfully %s %d detections. %s=%d, Audited=%d, Filtered=%d, Errors=%v, UpdateDuration=%s, SyncDuration=%s",
		opString,
		bulkStats.Updated,
		opString,
		bulkStats.Updated,
		bulkStats.Audited,
		bulkStats.Filtered,
		bulkStats.ErrMap,
		bulkStats.UpdateDuration,
		syncDur,
	)

	return result, nil
}
