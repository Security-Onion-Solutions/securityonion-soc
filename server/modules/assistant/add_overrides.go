// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
	t := &AddOverridesTool{}
	knownTools[t.GetName()] = t
}

type AddOverridesTool struct{}

func (t *AddOverridesTool) GetName() string {
	return "add_overrides"
}

func (t *AddOverridesTool) GetDescription() string {
	return `Adds new overrides to existing detections. Overrides modify detection behavior (suppress alerts, set thresholds, apply filters, etc.).

CRITICAL REQUIREMENTS:
- All target detections MUST use the same engine (Suricata or Sigma) - overrides are engine-specific
- Use 999-day date range unless specified otherwise
- Only include NEW overrides, not the ones that these detections already have`
}

func (t *AddOverridesTool) GetSchema() model.JSONSchema {
	return model.JSONSchema{
		Json: &model.ToolSchema{
			Type: "object",
			Properties: map[string]model.ToolSchemaProperty{
				"search_filter": {
					Type:        "string",
					Description: "OQL query to find target detections.",
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
					Description: `Array of new override objects to append to each matched detection. Always use array format even for single override.`,
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
					Description: "Max detections to return. Omit unless user specifies (e.g., \"add to 5 most recent detections\").",
				},
			},
			Required: []string{"search_filter"},
		},
	}
}

type AddOverridesArgs struct {
	SearchFilter string           `json:"search_filter"`
	Overrides    []map[string]any `json:"overrides"`
	RangeStart   string           `json:"range_start,omitempty"`
	RangeEnd     string           `json:"range_end,omitempty"`
	RangeFormat  string           `json:"range_format,omitempty"`
	Limit        int              `json:"limit"`
}

func (t *AddOverridesTool) Execute(ctx context.Context, srv *server.Server, params string, auxData string) (result *model.ToolResponse, err error) {
	logger := log.FromContext(ctx)

	logger.WithField("toolParameters", params).Info("running tool for assistant")

	err = srv.CheckAuthorized(ctx, "write", "detections")
	if err != nil {
		return nil, fmt.Errorf("user is not authorized to write detections: %w", err)
	}

	userId := ctx.Value(web.ContextKeyRequestorId).(string)

	args := &AddOverridesArgs{}
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

	newOverrides := populateOverridesFromMaps(args.Overrides, false)

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

	engInt, ok := srv.DetectionEngines.Load(detects[0].Engine)
	if !ok {
		logger.WithField("detectionEngine", detects[0].Engine).Error("unsupported engine")
		return nil, fmt.Errorf("unsupported engine %s", detects[0].Engine)
	}

	engine := engInt.(server.DetectionEngine)

	bulkStats, err := srv.Detectionstore.BulkAddOverrides(ctx, newOverrides, detects, logger)
	if err != nil {
		logger.WithError(err).Error("error adding overrides")
		return nil, fmt.Errorf("error adding overrides: %w", err)
	}

	syncDetects := bulkStats.NeedToSync
	syncStart := time.Now()

	errMap, err := engine.SyncLocalDetections(ctx, syncDetects)
	if err != nil {
		logger.WithError(err).Error("unable to sync detection")
		return nil, fmt.Errorf("unable to sync detections: %w", err)
	}

	if len(errMap) != 0 {
		logger.WithField("errMap", errMap).Error("unable to sync detection")
		return nil, fmt.Errorf("unable to sync detections: %v", errMap)
	}

	syncDur := time.Since(syncStart)

	plural := ""
	if len(newOverrides) > 1 {
		plural = "s"
	}

	result.Result = fmt.Sprintf(
		"Successfully added %d override%s to %d detections. Updated=%d, Audited=%d, Errors=%v, UpdateDuration=%s, SyncDuration=%s",
		len(newOverrides),
		plural,
		bulkStats.Updated,
		bulkStats.Updated,
		bulkStats.Audited,
		bulkStats.ErrMap,
		bulkStats.UpdateDuration,
		syncDur,
	)

	return result, nil
}
