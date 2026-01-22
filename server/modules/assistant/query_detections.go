// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

func init() {
	t := &QueryDetectionsTool{}
	knownTools[t.GetName()] = t
}

type QueryDetectionsTool struct{}

func (t *QueryDetectionsTool) GetName() string {
	return "query_detections"
}

func (t *QueryDetectionsTool) GetDescription() string {
	return "Retrieve Security Onion detections using OQL queries. " +
		"Use a 999-day date range. Search any relevant detection fields. " +
		"Present clear-cut matches directly, or provide multiple options with comparisons for user selection."
}

func (t *QueryDetectionsTool) GetSchema() model.JSONSchema {
	return model.JSONSchema{
		Json: &model.ToolSchema{
			Type: "object",
			Properties: map[string]model.ToolSchemaProperty{
				"oql_query": {
					Type:        "string",
					Description: "OQL query to search detections.",
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
					Description: "Maximum detections to return.",
					Default:     100,
				},
			},
			Required: []string{"oql_query"},
		},
	}
}

type queryDetectionsArgs struct {
	OQLQuery    string `json:"oql_query"`
	Query       string `json:"query"` // Support both query and oql_query
	RangeStart  string `json:"range_start,omitempty"`
	RangeEnd    string `json:"range_end,omitempty"`
	RangeFormat string `json:"range_format,omitempty"`
	Limit       int    `json:"limit"`
}

func (t *QueryDetectionsTool) Execute(ctx context.Context, server *server.Server, params string, auxData string) (result *model.ToolResponse, err error) {
	logger := log.FromContext(ctx)

	logger.WithField("toolParameters", params).Info("running tool for assistant")

	err = server.CheckAuthorized(ctx, "read", "detections")
	if err != nil {
		return nil, errors.New("ERROR_PERMISSION_DENIED")
	}

	userId := ctx.Value(web.ContextKeyRequestorId).(string)

	args := &queryDetectionsArgs{}
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
		logger.WithError(err).WithField("toolParams", params).Error("failed to unmarshal tool params")
		return nil, errors.New("ERROR_ASSISTANT_UNMARSHAL_PARAMS")
	}

	result.Parameters = args

	query := args.OQLQuery

	if args.Query != "" && args.OQLQuery == "" {
		query = args.Query
	}

	if query != "" && !strings.Contains(query, "NOT metadata.raw_index:") {
		query = fmt.Sprintf(`(%s) AND NOT metadata.raw_index:"logs-soc-so"`, query)
	} else if query == "" {
		query = `NOT metadata.raw_index:"logs-soc-so"`
	}

	var detectLimit int
	if args.Limit > 0 {
		detectLimit = args.Limit
	} else {
		detectLimit = 10
	}

	searchResults, err := server.Detectionstore.QueryWithRange(ctx, query, args.RangeStart, args.RangeEnd, args.RangeFormat, detectLimit)
	if err != nil {
		return nil, err
	}

	detectEvents := searchResults.Events

	if len(detectEvents) == 0 {
		result.Result = "No detections found"
		return result, nil
	}

	logger.WithField("detectionsFound", len(detectEvents)).Info("query executed successfully")

	// Log raw detection size before filtering
	rawJSON, _ := json.Marshal(detectEvents)
	logger.WithField("rawDetectionSize", len(rawJSON)).Debug("raw detection size before filtering")

	// Filter detection fields to reduce size
	filteredDetects := filterDetections(detectEvents)

	// Convert to JSON
	resultJSON, err := json.MarshalIndent(filteredDetects, "", "  ")
	if err != nil {
		logger.WithError(err).WithField("filteredDetects", filteredDetects).Error("failed to marshal tool result")
		return nil, errors.New("ERROR_ASSISTANT_MARSHAL_TOOL_RESULT")
	}

	// Log filtered result size and preview
	logger.WithField("filteredResultSize", len(resultJSON)).Debug("filtered result size")

	result.Result = filteredDetects

	return result, nil
}

// filterDetections filters detection event fields to reduce payload size
func filterDetections(events []*model.EventRecord, extraFields ...string) []map[string]any {
	// Default fields from Python implementation
	defaultFields := []string{
		"@timestamp",
		"so_detection.id",
		"so_detection.createTime",
		"so_detection.userId",
		"so_detection.publicId",
		"so_detection.title",
		"so_detection.severity",
		"so_detection.author",
		"so_detection.category",
		"so_detection.description",
		"so_detection.content",
		"so_detection.isEnabled",
		"so_detection.isCommunity",
		"so_detection.engine",
		"so_detection.language",
		"so_detection.overrides",
		"so_detection.tags",
		"so_detection.ruleset",
		"so_detection.license",
		"so_detection.sourceCreated",
		"so_detection.sourceUpdated",
		"so_detection.product",
		"so_detection.service",
	}

	filtered := make([]map[string]any, 0, len(events))

	fields := append(defaultFields, extraFields...)

	for _, event := range events {
		filteredPayload := map[string]any{
			"_id": event.Id,
		}

		// Copy only default fields starting with the Id field
		for _, field := range fields {
			// First try the field as-is (for non-nested fields)
			if val, exists := event.Payload[field]; exists && val != nil {
				filteredPayload[field] = val
			} else if value := getNestedField(event.Payload, field); value != nil {
				// Try nested field lookup
				setNestedField(filteredPayload, field, value)
			}
		}

		filtered = append(filtered, map[string]any{
			"payload": filteredPayload,
		})
	}

	return filtered
}
