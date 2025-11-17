// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
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
	return "- Execute OQL queries to retrieve Security Onion detections that are most applicable to the given alert(s) (or other event(s)/topic(s)) at hand.\n" +
		"- Search for detections by referencing any potentially relevant field(s), whichever you see fit from the ones described to you.\n" +
		"- *IMPORTANT* All queries should include `AND _index:\"*:so-detection\" AND so_kind:detection` appended to the end. The quotes around *:so-detection MUST be included.\n" +
		"- When searching for detections, specify a date range of 999 days ago.\n" +
		"- Examples for wild cards in the oql_query:\n" +
		"  - Search terms cannot begin with a wildcard (e.g., `*xyz` the wildcard is ignored, but `xyz*` is valid)\n" +
		"  - When using wildcards, do not wrap the value in quotes, instead use parentheses (e.g., `so_detection.title:(A B*)` is valid, but `so_detection.title:\"A B*\"` will not work as expected)\n" +
		"- If the most applicable detection is clear-cut, explain that to the user. Otherwise, give multiple options, compare them, and let the user choose."
}

func (t *QueryDetectionsTool) GetSchema() model.JSONSchema {
	return model.JSONSchema{
		Json: &model.ToolSchema{
			Type: "object",
			Properties: map[string]model.ToolSchemaProperty{
				"oql_query": {
					Type: "string",
					Description: "The OQL query string to execute. Here is a run-down of each of the potentially relevant fields you might want to use in your query:\n" +
						"- so_detection.id: The ID assigned to this detection by the server. This is a read-only field. Example: \"gQKCepgBAWAm-kn2lYs2\"\n" +
						"- so_detection.createTime: The date and time that this detection was created. This is a read-only field. Example: \"2024-11-14T15:03:22Z\"\n" +
						"- so_detection.userId: The ID of the user that created this detection. Example: \"dcbe6004-f6e0-4579-9f98-9576201ffb29\"\n" +
						"- so_detection.publicId: The public ID shared across all Security Onion grids. Example: \"923421c7-9b1e-45d4-80cc-e21d060c8723\"\n" +
						"- so_detection.title: Summarized title of the detection. Example: \"Security Onion - Grid Node Login Failure (SSH)\"\n" +
						"- so_detection.severity: The severity classification of this detection. This MUST be either \"unknown\", \"informational\", \"low\", \"medium\", \"high\", or \"critical\".\n" +
						"- so_detection.author: The original author of this detection. This can be a mixture of email address, organization name, first name, or any freeform value. Example: \"Security Onion Solutions\"\n" +
						"- so_detection.category: Used for categorizing this detection into a broader grouping such as firewalls or web servers. Example: \"ps_script\"\n" +
						"- so_detection.description: Brief explanation of this detection. Example: \"Detects when a user fails to login to a grid node via SSH. Review associated logs for username and source IP.\"\n" +
						"- so_detection.content: The underlying detection rule source content. Example: \"title: CobaltStrike Named Pipe\\nid: ...\\n logsource:\\n ...\\ncondition: selection\\nfalsepositives:\\n...\"\n" +
						"- so_detection.isEnabled: Indicates whether this detection is currently enabled in the Security Onion grid. Example: true\n" +
						"- so_detection.isCommunity: Indicates whether this detection originated from a community ruleset. Duplicated detections will show 'false'. Example: true\n" +
						"- so_detection.engine: The engine that processes this detection.\n" +
						"- so_detection.language: The language that this detection uses. This MUST be either \"sigma\", \"suricata\", or \"yara\".\n" +
						"- so_detection.overrides: A list of tuning overrides that apply to this detection.\n" +
						"- so_detection.tags: An optional list of user-defined tags, useful for grouping similar detections together.\n" +
						"- so_detection.ruleset: The name of the ruleset from which this detection originated, or __custom__ if the ruleset was created outside of a ruleset. Example: \"__custom__\"\n" +
						"- so_detection.license: The license that applies to this detection. Example: \"DRL\"\n" +
						"- so_detection.sourceCreated: The date and time when the underlying detection rule source was created. This is not when the detection was added to this grid.\n" +
						"- so_detection.sourceUpdated: The date and time when the underlying detection rule source was last updated. This is not when the detection was updated in this grid.\n" +
						"- so_detection.product: Used by Sigma rules for filtering log outputs to a specific product, such as the Windows eventlog types. Example: \"windows\"\n" +
						"- so_detection.service: Used by Sigma rules for filtering a subset of log outputs to a specific server. Example: \"sshd\"\n" +
						"- @timestamp: The date and time when this detection was last created/updated/modified. Example: \"2025-11-12T19:38:17.413984706Z\"",
				},
				"range_start": {
					Type:        "string",
					Description: "Optional start time for the query range (e.g., \"-1h\", \"2023/10/26 10:00:00 AM\"). Default is 24 hours ago (\"-24h\")",
				},
				"range_end": {
					Type:        "string",
					Description: "Optional end time for the query range (e.g., \"now\", \"2023/10/26 12:00:00 PM\"). Default is now.",
				},
				"range_format": {
					Type:        "string",
					Description: "Format of the date range (default: \"2006/01/02 3:04:05 PM\"). The format must be specified using Go's time package's reference layout format. Required if either range_start or range_end is provided.",
				},
				"limit": {
					Type:        "integer",
					Description: "The maximum number of detections to return",
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
		return nil, err
	}

	result.Parameters = args

	var metricLimit, detectLimit int
	zone := "UTC"
	query := args.OQLQuery

	if args.Query != "" && args.OQLQuery == "" {
		query = args.Query
	}

	if query != "" && !strings.Contains(query, "NOT metadata.raw_index:") {
		query = fmt.Sprintf(`(%s) AND NOT metadata.raw_index:"logs-soc-so"`, query)
	} else if query == "" {
		query = `NOT metadata.raw_index:"logs-soc-so"`
	}

	if args.Limit > 0 {
		detectLimit = args.Limit
	} else {
		detectLimit = 10
	}
	metricLimit = 10000

	var timeFormat string

	if args.RangeFormat != "" {
		timeFormat = args.RangeFormat
	} else {
		timeFormat = "2006/01/02 3:04:05 PM"
	}

	var timeRange string

	if args.RangeStart != "" || args.RangeEnd != "" {
		timeRange = parseRangeAllowRelative(args.RangeStart, args.RangeEnd, timeFormat)
	}

	criteria := model.NewEventSearchCriteria()
	err = criteria.Populate(query,
		timeRange,
		timeFormat,
		zone,
		strconv.Itoa(metricLimit),
		strconv.Itoa(detectLimit))
	if err != nil {
		return nil, err
	}

	criteria.SortFields = []*model.SortCriteria{
		{
			Field: "@timestamp",
			Order: "desc",
		},
	}

	err = server.CheckAuthorized(ctx, "read", "detections")
	if err != nil {
		return nil, err
	}

	searchResults, err := server.Eventstore.Search(ctx, criteria)
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
		return nil, fmt.Errorf("failed to marshal result: %w", err)
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
