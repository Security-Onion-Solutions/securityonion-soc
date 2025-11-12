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

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
)

func init() {
	t := &QueryCasesTool{}
	knownTools[t.GetName()] = t
}

type QueryCasesTool struct{}

type QueryCasesResult struct {
	QueryResults []map[string]any `json:"query_results"`
	RecentCases  []map[string]any `json:"recent_cases"`
}

func (t *QueryCasesTool) GetName() string {
	return "query_cases"
}

func (t *QueryCasesTool) GetDescription() string {
	return "- Execute OQL queries to retrieve Security Onion cases that are most applicable to the given alert(s) (or other event(s)/topic(s)) at hand.\n" +
		"- Search for cases by referencing so_case.description and so_case.title\n" +
		"- *IMPORTANT* All queries should include `AND _index:\"*:so-case\" AND so_kind:case` appended to the end. The quotes around *:so-case MUST be included.\n" +
		"- When searching for cases, specify a date range of 999 days ago.\n" +
		"- Examples for wild cards in the oql_query:\n" +
		"  - Search terms cannot begin with a wildcard (e.g., `*xyz` the wildcard is ignored, but `xyz*` is valid)\n" +
		"  - When using wildcards, do not wrap the value in quotes, instead use parentheses (e.g., `so_case.title:(A B*)` is valid, but `so_case.title:\"A B*\"` will not work as expected)\n" +
		"- In addition to search results, you'll also get the user's most recently viewed cases. This field is called recent_cases.\n" +
		"- If the most applicable case is clear-cut, explain that to the user. Otherwise, give multiple options, compare them, and let the user choose."
}

func (t *QueryCasesTool) GetSchema() model.JSONSchema {
	return model.JSONSchema{
		Json: &model.ToolSchema{
			Type: "object",
			Properties: map[string]model.ToolSchemaProperty{
				"oql_query": {
					Type:        "string",
					Description: "The OQL query string to execute",
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
					Description: "The maximum number of cases to return",
					Default:     100,
				},
			},
			Required: []string{"oql_query"},
		},
	}
}

type queryCasesArgs struct {
	OQLQuery    string `json:"oql_query"`
	Query       string `json:"query"` // Support both query and oql_query
	RangeStart  string `json:"range_start,omitempty"`
	RangeEnd    string `json:"range_end,omitempty"`
	RangeFormat string `json:"range_format,omitempty"`
	Limit       int    `json:"limit"`
}

func (t *QueryCasesTool) Execute(ctx context.Context, server *server.Server, params string, auxData string) (result *model.ToolResponse, err error) {
	logger := log.FromContext(ctx)

	logger.WithField("toolParameters", params).Info("running tool for assistant")

	userId := ctx.Value(web.ContextKeyRequestorId).(string)

	args := &queryCasesArgs{}
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

	var metricLimit, caseLimit int
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
		caseLimit = args.Limit
	} else {
		caseLimit = 10
	}
	metricLimit = 10000

	var timeRange string

	if args.RangeStart != "" || args.RangeEnd != "" {
		timeRange = parseRangeAllowRelative(args.RangeStart, args.RangeEnd, args.RangeFormat)
	}

	criteria := model.NewEventSearchCriteria()
	err = criteria.Populate(query,
		timeRange,
		"2006/01/02 3:04:05 PM",
		zone,
		strconv.Itoa(metricLimit),
		strconv.Itoa(caseLimit))
	if err != nil {
		return nil, err
	}

	criteria.SortFields = []*model.SortCriteria{
		{
			Field: "@timestamp",
			Order: "desc",
		},
	}

	searchResults, err := server.Eventstore.Search(ctx, criteria)
	if err != nil {
		return nil, err
	}

	caseEvents := searchResults.Events

	// Parse auxData first, regardless of whether cases are found
	recentCases := []map[string]any{}
	err = json.Unmarshal([]byte(auxData), &recentCases)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal recent cases from auxData: %w", err)
	}

	if len(caseEvents) == 0 && len(recentCases) == 0 {
		result.Result = "No cases found"
		return result, nil
	}

	logger.WithField("recentCasesFound", len(recentCases)).Debug("recent cases parsed from auxData")

	logger.WithField("casesFound", len(caseEvents)).Info("query executed successfully")

	// Log raw case size before filtering
	rawJSON, _ := json.Marshal(caseEvents)
	logger.WithField("rawCaseSize", len(rawJSON)).Debug("raw case size before filtering")

	// Filter case fields to reduce size
	filteredCases := filterCases(caseEvents)

	// Convert to JSON
	resultJSON, err := json.MarshalIndent(filteredCases, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal result: %w", err)
	}

	// Log filtered result size and preview
	logger.WithField("filteredResultSize", len(resultJSON)).Debug("filtered result size")

	result.Result = QueryCasesResult{
		QueryResults: filteredCases,
		RecentCases:  recentCases,
	}

	return result, nil
}

// filterCases filters case event fields to reduce payload size
func filterCases(events []*model.EventRecord, extraFields ...string) []map[string]any {
	// Default fields from Python implementation
	defaultFields := []string{
		"so_case.assigneeId",
		"so_case.category",
		"so_case.completeTime",
		"so_case.createTime",
		"so_case.description",
		"so_case.pap",
		"so_case.priority",
		"so_case.severity",
		"so_case.startTime",
		"so_case.status",
		"so_case.tags",
		"so_case.template",
		"so_case.title",
		"so_case.tlp",
		"so_case.userId",
		"@timestamp",
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
