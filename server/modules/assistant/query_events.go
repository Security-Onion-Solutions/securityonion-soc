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
	"strconv"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

var (
	ErrNoEvents = errors.New("no events found")
)

func init() {
	t := &QueryEventsTool{}
	knownTools[t.GetName()] = t
}

type QueryEventsTool struct{}

func (t *QueryEventsTool) GetName() string {
	return "query_events"
}

func (t *QueryEventsTool) GetDescription() string {
	return `- Execute OQL queries to retrieve Security Onion events
- **CRITICAL**: Understanding when to use groupby_field:
  - Use ` + "`groupby_field`" + ` when asked for: "top", "most frequent", "most common", "by count", "statistics", "summary"
  - Do NOT use ` + "`groupby_field`" + ` when asked for: "latest", "recent", "show me", "list", "details"
- Parameters:
  - ` + "`query`" + ` or ` + "`oql_query`" + `: The OQL query string
  - ` + "`groupby_field`" + `: Field to group/aggregate by (REQUIRED for frequency analysis)
  - ` + "`start_time`" + `, ` + "`end_time`" + `: Time range (e.g., "-24h", "now")
  - ` + "`limit`" + `: Maximum results to return
- Examples for GROUPED queries (frequency/statistics):
  - **"Show me the top 5 alerts"**: ` + "`" + `{"query": "tags:alert", "groupby_field": "rule.name", "limit": 5, "start_time": "-24h", "end_time": "now"}` + "`" + `
  - **"What are the most common alert types?"**: ` + "`" + `{"query": "tags:alert", "groupby_field": "rule.name", "limit": 10}` + "`" + `
  - **"Top source IPs by connection count"**: ` + "`" + `{"query": "tags:conn", "groupby_field": "source.ip", "limit": 10}` + "`" + `
  - **"Most frequent DNS queries"**: ` + "`" + `{"query": "tags:dns", "groupby_field": "dns.query.name", "limit": 20}` + "`" + `
- Examples for NON-GROUPED queries (individual events):
  - **"Show me the latest 5 alerts"**: ` + "`" + `{"query": "tags:alert", "limit": 5}` + "`" + `
  - **"List recent SSH connections"**: ` + "`" + `{"query": "tags:ssh", "limit": 10}` + "`" + `
  - **"Show alert details for ID X"**: ` + "`" + `{"query": "tags:alert AND log.id.uid:\"X\"", "limit": 1}` + "`"
}

func (t *QueryEventsTool) GetSchema() string {
	return `{
		"type": "object",
		"properties": {
			"oql_query": {
				"type": "string",
				"description": "The OQL query string to execute"
			},
			"start_time": {
				"type": "string",
				"description": "Optional start time for the query range (e.g., \"-1h\", \"2023-10-26 10:00:00\")"
			},
			"end_time": {
				"type": "string",
				"description": "Optional end time for the query range (e.g., \"now\", \"2023-10-26 12:00:00\")"
			},
			"limit": {
				"type": "integer",
				"description": "The maximum number of events to return",
				"default": 100
			},
			"groupby_field": {
				"type": "string",
				"description": "Optional OQL field name to group results by"
			}
		},
		"required": ["oql_query"]
	}`
}

type queryEventsArgs struct {
	OQLQuery     string  `json:"oql_query"`
	Query        string  `json:"query"` // Support both query and oql_query
	StartTime    *string `json:"start_time,omitempty"`
	EndTime      *string `json:"end_time,omitempty"`
	Limit        int     `json:"limit"`
	GroupByField *string `json:"groupby_field,omitempty"`
}

func (t *QueryEventsTool) Execute(ctx context.Context, server *server.Server, params string) (result *model.ToolResult, err error) {
	logger := log.FromContext(ctx)

	logger.WithField("toolParameters", params).Info("running tool for assistant")

	userId := ctx.Value(web.ContextKeyRequestorId).(string)

	args := &queryEventsArgs{}
	result = &model.ToolResult{
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

	var metricLimit, eventLimit int
	var query string
	zone := "UTC"

	if args.Query != "" && args.OQLQuery == "" {
		query = args.Query
	}

	if query != "" && !strings.Contains(query, "NOT metadata.raw_index:") {
		query = fmt.Sprintf(`(%s) AND NOT metadata.raw_index:"logs-soc-so"`, query)
	} else if query == "" {
		query = `NOT metadata.raw_index:"logs-soc-so"`
	}

	if args.GroupByField != nil && *args.GroupByField != "" {
		eventLimit = 10000
		metricLimit = args.Limit
		query = fmt.Sprintf("%s | groupby %s", query, *args.GroupByField)
	} else {
		eventLimit = args.Limit
		metricLimit = 10000
	}

	var timeRange string

	if args.StartTime != nil || args.EndTime != nil {
		start := "-24h"
		end := "now"

		if args.StartTime != nil {
			start = *args.StartTime
		}
		if args.EndTime != nil {
			end = *args.EndTime
		}

		// Parse and format times
		startFormatted := parseTimeString(start)
		endFormatted := parseTimeString(end)

		timeRange = fmt.Sprintf("%s - %s", startFormatted, endFormatted)
	}

	criteria := model.NewEventSearchCriteria()
	err = criteria.Populate(query,
		timeRange,
		"2006/01/02 3:04:05 PM",
		zone,
		strconv.Itoa(metricLimit),
		strconv.Itoa(eventLimit))
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

	// is this a groupby query?
	if args.GroupByField != nil && *args.GroupByField != "" {
		var groupbyResults []*model.EventMetric
		for k, v := range searchResults.Metrics {
			if strings.HasPrefix(k, "groupby_") {
				groupbyResults = v
				break
			}
		}

		if groupbyResults == nil {
			// no "groupby_*" key found, returning metrics as is
			result.Result = searchResults.Metrics
			return result, nil
		}

		simplifiedResults := make([]map[string]any, 0, len(groupbyResults))
		for _, g := range groupbyResults {
			var key any
			for _, k := range g.Keys {
				keys := k.([]any)
				if len(keys) > 0 {
					key = keys[0]
				}
			}

			simplifiedResults = append(simplifiedResults, map[string]any{
				*args.GroupByField: key,
				"count":            g.Value,
			})
		}

		logger.WithField("eventsFound", len(simplifiedResults)).Info("groupby query executed successfully")

		result.Result = simplifiedResults
	} else {
		events := searchResults.Events

		if len(events) == 0 {
			return nil, ErrNoEvents
		}

		logger.WithField("eventsFound", len(events)).Info("query executed successfully")

		// Log raw event size before filtering
		rawJSON, _ := json.Marshal(events)
		logger.WithField("rawEventSize", len(rawJSON)).Debug("raw event size before filtering")

		// Filter event fields to reduce size
		filteredEvents := filterEvents(events)

		// Convert to JSON
		resultJSON, err := json.MarshalIndent(filteredEvents, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal result: %w", err)
		}

		// Log filtered result size and preview
		logger.WithField("filteredResultSize", len(resultJSON)).Debug("filtered result size")

		result.Result = filteredEvents
	}

	return result, nil
}

// filterEvents filters event fields to reduce payload size
func filterEvents(events []*model.EventRecord) []map[string]any {
	// Default fields from Python implementation
	defaultFields := []string{
		"@timestamp",
		"client.name",
		"destination.ip", "destination.port",
		"dns.query.name", "dns.query_name", // Both formats
		"event.category", "event.module", "event.dataset", "event.severity", "event.severity_label",
		"file.mime_type", "file.name",
		"hash.md5", "hash.sha1",
		"host.mac",
		"http.method", "http.useragent", "http.virtual_host",
		"log.id.uid",
		"network.community_id", "network.protocol", "network.transport",
		"notice.message",
		"observer.name",
		"process.name", "process.executable",
		"rule.category", "rule.name", "rule.uuid",
		"software.name", "software.type", "software.version.unparsed",
		"source.ip", "source.port",
		"ssh.cypher_algorithm", "ssh.client", "ssh.server",
		"ssl.cipher", "ssl.server_name", "ssl.version",
		"user.name",
		"weird.name",
		"tags", // Important for identifying event types
	}

	filtered := make([]map[string]any, 0, len(events))

	for i, event := range events {
		filteredPayload := make(map[string]any)

		// Debug: log available fields for first event
		if i == 0 {
			fmt.Printf("[QueryEvents] First event payload fields:\n")
			for key := range event.Payload {
				fmt.Printf("  - %s\n", key)
			}
		}

		// Copy only default fields
		foundFields := 0
		for _, field := range defaultFields {
			// First try the field as-is (for non-nested fields)
			if val, exists := event.Payload[field]; exists && val != nil {
				filteredPayload[field] = val
				foundFields++
				if i == 0 && foundFields <= 10 {
					fmt.Printf("[QueryEvents] Found direct field '%s'\n", field)
				}
			} else if value := getNestedField(event.Payload, field); value != nil {
				// Try nested field lookup
				setNestedField(filteredPayload, field, value)
				foundFields++
				if i == 0 && foundFields <= 10 {
					fmt.Printf("[QueryEvents] Found nested field '%s'\n", field)
				}
			}
		}

		if i == 0 {
			fmt.Printf("[QueryEvents] Filtered %d fields from first event\n", foundFields)
		}

		filtered = append(filtered, map[string]any{
			"payload": filteredPayload,
		})
	}

	return filtered
}

// getNestedField retrieves a value from a nested map using dot notation
func getNestedField(data map[string]any, field string) any {
	parts := splitDotNotation(field)
	current := data

	for i, part := range parts {
		if i == len(parts)-1 {
			return current[part]
		}

		if next, ok := current[part].(map[string]any); ok {
			current = next
		} else {
			return nil
		}
	}

	return nil
}

// setNestedField sets a value in a nested map using dot notation
func setNestedField(data map[string]any, field string, value any) {
	parts := splitDotNotation(field)
	current := data

	for i, part := range parts {
		if i == len(parts)-1 {
			current[part] = value
			return
		}

		if _, ok := current[part]; !ok {
			current[part] = make(map[string]any)
		}

		current = current[part].(map[string]any)
	}
}

// splitDotNotation splits a field name by dots
func splitDotNotation(field string) []string {
	// Simple split for now. In production, handle escaped dots
	return strings.Split(field, ".")
}
