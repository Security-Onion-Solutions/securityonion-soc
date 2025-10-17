// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
)

func init() {
	t := &EscalateAlertsTool{}
	knownTools[t.GetName()] = t
}

type EscalateAlertsTool struct{}

func (t *EscalateAlertsTool) GetName() string {
	return "escalate_alerts"
}

func (t *EscalateAlertsTool) GetDescription() string {
	return "Escalate an alert in Security Onion to a new case using the alert's unique identifier (_id). This tool will only create new cases, and never attach to existing cases. If a user wishes to add to an existing case, they must manually do so through the SOC case interface.\n" +
		"- Examples for wild cards in the search_filter:\n" +
		"  - Search terms cannot begin with a wildcard (e.g., `*xyz` the wildcard is ignored, but `xyz*` is valid)\n" +
		"  - When using wildcards, do not wrap the value in quotes, instead use parentheses (e.g., `rule.name:(A B*)` is valid, but `rule.name:\"A B*\"` will not work as expected)"
}

func (t *EscalateAlertsTool) GetSchema() model.JSONSchema {
	return model.JSONSchema{
		Json: &model.ToolSchema{
			Type: "object",
			Properties: map[string]model.ToolSchemaProperty{
				"search_filter": {
					Type:        "string",
					Description: `OQL search filter to find matching events (e.g., "tags:alert AND rule.uuid:xyz")`,
				},
				"case_title": {
					Type:        "string",
					Description: `Title for the new case, usually named after the rule name of the alert(s) being escalated (e.g., "ET SCAN Potential SSH Scan")`,
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
			},
			Required: []string{"search_filter"},
		},
	}
}

type escalateAlertArgs struct {
	SearchFilter string `json:"search_filter"`
	CaseTitle    string `json:"case_title"`
	RangeStart   string `json:"range_start,omitempty"`
	RangeEnd     string `json:"range_end,omitempty"`
	RangeFormat  string `json:"range_format,omitempty"`
}

func (t *EscalateAlertsTool) Execute(ctx context.Context, server *server.Server, params string) (result *model.ToolResponse, err error) {
	logger := log.FromContext(ctx)

	logger.WithField("toolParameters", params).Info("running tool for assistant")

	userId := ctx.Value(web.ContextKeyRequestorId).(string)

	args := &escalateAlertArgs{}
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

	var timeRange string

	if args.RangeStart != "" || args.RangeEnd != "" {
		timeRange = parseRangeAllowRelative(args.RangeStart, args.RangeEnd, args.RangeFormat)
	}

	result.Parameters = args

	searchCrit := model.NewEventSearchCriteria()
	zone := "UTC"

	err = searchCrit.Populate(
		"(tags:alert AND NOT event.acknowledged:true AND NOT event.escalated:true) AND ("+args.SearchFilter+")",
		timeRange,
		"2006/01/02 3:04:05 PM",
		zone,
		"0",
		"10000",
	)
	if err != nil {
		return nil, err
	}

	searchCrit.SortFields = []*model.SortCriteria{
		{
			Field: "@timestamp",
			Order: "desc",
		},
	}

	// Step 1: Execute Search Filter, Retrieve Alerts

	searchResults, err := server.Eventstore.Search(ctx, searchCrit)
	if err != nil {
		logger.WithError(err).Error("error searching for alerts to escalate")

		return nil, err
	}

	// convert EventRecord to RelatedEvent
	relatedEvents := make([]*model.RelatedEvent, 0, len(searchResults.Events))
	for _, event := range searchResults.Events {
		related := model.NewRelatedEvent()
		related.Fields = event.Payload
		related.Fields["soc_id"] = event.Id
		related.Fields["soc_timestamp"] = event.Payload["@timestamp"]

		relatedEvents = append(relatedEvents, related)
	}

	if len(relatedEvents) == 0 {
		result.Result = "No alerts found with that query. No case was created."

		return result, nil
	}

	// Step 2: Create Case

	newCase := model.NewCase()
	newCase.Title = args.CaseTitle
	newCase.Description = "Review escalated event details in the Events tab below. Click here to update this description."

	savedCase, err := server.Casestore.Create(ctx, newCase)
	if err != nil {
		logger.WithError(err).Error("error creating case for escalated alert")

		return nil, err
	}

	for _, ev := range relatedEvents {
		ev.CaseId = savedCase.Id
	}

	// Step 3: Link Alerts to Case

	created, errMap, err := server.Casestore.CreateRelatedEvents(ctx, relatedEvents)
	if err != nil {
		logger.WithError(err).Error("error linking alerts to new case")

		return nil, err
	}

	logger.WithFields(log.Fields{
		"relatedEventsCreated": created,
		"errMap":               util.TruncateMap(errMap, 20),
	}).Info("linked alerts to new case")

	// Step 4: Mark Alerts as Escalated

	ackCrit := model.NewEventAckCriteria()
	ackCrit.Acknowledge = true
	ackCrit.Escalate = true
	ackCrit.SearchFilter = searchCrit.ParsedQuery.String()
	ackCrit.DateRange = timeRange
	ackCrit.DateRangeFormat = "2006/01/02 3:04:05 PM"
	ackCrit.Timezone = zone
	ackCrit.EventFilter = map[string]any{
		"tags": "alert",
	}

	ackResults, err := server.Eventstore.Acknowledge(ctx, ackCrit)
	if err != nil {
		logger.WithError(err).Error("error escalating alert to new case")

		return nil, err
	}

	if ackResults.UpdatedCount == 0 {
		result.Result = "No case was created"
	} else {
		plural := ""
		if ackResults.UpdatedCount != 1 {
			plural = "s"
		}

		result.Result = fmt.Sprintf(`Successfully added %d alert%s to new case "%s" (Id: %s)`, created, plural, savedCase.Title, savedCase.Id)
	}

	return result, nil
}
