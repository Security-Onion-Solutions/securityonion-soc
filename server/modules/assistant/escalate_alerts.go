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
	return "Escalate an alert in Security Onion to a new case using its unique identifier (soc_id)."
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
				"date_range": {
					Type:        "string",
					Description: `Date range for searching events (e.g., "2024/12/03 02:31:35 PM - 2024/12/04 02:31:35 PM"). The range must contain two dates. Do not specify a timezone or any offsets in this field. If this field is specified, a date_range_format is required.`,
				},
				"date_range_format": {
					Type:        "string",
					Description: `Format of the date range (default: "2006/01/02 3:04:05 PM"). The format must be specified using Go's time package's reference layout format. "Relative" is not an acceptable format. Required when a date_range is provided.`,
				},
				"timezone": {
					Type:        "string",
					Description: `Timezone for the date range (default: "UTC")`,
				},
			},
			Required: []string{"search_filter"},
		},
	}
}

type escalateAlertArgs struct {
	SearchFilter    string `json:"search_filter"`
	CaseTitle       string `json:"case_title"`
	DateRange       string `json:"date_range,omitempty"`
	DateRangeFormat string `json:"date_range_format,omitempty"`
	Timezone        string `json:"timezone,omitempty"`
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

	if args.DateRange != "" {
		if args.DateRangeFormat == "" {
			return nil, fmt.Errorf("date_range_format is required when date_range is provided")
		}

		_, _, err = util.ParseDateRange(args.DateRange, args.DateRangeFormat, args.Timezone)
		if err != nil {
			return nil, fmt.Errorf("error parsing date_range: %w", err)
		}
	}

	result.Parameters = args

	searchCrit := model.NewEventSearchCriteria()

	err = searchCrit.Populate(
		"(tags:alert AND NOT event.acknowledged:true AND NOT event.escalated:true) AND ("+args.SearchFilter+")",
		args.DateRange,
		args.DateRangeFormat,
		args.Timezone,
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
