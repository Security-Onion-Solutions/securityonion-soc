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
	return "Escalate an alert in Security Onion to a case using the alert's unique identifier (_id). This tool should create a new case if case_title is provided. On the other hand, if case_id is provided, escalate to that case.\n" +
		"- *IMPORTANT* You MUST provide ONE of case_title or case_id, but NEVER both."
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
				"case_id": {
					Type:        "string",
					Description: `Id of the case we want to escalate to. (e.g., "Y6i16JkBZwOCEak1tWqX")`,
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
			},
			Required: []string{"search_filter"},
		},
	}
}

type escalateAlertArgs struct {
	SearchFilter string `json:"search_filter"`
	CaseTitle    string `json:"case_title"`
	CaseId       string `json:"case_id"`
	RangeStart   string `json:"range_start,omitempty"`
	RangeEnd     string `json:"range_end,omitempty"`
	RangeFormat  string `json:"range_format,omitempty"`
}

func (t *EscalateAlertsTool) Execute(ctx context.Context, server *server.Server, params string, auxData string) (result *model.ToolResponse, err error) {
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
		return nil, errors.New("ERROR_ASSISTANT_UNMARSHAL_PARAMS")
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

	var modelCase *model.Case

	// Step 2: Create Case
	if args.CaseTitle != "" {
		newCase := model.NewCase()
		newCase.Title = args.CaseTitle
		newCase.Description = "Review escalated event details in the Events tab below. Click here to update this description."

		modelCase, err = server.Casestore.Create(ctx, newCase)
		if err != nil {
			logger.WithError(err).Error("error creating case for escalated alert")

			return nil, err
		}
	} else {
		modelCase, err = server.Casestore.GetCase(ctx, args.CaseId)
		if err != nil {
			logger.WithField("caseId", args.CaseId).WithError(err).Error("error fetching case for escalated alert")

			return nil, err
		}
	}
	for _, ev := range relatedEvents {
		ev.CaseId = modelCase.Id
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
	}).Info("linked alerts case")

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
		logger.WithError(err).Error("error escalating alert")

		return nil, err
	}

	if ackResults.UpdatedCount == 0 {
		result.Result = "No case was created"
	} else {
		plural := ""
		if ackResults.UpdatedCount != 1 {
			plural = "s"
		}

		result.Result = fmt.Sprintf(`Successfully added %d alert%s to case "%s" (Id: %s)`, created, plural, modelCase.Title, modelCase.Id)
	}

	return result, nil
}
