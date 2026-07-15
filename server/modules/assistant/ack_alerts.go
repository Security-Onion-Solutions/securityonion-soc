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
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
)

func init() {
	t := &AckAlertsTool{}
	knownTools[t.GetName()] = t
}

type AckAlertsTool struct{}

func (t *AckAlertsTool) GetName() string {
	return "ack_alerts"
}

func (t *AckAlertsTool) GetDescription() string {
	return `Acknowledge (A.K.A. ack) alerts in Security Onion by querying them with an OQL query.
	If range_start or range_end is specified, then date_range_format is required. If multiple alerts are
	difficult to gather in one query, try OR'ing all the Ids together in the search_filter. When querying
	by id, use _id instead of soc_id as the field.`
}

func (t *AckAlertsTool) GetSchema() model.JSONSchema {
	return model.JSONSchema{
		Json: &model.ToolSchema{
			Type: "object",
			Properties: map[string]model.ToolSchemaProperty{
				"search_filter": {
					Type:        "string",
					Description: `OQL search filter to find matching events (e.g., "tags:alert AND rule.uuid:xyz")`,
				},
				"event_filter": {
					Type:        "object",
					Description: "Optional dict of field:value pairs to further filter events",
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

type ackAlertArgs struct {
	SearchFilter string         `json:"search_filter"`
	EventFilter  map[string]any `json:"event_filter,omitempty"`
	RangeStart   string         `json:"range_start,omitempty"`
	RangeEnd     string         `json:"range_end,omitempty"`
	RangeFormat  string         `json:"range_format,omitempty"`
}

func (t *AckAlertsTool) Execute(ctx context.Context, server *server.Server, req *model.ToolRequest) (result *model.ToolResponse, err error) {
	logger := log.FromContext(ctx).WithFields(log.Fields{
		"sessionId": req.SessionId,
		"toolUseId": req.ToolUseId,
	})

	logger.WithField("toolParameters", req.Params).Info("running tool for assistant")

	userId := ctx.Value(web.ContextKeyRequestorId).(string)

	args := &ackAlertArgs{}
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

	err = json.Unmarshal([]byte(req.Params), args)
	if err != nil {
		logger.WithError(err).WithField("toolParams", req.Params).Error("failed to unmarshal tool params")
		return nil, errors.New("ERROR_ASSISTANT_UNMARSHAL_PARAMS")
	}

	var timeRange string

	if args.RangeStart != "" || args.RangeEnd != "" {
		timeRange = parseRangeAllowRelative(args.RangeStart, args.RangeEnd, args.RangeFormat)
	}

	result.Parameters = args

	crit := model.NewEventAckCriteria()
	crit.Acknowledge = true
	crit.SearchFilter = "(tags:alert AND NOT event.acknowledged:true AND NOT event.escalated:true) AND (" + args.SearchFilter + ")"
	crit.EventFilter = args.EventFilter
	crit.DateRange = timeRange
	crit.DateRangeFormat = "2006/01/02 3:04:05 PM"
	crit.Timezone = "UTC"

	if len(crit.EventFilter) == 0 {
		crit.EventFilter = map[string]any{
			"tags": "alert",
		}
	}

	results, err := server.Eventstore.Acknowledge(ctx, crit)
	if err != nil {
		logger.WithError(err).Error("error acknowledging alert")
		return nil, err
	}

	if results.UpdatedCount == 0 {
		result.Result = "No alert was modified"
	} else {
		plural := ""
		if results.UpdatedCount > 1 {
			plural = "s"
		}

		result.Result = fmt.Sprintf("%d eligible alert%s were successfully acknowledged", results.UpdatedCount, plural)
	}

	return result, nil
}
