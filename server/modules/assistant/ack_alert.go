// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
)

func init() {
	t := &AckAlertTool{}
	knownTools[t.GetName()] = t
}

type AckAlertTool struct{}

func (t *AckAlertTool) GetName() string {
	return "ack_alert"
}

func (t *AckAlertTool) GetDescription() string {
	return "Acknowledge (A.K.A. ack) an alert in Security Onion using its unique identifier (soc_id)."
}

func (t *AckAlertTool) GetSchema() model.JSONSchema {
	return model.JSONSchema{
		Json: &model.ToolSchema{
			Type: "object",
			Properties: map[string]model.ToolSchemaProperty{
				"alert_id": {
					Type:        "string",
					Description: "The unique identifier of the alert to acknowledge. This is the `soc_id` field of the alert.",
				},
			},
			Required: []string{"alert_id"},
		},
	}
}

type ackAlertArgs struct {
	AlertId string `json:"alert_id"`
}

func (t *AckAlertTool) Execute(ctx context.Context, server *server.Server, params string) (result *model.ToolResponse, err error) {
	logger := log.FromContext(ctx)

	logger.WithField("toolParameters", params).Info("running tool for assistant")

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

	err = json.Unmarshal([]byte(params), args)
	if err != nil {
		return nil, err
	}

	result.Parameters = args

	crit := model.NewEventAckCriteria()
	crit.Acknowledge = true
	crit.SearchFilter = "tags:alert AND NOT event.acknowledged:true AND NOT event.escalated:true"
	crit.EventFilter = map[string]any{
		"soc_id": args.AlertId,
	}

	results, err := server.Eventstore.Acknowledge(ctx, crit)
	if err != nil {
		logger.WithError(err).Error("error acknowledging alert")

		return nil, err
	}

	if results.UpdatedCount == 0 {
		result.Result = "No alert was modified"
	} else {
		result.Result = "Success"
	}

	return result, nil
}
