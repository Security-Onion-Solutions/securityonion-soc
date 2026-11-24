// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"errors"
	"maps"
	"slices"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
)

func init() {
	t := &ListDestinationsTool{}
	knownTools[t.GetName()] = t
}

type ListDestinationsTool struct{}

func (t *ListDestinationsTool) GetName() string {
	return "list_destinations"
}

func (t *ListDestinationsTool) GetDescription() string {
	return `List the configured notification destinations, for choosing destinations on send_notification.
	Only administrators may list destinations; for anyone else this fails, and send_notification still
	accepts the destination names the user gives. A destination silently skips notifications outside its severities or active schedules, and a disabled
	destination sends nothing. Empty severities means every severity, and empty scheduleIds means always
	active. Type "soc" is the SOC notification bell. Any destination's name may be empty. Nothing is sent
	while notifications are turned off for the grid.`
}

func (t *ListDestinationsTool) GetSchema() model.JSONSchema {
	return model.JSONSchema{
		Json: &model.ToolSchema{
			Type:       "object",
			Properties: map[string]model.ToolSchemaProperty{},
		},
	}
}

type listDestinationsResult struct {
	Destinations []*listedDestination `json:"destinations"`
}

type listedDestination struct {
	Id          string   `json:"id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Enabled     bool     `json:"enabled"`
	Severities  []string `json:"severities"`
	ScheduleIds []string `json:"scheduleIds"`
}

func (t *ListDestinationsTool) Execute(ctx context.Context, srv *server.Server, req *model.ToolRequest) (result *model.ToolResponse, err error) {
	logger := log.FromContext(ctx).WithFields(log.Fields{
		"sessionId": req.SessionId,
		"toolUseId": req.ToolUseId,
	})

	// Only those who manage destinations can list them; others send by naming one.
	err = srv.CheckAuthorized(ctx, "read", "config")
	if err != nil {
		logger.WithError(err).Error("user is not authorized to list notification destinations")
		return nil, errors.New("ERROR_PERMISSION_DENIED")
	}

	if !licensing.IsEnabled(licensing.FEAT_NTF) {
		logger.Error("no active license with notifications enabled")
		return nil, errors.New("ERROR_ASSISTANT_NOTIFICATIONS_UNLICENSED")
	}

	if srv.Notifier == nil {
		logger.Error("notifier is not available")
		return nil, errors.New("ERROR_ASSISTANT_NOTIFIER_UNAVAILABLE")
	}

	start := time.Now()
	result = &model.ToolResponse{
		ToolName:       t.GetName(),
		OnBehalfOfUser: ctx.Value(web.ContextKeyRequestorId).(string),
	}

	dests := srv.Notifier.GetDestinations()
	listed := make([]*listedDestination, 0, len(dests))
	for _, id := range slices.Sorted(maps.Keys(dests)) {
		dest := dests[id]
		// Field by field, so params and any future secret field never reach the model.
		listed = append(listed, &listedDestination{
			Id:          id,
			Name:        dest.Name,
			Type:        dest.Type,
			Enabled:     dest.Enabled,
			Severities:  nonNilStrings(dest.Severities),
			ScheduleIds: nonNilStrings(dest.ScheduleIDs),
		})
	}

	result.Result = &listDestinationsResult{Destinations: listed}
	result.TimeToExecute = time.Since(start)

	return result, nil
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
