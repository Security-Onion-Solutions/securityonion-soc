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
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/google/uuid"
)

const chatLinkLabel = "View chat"

// The approval card shows this input, when a tool declares it, to explain the call.
const approvalMessageParam = "approvalMessage"

// Delegation depth is capped well below this; the bound only guards a corrupt parent chain.
const maxSessionAncestors = 16

func init() {
	t := &SendNotificationTool{}
	knownTools[t.GetName()] = t
}

type SendNotificationTool struct{}

func (t *SendNotificationTool) GetName() string {
	return "send_notification"
}

func (t *SendNotificationTool) GetDescription() string {
	return `Send a notification to the Security Onion operators. The notification appears in the SOC
	notification bell for every user and is delivered to any other configured destination, so use it only
	for a finding a human needs to see: a confirmed or high-confidence detection, a completed investigation
	with an actionable outcome, or a condition requiring operator attention. Do not use it to acknowledge a
	request, report intermediate progress, or repeat something already stated in the chat.
	Write title as a single headline of a few words, and summary as one to three complete sentences that
	stand alone without the chat context: a reader who sees only the notification must understand what
	happened, where, and why it matters. Put identifiers, hostnames, IPs, rule names, and counts in fields
	rather than burying them in prose, and put SOC deep links in links. A link back to this chat is added
	automatically, so do not include one.
	Sending shares this chat, including any sub-agent sessions, with every user who can read shared chats,
	so that recipients can follow the link.
	Sending cannot be undone and a notification cannot be recalled, so send at most one per finding.`
}

func (t *SendNotificationTool) GetSchema() model.JSONSchema {
	return model.JSONSchema{
		Json: &model.ToolSchema{
			Type: "object",
			Properties: map[string]model.ToolSchemaProperty{
				"title": {
					Type:        "string",
					Description: "Short headline for the notification, a few words long",
				},
				"summary": {
					Type:        "string",
					Description: "One to three sentences describing what happened and why it matters, understandable without the chat context",
				},
				"severity": {
					Type:        "string",
					Description: `Operator urgency, one of "info", "low", "medium", "high", "critical". Anything else is treated as "info".`,
					Default:     model.NotificationSeverityInfo,
				},
				"fields": {
					Type:        "object",
					Description: "Optional dict of field:value context such as host, source.ip, rule name, or event count. Values are recorded as text.",
				},
				approvalMessageParam: {
					Type:        "string",
					Description: "Shown to the user when they are asked to approve this call. In one or two sentences, say what notification will be sent and that sending it shares this chat, including any sub-agent sessions, with everyone who can view shared chats.",
				},
				"links": {
					Type:        "object",
					Description: `Optional dict of link label:URL pointing back into SOC (e.g., {"View alert": "/#/alerts?q=_id:abc123"}). A link to this chat is added automatically.`,
				},
			},
			Required: []string{"title", "summary", approvalMessageParam},
		},
	}
}

// Fields and Links are map[string]any even though the payload takes map[string]string:
// a model will happily send {"count": 5}, and under map[string]string that fails the entire
// unmarshal, leaving it with an opaque error that names no key. stringifyValues coerces instead.
type sendNotificationArgs struct {
	Title    string         `json:"title"`
	Summary  string         `json:"summary"`
	Severity string         `json:"severity,omitempty"`
	Fields   map[string]any `json:"fields,omitempty"`
	Links    map[string]any `json:"links,omitempty"`
}

func (t *SendNotificationTool) Execute(ctx context.Context, srv *server.Server, req *model.ToolRequest) (result *model.ToolResponse, err error) {
	logger := log.FromContext(ctx).WithFields(log.Fields{
		"sessionId": req.SessionId,
		"toolUseId": req.ToolUseId,
	})

	logger.WithField("toolParameters", req.Params).Info("running tool for assistant")

	err = srv.CheckAuthorized(ctx, "write", "notifications")
	if err != nil {
		logger.WithError(err).Error("user is not authorized to send notifications")
		return nil, errors.New("ERROR_PERMISSION_DENIED")
	}

	// Two distinct failures: the notify module skips initialization entirely when unlicensed,
	// so it also may simply not be loaded. Neither can be detected from Send's error, which is
	// nil when the subsystem is unlicensed or disabled.
	if !licensing.IsEnabled(licensing.FEAT_NTF) {
		logger.Error("no active license with notifications enabled")
		return nil, errors.New("ERROR_ASSISTANT_NOTIFICATIONS_UNLICENSED")
	}

	if srv.Notifier == nil {
		logger.Error("notifier is not available")
		return nil, errors.New("ERROR_ASSISTANT_NOTIFIER_UNAVAILABLE")
	}

	userId := ctx.Value(web.ContextKeyRequestorId).(string)

	args := &sendNotificationArgs{}
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

	err = json.Unmarshal(req.Params, args)
	if err != nil {
		logger.WithError(err).WithField("toolParams", req.Params).Error("failed to unmarshal tool params")
		return nil, errors.New("ERROR_ASSISTANT_UNMARSHAL_PARAMS")
	}

	result.Parameters = args

	title := strings.TrimSpace(args.Title)
	if title == "" {
		logger.Error("notification title is empty")
		return nil, errors.New("ERROR_ASSISTANT_NOTIFICATION_TITLE_REQUIRED")
	}

	summary := strings.TrimSpace(args.Summary)
	if summary == "" {
		logger.Error("notification summary is empty")
		return nil, errors.New("ERROR_ASSISTANT_NOTIFICATION_SUMMARY_REQUIRED")
	}

	severity, severityNote := normalizeNotificationSeverity(args.Severity)

	// Only the SOC channel back-fills these, so another destination driver would otherwise
	// receive an empty id and a zero time. Owning the id also lets the result reference it.
	payload := &model.NotificationPayload{
		ID:        uuid.New().String(),
		Source:    model.SourceAgentAI,
		Title:     title,
		Summary:   summary,
		Severity:  severity,
		Timestamp: time.Now().UTC(),
		Fields:    stringifyValues(args.Fields),
		Links:     stringifyValues(args.Links),
	}

	sharedNote := ""
	rootSessionId := resolveRootSessionId(ctx, srv, req.SessionId)
	if rootSessionId != "" {
		// Shared before sending so the chat is readable by the time anyone follows the link.
		shared, shareErr := shareSessionTree(ctx, srv, rootSessionId)
		if shareErr != nil {
			logger.WithError(shareErr).WithField("rootSessionId", rootSessionId).Warn("unable to share the chat that sent the notification")
		} else if shared {
			sharedNote = " This chat is now shared so recipients can open it."
		}

		if payload.Links == nil {
			payload.Links = map[string]string{}
		}
		payload.Links[chatLinkLabel] = "/#/assistant/" + rootSessionId
	}

	_, err = srv.Notifier.Send(ctx, payload)
	if err != nil {
		logger.WithError(err).Error("error sending notification")
		return nil, err
	}

	// "Submitted", not "delivered": Send reports no error when the subsystem is disabled.
	result.Result = fmt.Sprintf("Notification %q was submitted with severity %q (id %s).%s%s", title, severity, payload.ID, severityNote, sharedNote)

	return result, nil
}

// resolveRootSessionId walks a delegated sub-agent's session up to the top-level chat,
// which is what a person opens. A failed lookup stops at the last session resolved.
func resolveRootSessionId(ctx context.Context, srv *server.Server, sessionId string) string {
	if sessionId == "" || srv.Assistantstore == nil {
		return sessionId
	}

	current := sessionId
	for range maxSessionAncestors {
		sessions, err := srv.Assistantstore.GetSessions(ctx,
			model.GetSessionsWithSessionId(current),
			model.GetSessionsWithIncludeDeleted(true),
			model.GetSessionsWithMessageMeta(false),
			model.GetSessionsWithAutomationSessions(true))
		if err != nil || len(sessions) == 0 || sessions[0].ParentSessionId == "" {
			return current
		}
		current = sessions[0].ParentSessionId
	}

	return current
}

// shareSessionTree shares the chat and its sub-sessions as the manual share action does,
// skipping the write when they are all shared already. It reports whether anything changed.
func shareSessionTree(ctx context.Context, srv *server.Server, rootSessionId string) (bool, error) {
	if srv.Assistantstore == nil {
		return false, errors.New("assistant store is not available")
	}

	sessions, err := srv.Assistantstore.GetSessions(ctx,
		model.GetSessionsWithSessionId(rootSessionId),
		model.GetSessionsWithAutomationSessions(true),
		model.GetSessionsWithDescendants(true),
		model.GetSessionsWithMessageMeta(false))
	if err != nil {
		return false, err
	}

	needsShare := slices.ContainsFunc(sessions, func(s *model.AssistantSession) bool {
		return !slices.Contains(s.Tags, model.SessionTagShared)
	})
	if !needsShare {
		return false, nil
	}

	err = server.SetSessionTreeShared(ctx, srv.Assistantstore, sessions, true)
	if err != nil {
		return false, err
	}

	return true, nil
}

// normalizeNotificationSeverity maps whatever the model sent onto a known severity, falling
// back to info. An unrecognized value returns a note for the result rather than an error: a
// round trip is too expensive for a cosmetic field.
func normalizeNotificationSeverity(severity string) (string, string) {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case model.NotificationSeverityInfo, "":
		return model.NotificationSeverityInfo, ""
	case model.NotificationSeverityLow:
		return model.NotificationSeverityLow, ""
	case model.NotificationSeverityMedium:
		return model.NotificationSeverityMedium, ""
	case model.NotificationSeverityHigh:
		return model.NotificationSeverityHigh, ""
	case model.NotificationSeverityCritical:
		return model.NotificationSeverityCritical, ""
	}

	// do not remove leading space in second param
	return model.NotificationSeverityInfo, fmt.Sprintf(` The severity %q was not recognized, so %q was used instead.`, severity, model.NotificationSeverityInfo)
}

func stringifyValues(values map[string]any) map[string]string {
	stringified := make(map[string]string, len(values))

	for key, value := range values {
		key = strings.TrimSpace(key)
		if key == "" || value == nil {
			continue
		}

		switch typed := value.(type) {
		case string:
			stringified[key] = typed
		case bool:
			stringified[key] = strconv.FormatBool(typed)
		case float64:
			// 'f' rather than 'g' so a large count stays 1000000 instead of 1e+06.
			stringified[key] = strconv.FormatFloat(typed, 'f', -1, 64)
		default:
			encoded, err := json.Marshal(typed)
			if err != nil {
				continue
			}
			stringified[key] = string(encoded)
		}
	}

	if len(stringified) == 0 {
		return nil
	}

	return stringified
}
