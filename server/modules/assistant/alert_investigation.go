// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
)

const alertInvestigationType = "alert_investigation"

// FindEventBySocId quotes the id into its query, so restrict it to id characters.
var cloneAlertIdPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func (ac *AssistantCoordinator) AttachInvestigation(ctx context.Context, socId string, sessionId string) error {
	err := ac.updateAlertInvestigation(ctx, socId, sessionId, false)
	if err != nil {
		log.FromContext(ctx).WithError(err).WithFields(log.Fields{
			"entityType": alertInvestigationType,
			"entityId":   socId,
		}).Warn("unable to mark alert as investigated")
	}

	return err
}

func (ac *AssistantCoordinator) DetachInvestigation(ctx context.Context, socId string, sessionId string) error {
	return ac.updateAlertInvestigation(ctx, socId, sessionId, true)
}

func (ac *AssistantCoordinator) updateAlertInvestigation(ctx context.Context, socId string, sessionId string, isDelete bool) error {
	logger := log.FromContext(ctx).WithFields(log.Fields{
		"socId":     socId,
		"sessionId": sessionId,
	})

	if err := ac.srv.CheckAuthorized(ctx, "write", "events"); err != nil {
		return err
	}

	if ac.srv.Eventstore == nil {
		return fmt.Errorf("eventstore is not available")
	}

	updater, ok := ac.srv.Eventstore.(server.EventstoreUpdater)
	if !ok {
		return fmt.Errorf("eventstore does not support investigation updates")
	}

	if isDelete {
		logger.Info("Clearing investigation_session_id from alert")
	} else {
		logger.Info("Marking alert as investigated")
	}

	userId, _ := ctx.Value(web.ContextKeyRequestorId).(string)
	updateCriteria := model.NewEventUpdateCriteria()
	updater.AddInvestigationUpdateScripts(updateCriteria, time.Now(), userId, isDelete, sessionId)

	updateCriteria.ParsedQuery = model.NewQuery()
	searchSegment := model.NewSearchSegmentEmpty()
	searchSegment.AddFilter("soc_id", socId, false, true, false)
	updateCriteria.ParsedQuery.AddSegment(searchSegment)
	updateCriteria.Asynchronous = false

	results, err := ac.srv.Eventstore.Update(ctx, updateCriteria)
	if err != nil {
		logger.WithError(err).Error("unable to update alert investigation")
		return err
	}

	if !isDelete && results.UpdatedCount == 0 && results.UnchangedCount == 0 {
		logger.Error("update made no changes")
		return fmt.Errorf("no alert found with soc_id: %s", socId)
	}

	logger.WithFields(log.Fields{
		"updatedCount":   results.UpdatedCount,
		"unchangedCount": results.UnchangedCount,
	}).Info("Successfully updated alert investigation")

	return nil
}

func (ac *AssistantCoordinator) DetachSessionInvestigation(ctx context.Context, sessionId string) error {
	logger := log.FromContext(ctx).WithField("sessionId", sessionId)

	// The store silently no-ops deleting others' sessions; refuse here so their alert link survives.
	userId, _ := ctx.Value(web.ContextKeyRequestorId).(string)

	owned, exists, _, _, err := ac.srv.Assistantstore.DoesUserOwnSession(ctx, userId, sessionId)
	if err != nil {
		return err
	}

	if !exists {
		return server.ErrSessionNotFound
	}

	if !owned {
		return server.ErrSessionAccessDenied
	}

	sessions, err := ac.srv.Assistantstore.GetSessions(ctx, model.GetSessionsWithSessionId(sessionId))
	if err != nil {
		logger.WithError(err).Error("unable to retrieve session before deletion")
		return nil
	}

	if len(sessions) > 0 && sessions[0].Type == alertInvestigationType && sessions[0].EntityId != "" {
		err = ac.DetachInvestigation(ctx, sessions[0].EntityId, sessionId)
		if err != nil {
			// Deleting the session proceeds regardless.
			logger.WithError(err).WithField("entityId", sessions[0].EntityId).Warn("unable to clear investigation_session_id from alert")
		}
	}

	return nil
}

func (ac *AssistantCoordinator) CloneSessionOntoAlert(ctx context.Context, sessionId string, socId string) (*model.AssistantSession, error) {
	// Validate before copying so a refusal leaves nothing behind.
	if err := ac.validateCloneAlert(ctx, socId, sessionId); err != nil {
		return nil, err
	}

	clone, err := ac.srv.Assistantstore.CloneSession(ctx, sessionId, alertInvestigationType, socId)
	if err != nil {
		return nil, err
	}

	// The copy stands even if the alert can't be updated; AttachInvestigation logs why.
	_ = ac.AttachInvestigation(ctx, socId, clone.SessionId)

	return clone, nil
}

// validateCloneAlert requires the alert to already reference the session, so unrelated
// sessions cannot be attached to arbitrary alerts.
func (ac *AssistantCoordinator) validateCloneAlert(ctx context.Context, socId string, sessionId string) error {
	if err := ac.srv.CheckAuthorized(ctx, "write", "events"); err != nil {
		return err
	}

	if !cloneAlertIdPattern.MatchString(socId) {
		return server.ErrSessionNotOnAlert
	}

	if ac.srv.Eventstore == nil {
		return fmt.Errorf("eventstore is not available")
	}

	alert, err := server.FindEventBySocId(ctx, ac.srv.Eventstore, socId, time.Time{})
	if err != nil {
		return err
	}

	// The lookup also matches log.id.uid and event.id; the stamp uses soc_id only.
	if alert == nil || alert.Id != socId {
		return server.ErrSessionNotOnAlert
	}

	fields := []string{"event.investigation_session_id"}
	if updater, ok := ac.srv.Assistantstore.(server.AlertTriageUpdater); ok {
		fields = append(fields, model.AlertTriageFieldSessionId(updater.AlertTriageSchemaPrefix()))
	}

	for _, field := range fields {
		if slices.Contains(payloadStrings(alert.Payload, field), sessionId) {
			return nil
		}
	}

	return server.ErrSessionNotOnAlert
}
