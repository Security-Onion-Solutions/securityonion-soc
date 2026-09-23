// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

const (
	ConfigSettingNotificationDestinations = "soc.config.server.modules.notification.destinations"
)

type NotificationHandler struct {
	server *Server
}

func NewNotificationHandler(srv *Server) *NotificationHandler {
	return &NotificationHandler{
		server: srv,
	}
}

func RegisterNotificationRoutes(srv *Server, r chi.Router, prefix string) {
	h := NewNotificationHandler(srv)

	r.Route(prefix, func(r chi.Router) {
		r.Use(h.notificationsEnabled)

		r.Get("/destinations", h.GetDestinations)
		r.Post("/destinations", h.PostDestination)
		r.Put("/destinations/{id}", h.PutDestination)
		r.Delete("/destinations/{id}", h.DeleteDestination)
		r.Post("/destinations/{id}/send", h.PostSendNotification)
		r.Post("/send", h.PostSendNotification)

		r.Get("/", h.GetNotifications)
		r.Put("/{id}/read", h.PutRead)
		r.Put("/{id}/dismiss", h.PutDismiss)
		r.Get("/{id}/audit", h.GetAudit)
	})
}

func (h *NotificationHandler) notificationsEnabled(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.server.Notificationstore == nil && h.server.Notifier == nil {
			web.Respond(w, r, http.StatusMethodNotAllowed, errors.New("Notification module not enabled"))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (h *NotificationHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	if err == nil {
		return
	}
	errStr := err.Error()
	if strings.Contains(errStr, "unauthorized") || strings.Contains(errStr, "Missing Authorizer") {
		web.Respond(w, r, http.StatusUnauthorized, err)
	} else if strings.Contains(errStr, "forbidden") || strings.Contains(errStr, "Unauthorized") || strings.Contains(errStr, "not authorized") {
		web.Respond(w, r, http.StatusForbidden, err)
	} else if errors.Is(err, ErrDestinationNotFound) || strings.Contains(errStr, "not found") {
		web.Respond(w, r, http.StatusNotFound, err)
	} else if errors.Is(err, ErrInvalidDestinationID) || errors.Is(err, ErrDuplicateDestinationID) ||
		errors.Is(err, ErrCannotDeleteDefaultDestination) ||
		strings.Contains(errStr, "invalid") || strings.Contains(errStr, "already exists") ||
		strings.Contains(errStr, "cannot delete") || strings.Contains(errStr, "exceeds") ||
		strings.Contains(errStr, "required") {
		web.Respond(w, r, http.StatusBadRequest, err)
	} else {
		web.Respond(w, r, http.StatusInternalServerError, err)
	}
}

// @Summary      Get Notification Destinations
// @Description  Retrieves all configured notification destination channels.
// @Tags         Notifications
// @Security     bearer[config/read]
// @Produce      json
// @Success      200  {array}  model.DestinationConfig  "The list of configured destinations"
// @Failure      400         "License is invalid"
// @Failure      401         "Request was not properly authenticated"
// @Failure      403         "Insufficient permissions for this request"
// @Failure      405         "Notification module has not been enabled on the server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/notifications/destinations [get]
func (h *NotificationHandler) GetDestinations(w http.ResponseWriter, r *http.Request) {
	if !licensing.IsEnabled(licensing.FEAT_NTF) {
		web.Respond(w, r, http.StatusBadRequest, errors.New("ERROR_LICENSE_INVALID"))
		return
	}

	ctx := r.Context()
	logger := log.FromContext(ctx)

	if h.server == nil || h.server.Notifier == nil {
		web.Respond(w, r, http.StatusMethodNotAllowed, errors.New("notification subsystem is not running"))
		return
	}

	destinations, err := h.server.Notifier.ListDestinations(ctx)
	if err != nil {
		logger.WithError(err).Error("failed to load notification destinations")
		h.respondError(w, r, err)
		return
	}

	web.Respond(w, r, http.StatusOK, destinations)
}

// @Summary      Create Notification Destination
// @Description  Creates a new notification destination channel in Pillar configuration.
// @Tags         Notifications
// @Security     bearer[config/write]
// @Param        request  body  model.DestinationConfig  true  "The destination data to create"
// @Accept       json
// @Produce      json
// @Success      200         "The destination was successfully created"
// @Failure      400         "Invalid request body or parameters, or duplicate ID"
// @Failure      401         "Request was not properly authenticated"
// @Failure      403         "Insufficient permissions for this request"
// @Failure      405         "Notification module has not been enabled on the server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/notifications/destinations [post]
func (h *NotificationHandler) PostDestination(w http.ResponseWriter, r *http.Request) {
	if !licensing.IsEnabled(licensing.FEAT_NTF) {
		web.Respond(w, r, http.StatusBadRequest, errors.New("ERROR_LICENSE_INVALID"))
		return
	}

	ctx := r.Context()
	logger := log.FromContext(ctx)

	if h.server == nil || h.server.Notifier == nil {
		web.Respond(w, r, http.StatusMethodNotAllowed, errors.New("notification subsystem is not running"))
		return
	}

	var req model.DestinationConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.WithError(err).Error("failed to decode request body")
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	created, err := h.server.Notifier.CreateDestination(ctx, &req)
	if err != nil {
		logger.WithError(err).Error("failed to create notification destination")
		h.respondError(w, r, err)
		return
	}

	web.Respond(w, r, http.StatusOK, created)
}

// @Summary      Update Notification Destination
// @Description  Updates an existing notification destination channel in Pillar configuration.
// @Tags         Notifications
// @Security     bearer[config/write]
// @Param        id       path  string                   true  "Destination ID"
// @Param        request  body  model.DestinationConfig  true  "The destination data to update"
// @Accept       json
// @Produce      json
// @Success      200         "The destination was successfully updated"
// @Failure      400         "Invalid request body or parameters"
// @Failure      404         "Destination not found"
// @Failure      401         "Request was not properly authenticated"
// @Failure      403         "Insufficient permissions for this request"
// @Failure      405         "Notification module has not been enabled on the server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/notifications/destinations/{id} [put]
func (h *NotificationHandler) PutDestination(w http.ResponseWriter, r *http.Request) {
	if !licensing.IsEnabled(licensing.FEAT_NTF) {
		web.Respond(w, r, http.StatusBadRequest, errors.New("ERROR_LICENSE_INVALID"))
		return
	}

	ctx := r.Context()
	logger := log.FromContext(ctx)

	id := chi.URLParam(r, "id")

	if h.server == nil || h.server.Notifier == nil {
		web.Respond(w, r, http.StatusMethodNotAllowed, errors.New("notification subsystem is not running"))
		return
	}

	var req model.DestinationConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.WithError(err).Error("failed to decode request body")
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	updated, err := h.server.Notifier.UpdateDestination(ctx, id, &req)
	if err != nil {
		logger.WithError(err).Error("failed to update notification destination")
		h.respondError(w, r, err)
		return
	}

	web.Respond(w, r, http.StatusOK, updated)
}

// @Summary      Delete Notification Destination
// @Description  Removes a notification destination channel from Pillar configuration.
// @Tags         Notifications
// @Security     bearer[config/write]
// @Param        id  path  string  true  "Destination ID"
// @Produce      json
// @Success      200         "The destination was successfully deleted"
// @Failure      400         "Invalid parameters"
// @Failure      404         "Destination not found"
// @Failure      401         "Request was not properly authenticated"
// @Failure      403         "Insufficient permissions for this request"
// @Failure      405         "Notification module has not been enabled on the server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/notifications/destinations/{id} [delete]
func (h *NotificationHandler) DeleteDestination(w http.ResponseWriter, r *http.Request) {
	if !licensing.IsEnabled(licensing.FEAT_NTF) {
		web.Respond(w, r, http.StatusBadRequest, errors.New("ERROR_LICENSE_INVALID"))
		return
	}

	ctx := r.Context()
	logger := log.FromContext(ctx)

	id := chi.URLParam(r, "id")

	if h.server == nil || h.server.Notifier == nil {
		web.Respond(w, r, http.StatusMethodNotAllowed, errors.New("notification subsystem is not running"))
		return
	}

	if err := h.server.Notifier.DeleteDestination(ctx, id); err != nil {
		logger.WithError(err).Error("failed to delete notification destination")
		h.respondError(w, r, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}

// @Description SendNotificationResponse specifies the number of destinations that delivered the notification.
type SendNotificationResponse struct {
	// The number of destinations that actually sent the notification.
	Count int `json:"count" example:"1"`
}

// @Summary      Send Notification
// @Description  Dispatches a test or ad-hoc notification payload. When a destination ID is provided in the route, the notification is dispatched specifically to that destination. When omitted, standard notification routing is used across all configured destinations.
// @Tags         Notifications
// @Security     bearer[notifications/write]
// @Param        id              path   string  false  "Destination ID"
// @Param        targeted        query  bool    false  "Whether to send a targeted notification to the current user"
// @Param        title           query  string  false  "Notification title"
// @Param        summary         query  string  false  "Notification summary"
// @Param        severity        query  string  false  "Notification severity"
// @Param        bypassSchedules query  bool    false  "Whether to bypass destination activation schedules"
// @Produce      json
// @Success      200  {object}   SendNotificationResponse "The notification dispatch result"
// @Failure      400         "Title is missing, input exceeds maximum length, or invalid configuration"
// @Failure      404         "Destination not found"
// @Failure      401         "Request was not properly authenticated"
// @Failure      403         "Insufficient permissions for this request"
// @Failure      405         "Notification module has not been enabled on the server"
// @Failure      500         "Failed to send notification via channel driver"
// @Router       /connect/notifications/send [post]
func (h *NotificationHandler) PostSendNotification(w http.ResponseWriter, r *http.Request) {
	if !licensing.IsEnabled(licensing.FEAT_NTF) {
		web.Respond(w, r, http.StatusBadRequest, errors.New("ERROR_LICENSE_INVALID"))
		return
	}

	ctx := r.Context()
	logger := log.FromContext(ctx)

	if err := h.server.CheckAuthorized(ctx, "write", "notifications"); err != nil {
		h.respondError(w, r, err)
		return
	}

	if h.server == nil || h.server.Notifier == nil {
		web.Respond(w, r, http.StatusMethodNotAllowed, errors.New("notification subsystem is not running"))
		return
	}

	id := chi.URLParam(r, "id")
	if id != "" && !model.IsValidDestinationID(id) {
		web.Respond(w, r, http.StatusBadRequest, errors.New("invalid destination ID"))
		return
	}

	var req struct {
		Title           string   `json:"title"`
		Summary         string   `json:"summary"`
		Severity        string   `json:"severity"`
		Recipients      []string `json:"recipients"`
		BypassSchedules bool     `json:"bypassSchedules"`
	}

	if r.Body != nil && r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.WithError(err).Error("failed to decode request body")
			web.Respond(w, r, http.StatusBadRequest, err)
			return
		}
	}

	if req.Title == "" {
		req.Title = r.URL.Query().Get("title")
	}
	if req.Summary == "" {
		req.Summary = r.URL.Query().Get("summary")
	}
	if req.Severity == "" {
		req.Severity = r.URL.Query().Get("severity")
	}
	if !req.BypassSchedules && r.URL.Query().Get("bypassSchedules") == "true" {
		req.BypassSchedules = true
	}
	if len(req.Recipients) == 0 {
		if r.URL.Query().Get("targeted") == "true" || r.URL.Query().Get("withRecipients") == "true" {
			if reqId, ok := ctx.Value(web.ContextKeyRequestorId).(string); ok && reqId != "" {
				req.Recipients = []string{reqId}
			} else if u, ok := ctx.Value(web.ContextKeyRunAsUsername).(string); ok && u != "" {
				req.Recipients = []string{u}
			}
		} else if rawRecipients := r.URL.Query()["recipients"]; len(rawRecipients) > 0 {
			req.Recipients = rawRecipients
		}
	}

	title := strings.TrimSpace(req.Title)
	if title == "" {
		web.Respond(w, r, http.StatusBadRequest, errors.New("title is required"))
		return
	}
	if len(title) > 255 {
		web.Respond(w, r, http.StatusBadRequest, errors.New("title exceeds maximum allowed length"))
		return
	}

	summary := strings.TrimSpace(req.Summary)
	if len(summary) > 4000 {
		web.Respond(w, r, http.StatusBadRequest, errors.New("summary exceeds maximum allowed length"))
		return
	}

	severity := strings.ToLower(strings.TrimSpace(req.Severity))
	if severity == "" {
		severity = model.NotificationSeverityInfo
	}
	switch severity {
	case model.NotificationSeverityInfo, model.NotificationSeverityLow, model.NotificationSeverityMedium, model.NotificationSeverityHigh, model.NotificationSeverityCritical:
	default:
		web.Respond(w, r, http.StatusBadRequest, errors.New("invalid severity"))
		return
	}

	payload := &model.NotificationPayload{
		ID:              uuid.NewString(),
		Source:          model.SourceClient,
		Title:           title,
		Summary:         summary,
		Severity:        severity,
		Timestamp:       time.Now().UTC(),
		Recipients:      req.Recipients,
		BypassSchedules: req.BypassSchedules,
	}

	var count int
	var sendErr error
	if id != "" {
		count, sendErr = h.server.Notifier.Send(ctx, payload, id)
	} else {
		count, sendErr = h.server.Notifier.Send(ctx, payload)
	}

	if sendErr != nil {
		logger.WithError(sendErr).WithField("destinationId", id).Error("failed to dispatch notification")
		web.Respond(w, r, http.StatusInternalServerError, fmt.Errorf("notification delivery failed: %w", sendErr))
		return
	}

	web.Respond(w, r, http.StatusOK, SendNotificationResponse{Count: count})
}

// @Summary      Get Notifications
// @Description  Retrieves notifications for the current user, optionally filtered.
// @Tags         Notifications
// @Security     bearer[notifications/read]
// @Param        filter  query  string  false  "Filter parameter (all, unread, dismissed)"
// @Produce      json
// @Success      200  {array}  model.NotificationRecord  "The list of notifications"
// @Failure      400         "License is invalid"
// @Failure      401         "Request was not properly authenticated"
// @Failure      403         "Insufficient permissions for this request"
// @Failure      405         "Notification module has not been enabled on the server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/notifications [get]
func (h *NotificationHandler) GetNotifications(w http.ResponseWriter, r *http.Request) {
	if !licensing.IsEnabled(licensing.FEAT_NTF) {
		web.Respond(w, r, http.StatusBadRequest, errors.New("ERROR_LICENSE_INVALID"))
		return
	}

	ctx := r.Context()
	logger := log.FromContext(ctx)

	filter := r.URL.Query().Get("filter")

	notifications, err := h.server.Notificationstore.GetNotifications(ctx, filter)
	if err != nil {
		logger.WithError(err).Error("failed to get notifications")
		h.respondError(w, r, err)
		return
	}

	web.Respond(w, r, http.StatusOK, notifications)
}

// @Description ToggleReadRequest specifies the desired read state for a notification.
type ToggleReadRequest struct {
	// Indicates whether the notification should be marked as read.
	IsRead bool `json:"isRead" example:"true"`
}

// @Summary      Toggle Read Notification
// @Description  Marks a notification as read or unread for the current user.
// @Tags         Notifications
// @Security     bearer[notifications/write]
// @Param        id       path  string             true  "Notification ID" example(notif-1)
// @Param        request  body  ToggleReadRequest  true  "Payload to toggle read"
// @Accept       json
// @Produce      json
// @Success      200         "The notification read state was successfully updated"
// @Failure      400         "Invalid request body or parameters"
// @Failure      401         "Request was not properly authenticated"
// @Failure      403         "Insufficient permissions for this request"
// @Failure      405         "Notification module has not been enabled on the server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/notifications/{id}/read [put]
func (h *NotificationHandler) PutRead(w http.ResponseWriter, r *http.Request) {
	if !licensing.IsEnabled(licensing.FEAT_NTF) {
		web.Respond(w, r, http.StatusBadRequest, errors.New("ERROR_LICENSE_INVALID"))
		return
	}

	ctx := r.Context()
	logger := log.FromContext(ctx)

	id := chi.URLParam(r, "id")
	if id == "" {
		web.Respond(w, r, http.StatusBadRequest, errors.New("missing notification id"))
		return
	}

	var req ToggleReadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.WithError(err).Error("failed to decode request body")
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	err := h.server.Notificationstore.SetRead(ctx, id, req.IsRead)
	if err != nil {
		logger.WithError(err).Error("failed to update read state")
		h.respondError(w, r, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}

// @Description ToggleDismissRequest specifies the desired dismissal state for a notification.
type ToggleDismissRequest struct {
	// Indicates whether the notification should be dismissed.
	IsDismissed bool `json:"isDismissed" example:"true"`
}

// @Summary      Toggle Dismiss Notification
// @Description  Marks a notification as dismissed or active for the current user.
// @Tags         Notifications
// @Security     bearer[notifications/write]
// @Param        id       path  string                true  "Notification ID" example(notif-1)
// @Param        request  body  ToggleDismissRequest  true  "Payload to toggle dismiss"
// @Accept       json
// @Produce      json
// @Success      200         "The notification dismissal state was successfully updated"
// @Failure      400         "Invalid request body or parameters"
// @Failure      401         "Request was not properly authenticated"
// @Failure      403         "Insufficient permissions for this request"
// @Failure      405         "Notification module has not been enabled on the server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/notifications/{id}/dismiss [put]
func (h *NotificationHandler) PutDismiss(w http.ResponseWriter, r *http.Request) {
	if !licensing.IsEnabled(licensing.FEAT_NTF) {
		web.Respond(w, r, http.StatusBadRequest, errors.New("ERROR_LICENSE_INVALID"))
		return
	}

	ctx := r.Context()
	logger := log.FromContext(ctx)

	id := chi.URLParam(r, "id")
	if id == "" {
		web.Respond(w, r, http.StatusBadRequest, errors.New("missing notification id"))
		return
	}

	var req ToggleDismissRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.WithError(err).Error("failed to decode request body")
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	err := h.server.Notificationstore.SetDismissed(ctx, id, req.IsDismissed)
	if err != nil {
		logger.WithError(err).Error("failed to update dismiss state")
		h.respondError(w, r, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}

// @Summary      Get Notification Audit Logs
// @Description  Retrieves team user state logs (view/dismiss) for a specific notification.
// @Tags         Notifications
// @Security     bearer[notifications/read_all]
// @Param        id  path  string  true  "Notification ID" example(notif-1)
// @Produce      json
// @Success      200  {array}  model.NotificationAuditEntry  "The list of notification user audit records"
// @Failure      400         "Invalid parameters"
// @Failure      401         "Request was not properly authenticated"
// @Failure      403         "Insufficient permissions for this request"
// @Failure      405         "Notification module has not been enabled on the server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/notifications/{id}/audit [get]
func (h *NotificationHandler) GetAudit(w http.ResponseWriter, r *http.Request) {
	if !licensing.IsEnabled(licensing.FEAT_NTF) {
		web.Respond(w, r, http.StatusBadRequest, errors.New("ERROR_LICENSE_INVALID"))
		return
	}

	ctx := r.Context()
	logger := log.FromContext(ctx)

	id := chi.URLParam(r, "id")
	if id == "" {
		web.Respond(w, r, http.StatusBadRequest, errors.New("missing notification id"))
		return
	}

	auditList, err := h.server.Notificationstore.GetAuditLogs(ctx, id)
	if err != nil {
		logger.WithError(err).Error("failed to query notification audit logs")
		h.respondError(w, r, err)
		return
	}

	web.Respond(w, r, http.StatusOK, auditList)
}
