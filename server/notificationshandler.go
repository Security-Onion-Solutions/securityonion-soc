// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/apex/log"
	"github.com/go-chi/chi/v5"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/web"
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

		r.Get("/", h.GetNotifications)
		r.Put("/{id}/read", h.PutRead)
		r.Put("/{id}/dismiss", h.PutDismiss)
		r.Get("/{id}/audit", h.GetAudit)
	})
}

func (h *NotificationHandler) notificationsEnabled(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.server.Notificationstore == nil {
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
	} else if strings.Contains(errStr, "forbidden") || strings.Contains(errStr, "Unauthorized") {
		web.Respond(w, r, http.StatusForbidden, err)
	} else {
		web.Respond(w, r, http.StatusInternalServerError, err)
	}
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
