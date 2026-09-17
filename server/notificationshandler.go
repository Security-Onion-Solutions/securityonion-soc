// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
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
		r.Post("/destinations/{id}/test", h.PostTestDestination)

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
	} else if strings.Contains(errStr, "forbidden") || strings.Contains(errStr, "Unauthorized") {
		web.Respond(w, r, http.StatusForbidden, err)
	} else {
		web.Respond(w, r, http.StatusInternalServerError, err)
	}
}

func unmarshalDestinations(val string) (map[string]model.DestinationConfig, error) {
	val = strings.TrimSpace(val)
	if val == "" {
		return make(map[string]model.DestinationConfig), nil
	}

	// 1. Try standard JSON map format
	if strings.HasPrefix(val, "{") {
		var dests map[string]model.DestinationConfig
		if err := json.Unmarshal([]byte(val), &dests); err == nil {
			for k, v := range dests {
				if v.ID == "" {
					v.ID = k
				}
				dests[k] = v
			}
			return dests, nil
		}
	}

	// 2. Try JSON array format
	if strings.HasPrefix(val, "[") {
		var slice []model.DestinationConfig
		if err := json.Unmarshal([]byte(val), &slice); err == nil {
			dests := make(map[string]model.DestinationConfig, len(slice))
			for _, item := range slice {
				id := item.ID
				if id == "" {
					id = uuid.NewString()
					item.ID = id
				}
				dests[id] = item
			}
			return dests, nil
		}
	}

	// 3. Try newline-delimited JSON objects
	lines := strings.Split(val, "\n")
	dests := make(map[string]model.DestinationConfig)
	allLinesParsed := true
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var item model.DestinationConfig
		if err := json.Unmarshal([]byte(line), &item); err == nil {
			id := item.ID
			if id == "" {
				id = uuid.NewString()
				item.ID = id
			}
			dests[id] = item
		} else {
			allLinesParsed = false
			break
		}
	}
	if allLinesParsed && len(dests) > 0 {
		return dests, nil
	}

	return nil, errors.New("unable to parse destination configuration")
}

func (h *NotificationHandler) loadDestinations(ctx context.Context) (map[string]model.DestinationConfig, error) {
	if h.server == nil || h.server.Configstore == nil {
		if h.server != nil && h.server.Notifier != nil {
			return h.server.Notifier.GetDestinations(), nil
		}
		return model.DefaultDestinationsMap(), nil
	}

	setting, err := h.server.Configstore.GetSetting(ctx, ConfigSettingNotificationDestinations)
	if err != nil {
		return nil, err
	}
	if setting == nil || strings.TrimSpace(setting.Value) == "" {
		if h.server.Notifier != nil {
			dests := h.server.Notifier.GetDestinations()
			if len(dests) > 0 {
				return dests, nil
			}
		}
		return model.DefaultDestinationsMap(), nil
	}

	return unmarshalDestinations(setting.Value)
}

func (h *NotificationHandler) saveDestinations(ctx context.Context, dests map[string]model.DestinationConfig) error {
	valBytes, err := json.Marshal(dests)
	if err != nil {
		return err
	}
	if h.server != nil && h.server.Configstore != nil {
		setting := &model.Setting{
			Id:    ConfigSettingNotificationDestinations,
			Value: string(valBytes),
		}
		if err := h.server.Configstore.UpdateSetting(ctx, setting, false); err != nil {
			return err
		}
	}
	return nil
}

// @Summary      Get Notification Destinations
// @Description  Retrieves all configured notification destination channels.
// @Tags         Notifications
// @Security     bearer[notifications/read]
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

	if err := h.server.CheckAuthorized(ctx, "read", "notifications"); err != nil {
		h.respondError(w, r, err)
		return
	}

	destsMap, err := h.loadDestinations(ctx)
	if err != nil {
		logger.WithError(err).Error("failed to load notification destinations")
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	result := make([]model.DestinationConfig, 0, len(destsMap))
	for id, dest := range destsMap {
		if dest.ID == "" {
			dest.ID = id
		}
		result = append(result, dest)
	}

	sort.Slice(result, func(i, j int) bool {
		return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
	})

	web.Respond(w, r, http.StatusOK, result)
}

// @Summary      Create Notification Destination
// @Description  Creates a new notification destination channel in Pillar configuration.
// @Tags         Notifications
// @Security     bearer[notifications/write]
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

	if err := h.server.CheckAuthorized(ctx, "write", "notifications"); err != nil {
		h.respondError(w, r, err)
		return
	}

	var req model.DestinationConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.WithError(err).Error("failed to decode request body")
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	if err := model.ValidateDestinationName(req.Name); err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	if strings.TrimSpace(req.Type) == "" {
		req.Type = model.ChannelTypeSOC
	}

	if req.ID == "" {
		req.ID = uuid.NewString()
	} else if !model.IsValidDestinationID(req.ID) {
		web.Respond(w, r, http.StatusBadRequest, errors.New("invalid destination ID"))
		return
	}

	if h.server != nil && h.server.Notifier != nil {
		if ch, found := h.server.Notifier.GetChannel(req.Type); found {
			if err := ch.ValidateConfig(req.Params); err != nil {
				web.Respond(w, r, http.StatusBadRequest, fmt.Errorf("invalid channel parameters: %w", err))
				return
			}
		}
	}

	destsMap, err := h.loadDestinations(ctx)
	if err != nil {
		logger.WithError(err).Error("failed to load notification destinations")
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	if _, exists := destsMap[req.ID]; exists {
		web.Respond(w, r, http.StatusBadRequest, errors.New("destination with this ID already exists"))
		return
	}

	destsMap[req.ID] = req
	if err := h.saveDestinations(ctx, destsMap); err != nil {
		logger.WithError(err).Error("failed to save notification destinations")
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, req)
}

// @Summary      Update Notification Destination
// @Description  Updates an existing notification destination channel in Pillar configuration.
// @Tags         Notifications
// @Security     bearer[notifications/write]
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
	if !model.IsValidDestinationID(id) {
		web.Respond(w, r, http.StatusBadRequest, errors.New("invalid destination ID"))
		return
	}

	if err := h.server.CheckAuthorized(ctx, "write", "notifications"); err != nil {
		h.respondError(w, r, err)
		return
	}

	var req model.DestinationConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.WithError(err).Error("failed to decode request body")
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	if err := model.ValidateDestinationName(req.Name); err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	if strings.TrimSpace(req.Type) == "" {
		req.Type = model.ChannelTypeSOC
	}

	req.ID = id

	if h.server != nil && h.server.Notifier != nil {
		if ch, found := h.server.Notifier.GetChannel(req.Type); found {
			if err := ch.ValidateConfig(req.Params); err != nil {
				web.Respond(w, r, http.StatusBadRequest, fmt.Errorf("invalid channel parameters: %w", err))
				return
			}
		}
	}

	destsMap, err := h.loadDestinations(ctx)
	if err != nil {
		logger.WithError(err).Error("failed to load notification destinations")
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	if _, exists := destsMap[id]; !exists {
		web.Respond(w, r, http.StatusNotFound, errors.New("destination not found"))
		return
	}

	destsMap[id] = req
	if err := h.saveDestinations(ctx, destsMap); err != nil {
		logger.WithError(err).Error("failed to save notification destinations")
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, req)
}

// @Summary      Delete Notification Destination
// @Description  Removes a notification destination channel from Pillar configuration.
// @Tags         Notifications
// @Security     bearer[notifications/write]
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
	if !model.IsValidDestinationID(id) {
		web.Respond(w, r, http.StatusBadRequest, errors.New("invalid destination ID"))
		return
	}

	if id == model.DefaultDestinationSOCBell {
		web.Respond(w, r, http.StatusBadRequest, errors.New("cannot delete default notification destination"))
		return
	}

	if err := h.server.CheckAuthorized(ctx, "write", "notifications"); err != nil {
		h.respondError(w, r, err)
		return
	}

	destsMap, err := h.loadDestinations(ctx)
	if err != nil {
		logger.WithError(err).Error("failed to load notification destinations")
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	if _, exists := destsMap[id]; !exists {
		web.Respond(w, r, http.StatusNotFound, errors.New("destination not found"))
		return
	}

	delete(destsMap, id)
	if err := h.saveDestinations(ctx, destsMap); err != nil {
		logger.WithError(err).Error("failed to save notification destinations")
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}

// @Summary      Test Notification Destination
// @Description  Dispatches a test notification payload directly to the specified destination to verify connectivity and driver configuration.
// @Tags         Notifications
// @Security     bearer[notifications/write]
// @Param        id  path  string  true  "Destination ID"
// @Produce      json
// @Success      200         "The test notification was successfully sent"
// @Failure      400         "Channel driver not available or invalid configuration"
// @Failure      404         "Destination not found"
// @Failure      401         "Request was not properly authenticated"
// @Failure      403         "Insufficient permissions for this request"
// @Failure      405         "Notification module has not been enabled on the server"
// @Failure      500         "Failed to send test notification via channel driver"
// @Router       /connect/notifications/destinations/{id}/test [post]
func (h *NotificationHandler) PostTestDestination(w http.ResponseWriter, r *http.Request) {
	if !licensing.IsEnabled(licensing.FEAT_NTF) {
		web.Respond(w, r, http.StatusBadRequest, errors.New("ERROR_LICENSE_INVALID"))
		return
	}

	ctx := r.Context()
	logger := log.FromContext(ctx)

	id := chi.URLParam(r, "id")
	if !model.IsValidDestinationID(id) {
		web.Respond(w, r, http.StatusBadRequest, errors.New("invalid destination ID"))
		return
	}

	if err := h.server.CheckAuthorized(ctx, "write", "notifications"); err != nil {
		h.respondError(w, r, err)
		return
	}

	destsMap, err := h.loadDestinations(ctx)
	if err != nil {
		logger.WithError(err).Error("failed to load notification destinations")
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	destCfg, exists := destsMap[id]
	if !exists {
		web.Respond(w, r, http.StatusNotFound, errors.New("destination not found"))
		return
	}

	if h.server == nil || h.server.Notifier == nil {
		web.Respond(w, r, http.StatusMethodNotAllowed, errors.New("notification subsystem is not running"))
		return
	}

	channel, found := h.server.Notifier.GetChannel(destCfg.Type)
	if !found {
		web.Respond(w, r, http.StatusBadRequest, fmt.Errorf("channel driver '%s' not registered", destCfg.Type))
		return
	}

	if err := channel.ValidateConfig(destCfg.Params); err != nil {
		web.Respond(w, r, http.StatusBadRequest, fmt.Errorf("invalid channel configuration: %w", err))
		return
	}

	destName := destCfg.Name
	if destName == "" {
		destName = destCfg.ID
	}

	testPayload := &model.NotificationPayload{
		ID:        uuid.NewString(),
		Source:    model.SourceMetric,
		Title:     "Test: " + destName,
		Summary:   "This is a test notification dispatched to verify destination connectivity.",
		Severity:  model.NotificationSeverityInfo,
		Timestamp: time.Now().UTC(),
	}

	if err := channel.Send(ctx, destCfg.Params, testPayload); err != nil {
		logger.WithError(err).WithField("destinationId", id).Error("failed to dispatch test notification")
		web.Respond(w, r, http.StatusInternalServerError, fmt.Errorf("test notification delivery failed: %w", err))
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
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
