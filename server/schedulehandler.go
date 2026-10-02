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
	"time"

	"github.com/apex/log"
	"github.com/go-chi/chi/v5"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

type ScheduleHandler struct {
	server *Server
}

func NewScheduleHandler(srv *Server) *ScheduleHandler {
	return &ScheduleHandler{
		server: srv,
	}
}

func RegisterScheduleRoutes(srv *Server, r chi.Router, prefix string) {
	h := NewScheduleHandler(srv)

	r.Route(prefix, func(r chi.Router) {
		r.Use(h.schedulesEnabled)

		r.Get("/", h.GetSchedules)
		r.Post("/", h.PostSchedule)
		r.Put("/{id}", h.PutSchedule)
		r.Delete("/{id}", h.DeleteSchedule)
		r.Post("/evaluate", h.PostEvaluate)
	})
}

func (h *ScheduleHandler) schedulesEnabled(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (h.server == nil || h.server.Configstore == nil) && (h.server == nil || h.server.Schedulestore == nil) {
			web.Respond(w, r, http.StatusMethodNotAllowed, errors.New("Config module not enabled"))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (h *ScheduleHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	if err == nil {
		return
	}
	errStr := err.Error()
	if strings.Contains(errStr, "unauthorized") || strings.Contains(errStr, "Missing Authorizer") {
		web.Respond(w, r, http.StatusUnauthorized, err)
	} else if strings.Contains(errStr, "forbidden") || strings.Contains(errStr, "Unauthorized") || strings.Contains(errStr, "not authorized") {
		web.Respond(w, r, http.StatusForbidden, err)
	} else if errors.Is(err, ErrScheduleNotFound) || strings.Contains(errStr, "not found") {
		web.Respond(w, r, http.StatusNotFound, err)
	} else if errors.Is(err, ErrInvalidScheduleID) || errors.Is(err, ErrDuplicateScheduleID) ||
		strings.Contains(errStr, "invalid") || strings.Contains(errStr, "already exists") ||
		strings.Contains(errStr, "cannot") || strings.Contains(errStr, "exceeds") ||
		strings.Contains(errStr, "required") || strings.Contains(errStr, "cycle") ||
		strings.Contains(errStr, "circular") || strings.Contains(errStr, "dependency") ||
		strings.Contains(errStr, "exclude") {
		web.Respond(w, r, http.StatusBadRequest, err)
	} else {
		web.Respond(w, r, http.StatusInternalServerError, err)
	}
}

// @Summary      Get Schedules
// @Description  Retrieves all reusable activation schedules with live computed active states.
// @Tags         Schedules
// @Security     bearer[config/read]
// @Produce      json
// @Success      200  {array}  model.Schedule  "The list of schedules"
// @Failure      400         "License is invalid"
// @Failure      401         "Request was not properly authenticated"
// @Failure      403         "Insufficient permissions for this request"
// @Failure      405         "Configuration module has not been enabled on the server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/schedules [get]
func (h *ScheduleHandler) GetSchedules(w http.ResponseWriter, r *http.Request) {
	if !licensing.IsEnabled(licensing.FEAT_NTF) {
		web.Respond(w, r, http.StatusBadRequest, errors.New("ERROR_LICENSE_INVALID"))
		return
	}

	ctx := r.Context()
	logger := log.FromContext(ctx)

	if h.server == nil || h.server.Schedulestore == nil {
		web.Respond(w, r, http.StatusMethodNotAllowed, errors.New("Config module not enabled"))
		return
	}

	schedules, err := h.server.Schedulestore.GetSchedules(ctx)
	if err != nil {
		logger.WithError(err).Error("failed to load schedules")
		h.respondError(w, r, err)
		return
	}

	web.Respond(w, r, http.StatusOK, schedules)
}

// @Summary      Create Schedule
// @Description  Creates a new reusable activation schedule in the Pillar configuration.
// @Tags         Schedules
// @Security     bearer[config/write]
// @Param        request  body  model.Schedule  true  "The schedule to create"
// @Accept       json
// @Produce      json
// @Success      200         "The schedule was successfully created"
// @Failure      400         "Invalid request body or parameters, or duplicate ID"
// @Failure      401         "Request was not properly authenticated"
// @Failure      403         "Insufficient permissions for this request"
// @Failure      405         "Configuration module has not been enabled on the server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/schedules [post]
func (h *ScheduleHandler) PostSchedule(w http.ResponseWriter, r *http.Request) {
	if !licensing.IsEnabled(licensing.FEAT_NTF) {
		web.Respond(w, r, http.StatusBadRequest, errors.New("ERROR_LICENSE_INVALID"))
		return
	}

	ctx := r.Context()
	logger := log.FromContext(ctx)

	if h.server == nil || h.server.Schedulestore == nil {
		web.Respond(w, r, http.StatusMethodNotAllowed, errors.New("Config module not enabled"))
		return
	}

	var req model.Schedule
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.WithError(err).Error("failed to decode request body")
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	created, err := h.server.Schedulestore.CreateSchedule(ctx, &req)
	if err != nil {
		logger.WithError(err).Error("failed to create schedule")
		h.respondError(w, r, err)
		return
	}

	web.Respond(w, r, http.StatusOK, created)
}

// @Summary      Update Schedule
// @Description  Updates an existing reusable activation schedule in the Pillar configuration.
// @Tags         Schedules
// @Security     bearer[config/write]
// @Param        id       path  string          true  "Schedule ID"
// @Param        request  body  model.Schedule  true  "The schedule data to update"
// @Accept       json
// @Produce      json
// @Success      200         "The schedule was successfully updated"
// @Failure      400         "Invalid request body or parameters"
// @Failure      404         "Schedule not found"
// @Failure      401         "Request was not properly authenticated"
// @Failure      403         "Insufficient permissions for this request"
// @Failure      405         "Configuration module has not been enabled on the server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/schedules/{id} [put]
func (h *ScheduleHandler) PutSchedule(w http.ResponseWriter, r *http.Request) {
	if !licensing.IsEnabled(licensing.FEAT_NTF) {
		web.Respond(w, r, http.StatusBadRequest, errors.New("ERROR_LICENSE_INVALID"))
		return
	}

	ctx := r.Context()
	logger := log.FromContext(ctx)

	id := chi.URLParam(r, "id")

	if h.server == nil || h.server.Schedulestore == nil {
		web.Respond(w, r, http.StatusMethodNotAllowed, errors.New("Config module not enabled"))
		return
	}

	var req model.Schedule
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.WithError(err).Error("failed to decode request body")
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	updated, err := h.server.Schedulestore.UpdateSchedule(ctx, id, &req)
	if err != nil {
		logger.WithError(err).Error("failed to update schedule")
		h.respondError(w, r, err)
		return
	}

	web.Respond(w, r, http.StatusOK, updated)
}

// @Summary      Delete Schedule
// @Description  Removes a reusable activation schedule from the Pillar configuration.
// @Tags         Schedules
// @Security     bearer[config/write]
// @Param        id  path  string  true  "Schedule ID"
// @Produce      json
// @Success      200         "The schedule was successfully deleted"
// @Failure      400         "Invalid parameters"
// @Failure      404         "Schedule not found"
// @Failure      401         "Request was not properly authenticated"
// @Failure      403         "Insufficient permissions for this request"
// @Failure      405         "Configuration module has not been enabled on the server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/schedules/{id} [delete]
func (h *ScheduleHandler) DeleteSchedule(w http.ResponseWriter, r *http.Request) {
	if !licensing.IsEnabled(licensing.FEAT_NTF) {
		web.Respond(w, r, http.StatusBadRequest, errors.New("ERROR_LICENSE_INVALID"))
		return
	}

	ctx := r.Context()
	logger := log.FromContext(ctx)

	id := chi.URLParam(r, "id")

	if h.server == nil || h.server.Schedulestore == nil {
		web.Respond(w, r, http.StatusMethodNotAllowed, errors.New("Config module not enabled"))
		return
	}

	if err := h.server.Schedulestore.DeleteSchedule(ctx, id); err != nil {
		logger.WithError(err).Error("failed to delete schedule")
		h.respondError(w, r, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}

// @Description EvaluateScheduleRequest specifies the schedule and timestamp for evaluation.
type EvaluateScheduleRequest struct {
	// The schedule definition to evaluate
	Schedule model.Schedule `json:"schedule"`
	// RFC3339 formatted timestamp, e.g. "2026-09-14T12:00:00Z". If empty, current UTC time is used.
	Timestamp string `json:"timestamp" example:"2026-09-14T12:00:00Z"`
}

// @Description EvaluateScheduleResponse specifies the resulting active state.
type EvaluateScheduleResponse struct {
	// Indicates whether the schedule is active at the requested timestamp
	Active bool `json:"active" example:"true"`
}

// @Summary      Evaluate Schedule
// @Description  Evaluates a schedule's recurrence definitions against an arbitrary RFC3339 timestamp.
// @Tags         Schedules
// @Security     bearer[config/read]
// @Param        request  body  EvaluateScheduleRequest  true  "The evaluation parameters"
// @Accept       json
// @Produce      json
// @Success      200  {object}  EvaluateScheduleResponse  "The active state result"
// @Failure      400         "Invalid request body or parameters"
// @Failure      401         "Request was not properly authenticated"
// @Failure      403         "Insufficient permissions for this request"
// @Failure      405         "Configuration module has not been enabled on the server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/schedules/evaluate [post]
func (h *ScheduleHandler) PostEvaluate(w http.ResponseWriter, r *http.Request) {
	if !licensing.IsEnabled(licensing.FEAT_NTF) {
		web.Respond(w, r, http.StatusBadRequest, errors.New("ERROR_LICENSE_INVALID"))
		return
	}

	ctx := r.Context()
	logger := log.FromContext(ctx)

	if h.server == nil || h.server.Schedulestore == nil {
		web.Respond(w, r, http.StatusMethodNotAllowed, errors.New("Config module not enabled"))
		return
	}

	var req EvaluateScheduleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.WithError(err).Error("failed to decode request body")
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	evalTime := time.Now().UTC()
	if req.Timestamp != "" {
		parsed, err := time.Parse(time.RFC3339, req.Timestamp)
		if err != nil {
			logger.WithError(err).Error("failed to parse evaluation timestamp")
			web.Respond(w, r, http.StatusBadRequest, errors.New("invalid timestamp format; must be RFC3339"))
			return
		}
		evalTime = parsed.UTC()
	}

	active, err := h.server.Schedulestore.EvaluateSchedule(ctx, &req.Schedule, evalTime)
	if err != nil {
		logger.WithError(err).Error("failed to evaluate schedule")
		h.respondError(w, r, err)
		return
	}

	web.Respond(w, r, http.StatusOK, EvaluateScheduleResponse{Active: active})
}
