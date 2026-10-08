// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

type AlarmHandler struct {
	server *Server
}

func NewAlarmHandler(srv *Server) *AlarmHandler {
	return &AlarmHandler{
		server: srv,
	}
}

func RegisterAlarmRoutes(srv *Server, r chi.Router, prefix string) {
	h := NewAlarmHandler(srv)

	r.Route(prefix, func(r chi.Router) {
		r.Get("/states", h.GetStates)

		r.Group(func(r chi.Router) {
			r.Use(h.alarmsEnabled)

			r.Get("/", h.GetAlarms)
			r.Get("/metrics", h.GetMetrics)
			r.Get("/{id}", h.GetAlarm)
			r.Post("/", h.PostAlarm)
			r.Put("/{id}", h.PutAlarm)
			r.Delete("/{id}", h.DeleteAlarm)
			r.Post("/evaluate", h.PostEvaluate)
		})
	})
}

func (h *AlarmHandler) alarmsEnabled(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.server == nil || h.server.Alarmstore == nil {
			web.Respond(w, r, http.StatusMethodNotAllowed, errors.New("Alarm module not enabled"))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (h *AlarmHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	if err == nil {
		return
	}
	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "unauthorized") || strings.Contains(errStr, "missing authorizer") {
		web.Respond(w, r, http.StatusUnauthorized, err)
	} else if strings.Contains(errStr, "forbidden") || strings.Contains(errStr, "not authorized") {
		web.Respond(w, r, http.StatusForbidden, err)
	} else if errors.Is(err, ErrAlarmNotFound) || strings.Contains(errStr, "not found") {
		web.Respond(w, r, http.StatusNotFound, err)
	} else if errors.Is(err, ErrInvalidAlarmID) || errors.Is(err, ErrDuplicateAlarmID) ||
		strings.Contains(errStr, "invalid") || strings.Contains(errStr, "already exists") ||
		strings.Contains(errStr, "cannot") || strings.Contains(errStr, "exceeds") ||
		strings.Contains(errStr, "required") || strings.Contains(errStr, "threshold") ||
		strings.Contains(errStr, "number") || strings.Contains(errStr, "boolean") ||
		strings.Contains(errStr, "metric") || strings.Contains(errStr, "operator") ||
		strings.Contains(errStr, "severity") || strings.Contains(errStr, "duration") {
		web.Respond(w, r, http.StatusBadRequest, err)
	} else {
		web.Respond(w, r, http.StatusInternalServerError, err)
	}
}

// @Summary      Get Alarms
// @Description  Retrieves all configured metric alarms.
// @Tags         Alarms
// @Security     bearer[grid/read]
// @Produce      json
// @Success      200  {array}  model.Alarm  "The list of alarms"
// @Failure      401         "Request was not properly authenticated"
// @Failure      403         "Insufficient permissions for this request"
// @Failure      405         "Alarm module has not been enabled on the server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/alarms [get]
func (h *AlarmHandler) GetAlarms(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	alarms, err := h.server.Alarmstore.GetAlarms(ctx)
	if err != nil {
		logger.WithError(err).Error("failed to load alarms")
		h.respondError(w, r, err)
		return
	}

	web.Respond(w, r, http.StatusOK, alarms)
}

// @Summary      Get Alarm Metric Datapoints
// @Description  Retrieves available grid metric datapoint metadata for configuring alarms.
// @Tags         Alarms
// @Security     bearer[grid/read]
// @Produce      json
// @Success      200  {array}  model.AlarmMetricInfo  "The list of available metric datapoints"
// @Failure      401         "Request was not properly authenticated"
// @Failure      403         "Insufficient permissions for this request"
// @Failure      405         "Alarm module has not been enabled on the server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/alarms/metrics [get]
func (h *AlarmHandler) GetMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	metrics, err := h.server.Alarmstore.GetAlarmMetrics(ctx)
	if err != nil {
		logger.WithError(err).Error("failed to load alarm metrics")
		h.respondError(w, r, err)
		return
	}

	web.Respond(w, r, http.StatusOK, metrics)
}

// @Summary      Get Alarm States
// @Description  Retrieves live persisted alarm states across all grid nodes.
// @Tags         Alarms
// @Security     bearer[grid/read]
// @Produce      json
// @Success      200  {array}  model.AlarmState  "The list of alarm states"
// @Failure      401         "Request was not properly authenticated"
// @Failure      403         "Insufficient permissions for this request"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/alarms/states [get]
func (h *AlarmHandler) GetStates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	if h.server == nil || h.server.Alarmstore == nil {
		web.Respond(w, r, http.StatusOK, []*model.AlarmState{})
		return
	}

	states, err := h.server.Alarmstore.GetAlarmStates(ctx)
	if err != nil {
		logger.WithError(err).Error("failed to load alarm states")
		h.respondError(w, r, err)
		return
	}

	web.Respond(w, r, http.StatusOK, states)
}

// @Summary      Get Single Alarm
// @Description  Retrieves a specific metric alarm by ID.
// @Tags         Alarms
// @Security     bearer[grid/read]
// @Param        id   path      string  true  "Alarm ID"
// @Produce      json
// @Success      200  {object}  model.Alarm  "The alarm"
// @Failure      400         "Invalid alarm ID"
// @Failure      404         "Alarm not found"
// @Failure      401         "Request was not properly authenticated"
// @Failure      403         "Insufficient permissions for this request"
// @Failure      405         "Alarm module has not been enabled on the server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/alarms/{id} [get]
func (h *AlarmHandler) GetAlarm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)
	id := chi.URLParam(r, "id")

	alarm, err := h.server.Alarmstore.GetAlarm(ctx, id)
	if err != nil {
		logger.WithError(err).Error("failed to load alarm")
		h.respondError(w, r, err)
		return
	}

	web.Respond(w, r, http.StatusOK, alarm)
}

// @Summary      Create Alarm
// @Description  Creates a new metric alarm.
// @Tags         Alarms
// @Security     bearer[config/write]
// @Param        request  body  model.Alarm  true  "The alarm to create"
// @Accept       json
// @Produce      json
// @Success      200  {object}  model.Alarm  "The created alarm"
// @Failure      400         "Invalid request body or parameters, or duplicate ID"
// @Failure      401         "Request was not properly authenticated"
// @Failure      403         "Insufficient permissions for this request"
// @Failure      405         "Alarm module has not been enabled on the server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/alarms [post]
func (h *AlarmHandler) PostAlarm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	var req model.Alarm
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.WithError(err).Error("failed to decode request body")
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	created, err := h.server.Alarmstore.CreateAlarm(ctx, &req)
	if err != nil {
		logger.WithError(err).Error("failed to create alarm")
		h.respondError(w, r, err)
		return
	}

	web.Respond(w, r, http.StatusOK, created)
}

// @Summary      Update Alarm
// @Description  Updates an existing metric alarm.
// @Tags         Alarms
// @Security     bearer[config/write]
// @Param        id       path  string       true  "Alarm ID"
// @Param        request  body  model.Alarm  true  "The alarm data to update"
// @Accept       json
// @Produce      json
// @Success      200  {object}  model.Alarm  "The updated alarm"
// @Failure      400         "Invalid request body or parameters"
// @Failure      404         "Alarm not found"
// @Failure      401         "Request was not properly authenticated"
// @Failure      403         "Insufficient permissions for this request"
// @Failure      405         "Alarm module has not been enabled on the server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/alarms/{id} [put]
func (h *AlarmHandler) PutAlarm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)
	id := chi.URLParam(r, "id")

	var req model.Alarm
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.WithError(err).Error("failed to decode request body")
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	updated, err := h.server.Alarmstore.UpdateAlarm(ctx, id, &req)
	if err != nil {
		logger.WithError(err).Error("failed to update alarm")
		h.respondError(w, r, err)
		return
	}

	web.Respond(w, r, http.StatusOK, updated)
}

// @Summary      Delete Alarm
// @Description  Deletes an existing metric alarm.
// @Tags         Alarms
// @Security     bearer[config/write]
// @Param        id   path  string  true  "Alarm ID"
// @Produce      json
// @Success      200         "The alarm was successfully deleted"
// @Failure      400         "Invalid alarm ID"
// @Failure      404         "Alarm not found"
// @Failure      401         "Request was not properly authenticated"
// @Failure      403         "Insufficient permissions for this request"
// @Failure      405         "Alarm module has not been enabled on the server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/alarms/{id} [delete]
func (h *AlarmHandler) DeleteAlarm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)
	id := chi.URLParam(r, "id")

	if err := h.server.Alarmstore.DeleteAlarm(ctx, id); err != nil {
		logger.WithError(err).Error("failed to delete alarm")
		h.respondError(w, r, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}

// @Summary      Evaluate Alarms
// @Description  Triggers an immediate evaluation pass of all enabled alarms.
// @Tags         Alarms
// @Security     bearer[config/read]
// @Produce      json
// @Success      200         "Evaluation completed successfully"
// @Failure      401         "Request was not properly authenticated"
// @Failure      403         "Insufficient permissions for this request"
// @Failure      405         "Alarm module has not been enabled on the server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/alarms/evaluate [post]
func (h *AlarmHandler) PostEvaluate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	if err := h.server.CheckAuthorized(ctx, "read", "config"); err != nil {
		logger.WithError(err).Error("unauthorized to evaluate alarms")
		h.respondError(w, r, err)
		return
	}

	if err := h.server.Alarmstore.EvaluateAlarms(ctx); err != nil {
		logger.WithError(err).Error("failed to evaluate alarms")
		h.respondError(w, r, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}
