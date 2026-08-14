// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/go-chi/chi/v5"
)

type EventHandler struct {
	server *Server
}

func RegisterEventRoutes(srv *Server, r chi.Router, prefix string) {
	h := &EventHandler{
		server: srv,
	}

	r.Route(prefix, func(r chi.Router) {
		r.Use(srv.eventstoreEnabled)

		r.Get("/", h.getEvent)
		r.Post("/ack", h.postAck)
		r.Get("/health", h.getHealth)
	})
}

func (s *Server) eventstoreEnabled(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Eventstore == nil {
			web.Respond(w, r, http.StatusMethodNotAllowed, errors.New("Method not supported"))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// @Summary      Query Data
// @Description  Given a search query, fetch all matching results, up to the maximum number requested, or the maximum that the backend data server will provide.
// @Description.markdown get_events
// @Security     bearer[events/read]
// @Tags         Query
// @Param        query  query  string  true "User defined search query" example(tags:conn | groupby source.ip destination.ip network.protocol destination.port)
// @Param        range  query  string  true "Date range, in the specified timezone" example(2024/12/03 03:09:31 PM - 2024/12/04 03:09:31 PM)
// @Param        zone  query  string  true "Timezone of the date range" example(America/New_York)
// @Param        format  query  string  true "Date range date format. Use the example, exactly as shown, if not familiar with date formats" example(2006/01/02 3:04:05 PM)
// @Param        metricLimit  query  integer  true "Maximum number of metrics to include in each aggregation" example(10)
// @Param        eventLimit  query  integer  true "Maximum number of events to return" example(100)
// @Produce      json
// @Success      200  {array}  model.EventSearchResults   "Outputs the list of search results"
// @Failure      400         "The provided input object or parameters are malformed or invalid"
// @Failure      401         "Request was not properly authenticated"
// @Failure      405         "The event module is not loaded on the server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/events/ [get]
func (h *EventHandler) getEvent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	err := r.ParseForm()
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	criteria := model.NewEventSearchCriteria()
	err = criteria.Populate(r.Form.Get("query"),
		r.Form.Get("range"),
		r.Form.Get("format"),
		r.Form.Get("zone"),
		r.Form.Get("metricLimit"),
		r.Form.Get("eventLimit"))
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	results, err := h.server.Eventstore.Search(ctx, criteria)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, results)
}

// @Summary      Acknowledge Alerts
// @Description  Acknowledges the alert event(s) matching the given query. Note that this will not remove the event from connected SOC users' Alert screens when the same alert event happens to be also present on their Alert screen. However, if they refresh the Alert screen the alert event will no longer be listed.
// @Security     bearer[events/ack,events/write]
// @Tags         Query
// @Param        request  body  model.EventAckCriteria  true "Ack criteria"
// @Accept       json
// @Produce      json
// @Success      200  {object}  model.EventUpdateResults   "Outputs the list of update results"
// @Failure      400         "The provided input object or parameters are malformed or invalid"
// @Failure      401         "Request was not properly authenticated"
// @Failure      405         "The event module is not loaded on the server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/events/ack [post]
func (h *EventHandler) postAck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ackCriteria := model.NewEventAckCriteria()

	err := json.NewDecoder(r.Body).Decode(&ackCriteria)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	results, err := h.server.Eventstore.Acknowledge(ctx, ackCriteria)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	web.Respond(w, r, http.StatusOK, results)
}

// @Summary      Get Events Health
// @Description  Retrieves a point-in-time diagnostic snapshot of the event datastore: overall status, health
// @Description  indicators, node listing, and non-default settings. When shard availability is degraded, the
// @Description  unassigned shards are inventoried and one sampled shard per group is explained. Diagnosed
// @Description  problems are reported as findings on the indicator they affect, ranked by severity.
// @Tags         Query
// @Security     bearer[nodes/read]
// @Produce      json
// @Success      200  {object}  model.EventsHealth  "The events health snapshot"
// @Failure      401         "Request was not properly authenticated"
// @Failure      403         "Insufficient permissions for this request"
// @Failure      405         "The event module is not loaded on the server"
// @Failure      500         "Events health could not be retrieved; review SOC logs"
// @Router       /connect/events/health [get]
func (h *EventHandler) getHealth(w http.ResponseWriter, r *http.Request) {
	timeoutMs := h.server.Config.EventsHealthTimeoutMs
	// Verify() defaults this; guard for configs that bypassed it
	if timeoutMs <= 0 {
		timeoutMs = config.DEFAULT_EVENTS_HEALTH_TIMEOUT_MS
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()

	// nodes/read, not events/read: this reveals infrastructure, not event data,
	// and gates the same audience as the grid page hosting the link
	if err := h.server.CheckAuthorized(ctx, "read", "nodes"); err != nil {
		web.Respond(w, r, http.StatusUnauthorized, err)
		return
	}

	health, err := h.server.Eventstore.GetEventsHealth(ctx)
	if err != nil {
		// The client aborts in-flight requests when the dialog closes; not a failure
		if errors.Is(err, context.Canceled) {
			log.FromContext(ctx).Debug("events health request canceled by client")
			return
		}

		log.FromContext(ctx).WithError(err).Error("unable to retrieve events health")
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, health)
}
