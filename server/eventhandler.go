// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

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
		r.Use(h.eventsEnabled)

		r.Get("/", h.getEvent)
		r.Post("/ack", h.postAck)
		r.Put("/{id}/status", h.putEventStatus)
	})
}

func (h *EventHandler) eventsEnabled(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.server.Eventstore == nil {
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

	// Check if simple view is requested
	if r.Form.Get("view") == "simple" {
		simplifiedResults := h.simplifyEventResults(results)
		web.Respond(w, r, http.StatusOK, simplifiedResults)
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
func (h *EventHandler) simplifyEventResults(results *model.EventSearchResults) *model.EventSearchResults {
	simplified := &model.EventSearchResults{
		EventResults: results.EventResults,
		Criteria:     results.Criteria,
		TotalEvents:  results.TotalEvents,
		Events:       make([]*model.EventRecord, len(results.Events)),
		Metrics:      results.Metrics,
	}

	// Extract only essential fields for each event
	for i, event := range results.Events {
		simplifiedEvent := &model.EventRecord{
			Source:    event.Source,
			Time:      event.Time,
			Timestamp: event.Timestamp,
			Id:        event.Id,
			Type:      event.Type,
			Score:     event.Score,
			Payload:   make(map[string]interface{}),
			Sort:      event.Sort,
		}

		// Extract only essential fields from payload
		if event.Payload != nil {
			// Rule information
			if ruleName, exists := event.Payload["rule.name"]; exists {
				simplifiedEvent.Payload["rule.name"] = ruleName
			}
			if ruleUuid, exists := event.Payload["rule.uuid"]; exists {
				simplifiedEvent.Payload["rule.uuid"] = ruleUuid
			}

			// Severity
			if severity, exists := event.Payload["event.severity"]; exists {
				simplifiedEvent.Payload["event.severity"] = severity
			}
			if severityLabel, exists := event.Payload["event.severity_label"]; exists {
				simplifiedEvent.Payload["event.severity_label"] = severityLabel
			}

			// Source and destination
			if srcIP, exists := event.Payload["source.ip"]; exists {
				simplifiedEvent.Payload["source.ip"] = srcIP
			}
			if srcPort, exists := event.Payload["source.port"]; exists {
				simplifiedEvent.Payload["source.port"] = srcPort
			}
			if dstIP, exists := event.Payload["destination.ip"]; exists {
				simplifiedEvent.Payload["destination.ip"] = dstIP
			}
			if dstPort, exists := event.Payload["destination.port"]; exists {
				simplifiedEvent.Payload["destination.port"] = dstPort
			}

			// Module and category
			if module, exists := event.Payload["event.module"]; exists {
				simplifiedEvent.Payload["event.module"] = module
			}
			if category, exists := event.Payload["event.category"]; exists {
				simplifiedEvent.Payload["event.category"] = category
			}

			// Status fields
			if acknowledged, exists := event.Payload["event.acknowledged"]; exists {
				simplifiedEvent.Payload["event.acknowledged"] = acknowledged
			}
			if escalated, exists := event.Payload["event.escalated"]; exists {
				simplifiedEvent.Payload["event.escalated"] = escalated
			}

			// Timestamp
			if timestamp, exists := event.Payload["@timestamp"]; exists {
				simplifiedEvent.Payload["@timestamp"] = timestamp
			}
		}

		simplified.Events[i] = simplifiedEvent
	}

	return simplified
}

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

// @Summary      Update Event Status
// @Description  Updates the status of a specific event
// @Security     bearer[events/write]
// @Tags         Events
// @Param        id   path      string  true  "Event ID"
// @Param        status  body  object  true  "Status update" example({"status": "acknowledged"})
// @Accept       json
// @Produce      json
// @Success      200  {object}  model.EventUpdateResults   "Event successfully updated"
// @Failure      400         "The provided input object or parameters are malformed or invalid"
// @Failure      401         "Request was not properly authenticated"
// @Failure      405         "The event module is not loaded on the server"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /api/events/{id}/status [put]
func (h *EventHandler) putEventStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	eventId := chi.URLParam(r, "id")

	var statusUpdate struct {
		Status string `json:"status"`
	}

	err := json.NewDecoder(r.Body).Decode(&statusUpdate)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	// Validate status
	if statusUpdate.Status != "acknowledged" && statusUpdate.Status != "dismissed" && statusUpdate.Status != "escalated" {
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid status. Must be 'acknowledged', 'dismissed', or 'escalated'"))
		return
	}

	// Create update criteria for this specific event
	updateCriteria := model.NewEventUpdateCriteria()
	updateCriteria.RawQuery = "_id:\"" + eventId + "\""

	// Add the appropriate update script based on status
	switch statusUpdate.Status {
	case "acknowledged":
		updateCriteria.AddUpdateScript("ctx._source['event.acknowledged'] = true")
	case "dismissed":
		updateCriteria.AddUpdateScript("ctx._source['event.dismissed'] = true")
	case "escalated":
		updateCriteria.AddUpdateScript("ctx._source['event.escalated'] = true")
	}

	// Perform the update
	results, err := h.server.Eventstore.Update(ctx, updateCriteria)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, results)
}
