// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

type EventHandler struct {
	server *Server
}

func RegisterEventRoutes(srv *Server, prefix string) {
	h := &EventHandler{
		server: srv,
	}

	r := chi.NewMux()

	r.Route(prefix, func(r chi.Router) {
		r.Use(Middleware(srv.Host))

		r.Get("/", h.getEvent)
		r.Post("/ack", h.postAck)
	})

	srv.Host.RegisterRouter(prefix, r)
}

func (h *EventHandler) getEvent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	err := r.ParseForm()
	if err != nil {
		Respond(w, r, http.StatusBadRequest, err)
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
		Respond(w, r, http.StatusBadRequest, err)
		return
	}

	results, err := h.server.Eventstore.Search(ctx, criteria)
	if err != nil {
		Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	Respond(w, r, http.StatusOK, results)
}

func (h *EventHandler) postAck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ackCriteria := model.NewEventAckCriteria()

	err := json.NewDecoder(r.Body).Decode(&ackCriteria)
	if err != nil {
		Respond(w, r, http.StatusBadRequest, err)
		return
	}

	results, err := h.server.Eventstore.Acknowledge(ctx, ackCriteria)
	if err != nil {
		Respond(w, r, http.StatusBadRequest, err)
		return
	}

	Respond(w, r, http.StatusOK, results)
}
