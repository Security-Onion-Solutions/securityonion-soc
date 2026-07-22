// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/apex/log"
	"github.com/go-chi/chi/v5"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

const EVENTSTORE_HEALTH_TIMEOUT = 30 * time.Second

type EventstoreHandler struct {
	server *Server
}

func RegisterEventstoreRoutes(srv *Server, r chi.Router, prefix string) {
	h := &EventstoreHandler{
		server: srv,
	}

	r.Route(prefix, func(r chi.Router) {
		r.Use(srv.eventstoreEnabled)

		r.Get("/health", h.getHealth)
	})
}

// Rejects requests when no eventstore module is loaded
func (s *Server) eventstoreEnabled(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Eventstore == nil {
			web.Respond(w, r, http.StatusMethodNotAllowed, errors.New("Method not supported"))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// @Summary      Get Eventstore Health
// @Description  Retrieves the live eventstore health report, along with the cluster settings and node listing
// @Description  for support purposes. When the health report indicates a shard availability problem, the unassigned
// @Description  shards are inventoried and an allocation explanation is included for one sampled shard from each
// @Description  group of unassigned shards, along with a digest of the allocation verdict and blocking deciders.
// @Tags         Grid
// @Security     bearer[nodes/read]
// @Produce      json
// @Success      200  {object}  model.EventstoreHealth  "The aggregated eventstore health details"
// @Failure      401            "Request was not properly authenticated"
// @Failure      403            "Insufficient permissions for this request"
// @Failure      500            "Eventstore health report could not be retrieved; review SOC logs"
// @Router       /connect/eventstore/health [get]
func (h *EventstoreHandler) getHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), EVENTSTORE_HEALTH_TIMEOUT)
	defer cancel()

	if err := h.server.CheckAuthorized(ctx, "read", "nodes"); err != nil {
		web.Respond(w, r, http.StatusUnauthorized, err)
		return
	}

	health, err := GetEventstoreHealth(ctx, h.server.Eventstore)
	if err != nil {
		log.FromContext(ctx).WithError(err).Error("unable to retrieve eventstore health report")
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, health)
}
