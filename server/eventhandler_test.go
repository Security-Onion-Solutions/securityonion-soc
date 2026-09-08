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
	"net/http/httptest"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
)

func recordGetHealth(srv *Server) *httptest.ResponseRecorder {
	h := &EventHandler{server: srv}

	req := httptest.NewRequest("GET", "/events/health", nil)
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestStart, time.Now())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.getHealth(w, req)
	return w
}

func TestGetEventsHealthHandlerNoEventstore(t *testing.T) {
	srv := NewFakeAuthorizedServer(nil)
	srv.Eventstore = nil

	r := chi.NewRouter()
	RegisterEventRoutes(srv, r, "/events")

	req := httptest.NewRequest("GET", "/events/health", nil)
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestId, "test-request")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestGetEventsHealthHandlerUnauthorized(t *testing.T) {
	srv := NewFakeUnauthorizedServer()
	srv.Eventstore = NewFakeEventstore()

	w := recordGetHealth(srv)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestGetEventsHealthHandlerOk(t *testing.T) {
	srv := NewFakeAuthorizedServer(nil)
	store := NewFakeEventstore()
	store.EventsHealth = &model.EventsHealth{
		Status:     "green",
		Indicators: []model.HealthIndicator{{Id: "shards_availability", Status: "green"}},
	}
	srv.Eventstore = store

	w := recordGetHealth(srv)

	assert.Equal(t, http.StatusOK, w.Code)

	var health model.EventsHealth
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &health))
	assert.Equal(t, "green", health.Status)
	if assert.Len(t, health.Indicators, 1) {
		assert.Equal(t, "shards_availability", health.Indicators[0].Id)
	}
	assert.Nil(t, health.UnassignedShards)

	// The store call is bounded by the endpoint's fail-fast deadline
	for _, ctx := range store.InputContexts {
		deadline, ok := ctx.Deadline()
		if assert.True(t, ok) {
			assert.LessOrEqual(t, time.Until(deadline), time.Duration(config.DEFAULT_EVENTS_HEALTH_TIMEOUT_MS)*time.Millisecond)
		}
	}
}

func TestGetEventsHealthHandlerClientAborted(t *testing.T) {
	srv := NewFakeAuthorizedServer(nil)
	store := NewFakeEventstore()
	store.EventsHealthErr = fmt.Errorf("transport: %w", context.Canceled)
	srv.Eventstore = store

	w := recordGetHealth(srv)

	// Not an error: the client aborts health requests when the dialog closes
	assert.NotEqual(t, http.StatusInternalServerError, w.Code)
	assert.Empty(t, w.Body.String())
}

func TestGetEventsHealthHandlerError(t *testing.T) {
	srv := NewFakeAuthorizedServer(nil)
	store := NewFakeEventstore()
	store.EventsHealthErr = errors.New("no master")
	srv.Eventstore = store

	w := recordGetHealth(srv)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
