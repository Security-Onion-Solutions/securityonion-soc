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
	"net/http/httptest"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/tidwall/gjson"
)

func getEventstoreHealth(srv *Server) *httptest.ResponseRecorder {
	h := &EventstoreHandler{server: srv}

	req := httptest.NewRequest("GET", "/eventstore/health", nil)
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestStart, time.Now())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.getHealth(w, req)
	return w
}

func TestGetEventstoreHealthHandlerNoEventstore(t *testing.T) {
	srv := NewFakeAuthorizedServer(nil)
	srv.Eventstore = nil

	r := chi.NewRouter()
	RegisterEventstoreRoutes(srv, r, "/eventstore")

	req := httptest.NewRequest("GET", "/eventstore/health", nil)
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestId, "test-request")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestGetEventstoreHealthHandlerUnauthorized(t *testing.T) {
	srv := NewFakeUnauthorizedServer()
	srv.Eventstore = NewFakeEventstore()

	w := getEventstoreHealth(srv)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestGetEventstoreHealthHandlerOk(t *testing.T) {
	srv := NewFakeAuthorizedServer(nil)
	store := NewFakeEventstore()
	store.HealthReportJson = `{"status":"green","indicators":{"shards_availability":{"status":"green"}}}`
	store.ClusterSettingsJson = `{"persistent":{},"transient":{}}`
	store.NodesJson = `[{"name":"node-1"}]`
	srv.Eventstore = store

	w := getEventstoreHealth(srv)

	assert.Equal(t, http.StatusOK, w.Code)

	var health model.EventstoreHealth
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &health))
	assert.Equal(t, "green", gjson.GetBytes(health.HealthReport, "status").String())
	assert.Nil(t, health.UnassignedShards)

	// Every store call is bounded by the endpoint's fail-fast deadline
	for _, ctx := range store.InputContexts {
		deadline, ok := ctx.Deadline()
		if assert.True(t, ok) {
			assert.LessOrEqual(t, time.Until(deadline), EVENTSTORE_HEALTH_TIMEOUT)
		}
	}
}

func TestGetEventstoreHealthHandlerError(t *testing.T) {
	srv := NewFakeAuthorizedServer(nil)
	store := NewFakeEventstore()
	store.HealthReportErr = errors.New("no master")
	srv.Eventstore = store

	w := getEventstoreHealth(srv)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
