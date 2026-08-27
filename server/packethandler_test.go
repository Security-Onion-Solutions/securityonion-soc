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

	"github.com/go-chi/chi/v5"
	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

func newPacketTestRequest(method, target string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestStart, time.Now())
	return req.WithContext(ctx)
}

func TestPacketHandler_GetPackets_SuccessWithoutErrors(t *testing.T) {
	fakeDs := NewFakeDatastore()
	fakeDs.packets = []*model.Packet{
		{Number: 0, Type: "TCP"},
		{Number: 1, Type: "UDP"},
	}
	fakeDs.HasErrors = false

	srv := &Server{
		Config:    &config.ServerConfig{MaxPacketCount: 5000},
		Datastore: fakeDs,
	}

	r := chi.NewRouter()
	RegisterPacketRoutes(srv, r, "/packets")

	req := newPacketTestRequest("GET", "/packets/1004?offset=10&count=50&unwrap=true&excludeErrors=false")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "false", w.Header().Get("X-Decode-Errors-Present"))
	assert.Equal(t, 1004, fakeDs.LastJobId)
	assert.Equal(t, 10, fakeDs.LastOffset)
	assert.Equal(t, 50, fakeDs.LastCount)
	assert.True(t, fakeDs.LastUnwrap)
	assert.False(t, fakeDs.LastExcludeErrors)

	var packets []*model.Packet
	err := json.Unmarshal(w.Body.Bytes(), &packets)
	assert.NoError(t, err)
	assert.Len(t, packets, 2)
}

func TestPacketHandler_GetPackets_SuccessWithErrors(t *testing.T) {
	fakeDs := NewFakeDatastore()
	fakeDs.packets = []*model.Packet{
		{Number: 0, Type: "TCP"},
	}
	fakeDs.HasErrors = true

	srv := &Server{
		Config:    &config.ServerConfig{MaxPacketCount: 5000},
		Datastore: fakeDs,
	}

	r := chi.NewRouter()
	RegisterPacketRoutes(srv, r, "/packets")

	req := newPacketTestRequest("GET", "/packets/1004?excludeErrors=true")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "true", w.Header().Get("X-Decode-Errors-Present"))
	assert.Equal(t, 1004, fakeDs.LastJobId)
	assert.True(t, fakeDs.LastExcludeErrors)
	assert.False(t, fakeDs.LastUnwrap)
	assert.Equal(t, 0, fakeDs.LastOffset)
	assert.Equal(t, 5000, fakeDs.LastCount)
}

func TestPacketHandler_GetPackets_QueryParamJobId(t *testing.T) {
	fakeDs := NewFakeDatastore()
	srv := &Server{
		Config:    &config.ServerConfig{MaxPacketCount: 5000},
		Datastore: fakeDs,
	}

	r := chi.NewRouter()
	RegisterPacketRoutes(srv, r, "/packets")

	req := newPacketTestRequest("GET", "/packets/?jobId=1005")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1005, fakeDs.LastJobId)
}

func TestPacketHandler_GetPackets_InvalidJobId(t *testing.T) {
	fakeDs := NewFakeDatastore()
	srv := &Server{
		Config:    &config.ServerConfig{MaxPacketCount: 5000},
		Datastore: fakeDs,
	}

	r := chi.NewRouter()
	RegisterPacketRoutes(srv, r, "/packets")

	req := newPacketTestRequest("GET", "/packets/invalid")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPacketHandler_GetPackets_NotFound(t *testing.T) {
	fakeDs := NewFakeDatastore()
	fakeDs.GetPacketsErr = errors.New("Job not found")

	srv := &Server{
		Config:    &config.ServerConfig{MaxPacketCount: 5000},
		Datastore: fakeDs,
	}

	r := chi.NewRouter()
	RegisterPacketRoutes(srv, r, "/packets")

	req := newPacketTestRequest("GET", "/packets/9999")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}
