// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

type FakeConfigstore struct {
	SyncModuleError error
}

func (f *FakeConfigstore) GetSettings(ctx context.Context, advanced bool) ([]*model.Setting, error) {
	return nil, nil
}

func (f *FakeConfigstore) UpdateSetting(ctx context.Context, setting *model.Setting, remove bool) error {
	return nil
}

type FakeAdminConfigstore struct {
	SyncModuleError error
}

func (f *FakeAdminConfigstore) SyncSettings(ctx context.Context) error {
	return nil
}

func (f *FakeAdminConfigstore) SyncModule(ctx context.Context, module string, force bool) error {
	return f.SyncModuleError
}

func TestConfigHandler_putSyncModule(t *testing.T) {
	tests := []struct {
		name           string
		module         string
		async          string
		syncModuleErr  error
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Success without async",
			module:         "soc",
			async:          "",
			syncModuleErr:  nil,
			expectedStatus: http.StatusOK,
			expectedBody:   "",
		},
		{
			name:           "Success with async",
			module:         "myapp",
			async:          "true",
			syncModuleErr:  nil,
			expectedStatus: http.StatusOK,
			expectedBody:   "",
		},
		{
			name:           "SyncModule error",
			module:         "soc",
			async:          "false",
			syncModuleErr:  errors.New("ERROR_SYNC_FAILED"),
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "ERROR_SYNC_FAILED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := NewFakeAuthorizedServer(nil)
			srv.Configstore = &FakeConfigstore{}
			srv.AdminConfigstore = &FakeAdminConfigstore{
				SyncModuleError: tt.syncModuleErr,
			}

			h := &ConfigHandler{
				server: srv,
			}

			r := chi.NewRouter()
			r.Put("/sync/{module}", h.putSyncModule)

			w := httptest.NewRecorder()
			req := httptest.NewRequest("PUT", "/sync/"+tt.module+"?async="+tt.async, bytes.NewReader([]byte{}))
			ctx := context.WithValue(req.Context(), web.ContextKeyRequestId, "test-request")
			ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
			req = req.WithContext(ctx)

			r.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedBody != "" {
				assert.Contains(t, w.Body.String(), tt.expectedBody)
			} else {
				assert.Empty(t, w.Body.String())
			}
		})
	}
}

func TestConfigHandler_putSyncModule_NoConfigstore(t *testing.T) {
	srv := NewFakeAuthorizedServer(nil)
	srv.Configstore = nil

	h := &ConfigHandler{
		server: srv,
	}

	r := chi.NewRouter()
	r.Use(h.configEnabled)
	r.Put("/sync/{module}", h.putSyncModule)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/config/sync/soc", bytes.NewReader([]byte{}))
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestId, "test-request")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	req = req.WithContext(ctx)

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	assert.Contains(t, w.Body.String(), "The request could not be processed.")
}
