// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

func TestClientsHandler_LicenseInvalid(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	h := &ClientsHandler{server: &Server{}}

	tests := []struct {
		Name    string
		Handler http.HandlerFunc
	}{
		{"getClients", h.getClients},
		{"postClient", h.postClient},
		{"postAddPermission", h.postAddPermission},
		{"putGeneratedSecret", h.putGeneratedSecret},
		{"putClient", h.putClient},
		{"deleteClient", h.deleteClient},
		{"deleteClientPermission", h.deleteClientPermission},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/connect/clients/", nil)
			req = req.WithContext(context.WithValue(req.Context(), web.ContextKeyRequestStart, time.Now()))
			w := httptest.NewRecorder()

			test.Handler(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Equal(t, "ERROR_LICENSE_INVALID", w.Body.String())
		})
	}
}
