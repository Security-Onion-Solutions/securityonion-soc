// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"mime/multipart"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

type rejectAuthorizer struct{}

func (auth *rejectAuthorizer) CheckContextOperationAuthorized(ctx context.Context, operation string, target string) error {
	return model.NewUnauthorized("", operation, target)
}
func (auth *rejectAuthorizer) CheckUserOperationAuthorized(user *model.User, operation string, target string) error {
	return model.NewUnauthorized("", operation, target)
}

func TestImportAuth(t *testing.T) {
	h := &GridMembersHandler{
		server: &Server{
			Authorizer: &rejectAuthorizer{},
			Config:     &config.ServerConfig{},
		},
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	ff, err := writer.CreateFormFile("attachment", "file.pcap")
	if err != nil {
		t.Fatal(err)
	}

	content, err := hex.DecodeString("a1b2c3d4000000")
	assert.NoError(t, err)

	_, err = ff.Write(content)
	assert.NoError(t, err)

	assert.NoError(t, writer.Close())

	w := httptest.NewRecorder()

	r := httptest.NewRequest("POST", "/1_standalone/import", bytes.NewReader(body.Bytes()))
	r.Header.Add("Content-Type", "multipart/form-data; boundary="+writer.Boundary())

	c := chi.NewRouteContext()
	c.URLParams.Add("id", "1_standalone")
	ctx := context.WithValue(context.Background(), chi.RouteCtxKey, c)
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())

	r = r.WithContext(ctx)

	h.postImport(w, r)

	assert.Equal(t, 401, w.Code)
	assert.Equal(t, web.GENERIC_ERROR_MESSAGE, w.Body.String())
}
