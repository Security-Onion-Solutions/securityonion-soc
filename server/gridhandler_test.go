// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

type FakeStatusstore struct {
	status *model.Status
}

func (f *FakeStatusstore) GetStatusSummary(ctx context.Context) (*model.Status, error) {
	return f.status, nil
}

func TestGetStatus(t *testing.T) {
	originalStatus := &model.Status{
		GridId: "original-grid-id",
	}

	srv := &Server{
		Statusstore: &FakeStatusstore{status: originalStatus},
	}
	h := &GridHandler{server: srv}

	req := httptest.NewRequest("GET", "/status?assignedGridId=new-grid-id", nil)
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestStart, time.Now())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.getStatus(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var responseStatus model.Status
	err := json.Unmarshal(w.Body.Bytes(), &responseStatus)
	assert.NoError(t, err)

	// Verify the response has the assigned grid ID
	assert.Equal(t, "new-grid-id", responseStatus.GridId)

	// Verify the original status object was NOT modified
	assert.Equal(t, "original-grid-id", originalStatus.GridId)
}

func TestGetNodes(t *testing.T) {
	originalNode := &model.Node{
		Id:     "node-1",
		GridId: "original-grid-id",
	}

	nodes := []*model.Node{originalNode}

	srv := &Server{
		Datastore: &FakeDatastore{nodes: nodes},
	}
	h := &GridHandler{server: srv}

	req := httptest.NewRequest("GET", "/?assignedGridId=new-grid-id", nil)
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestStart, time.Now())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.getNodes(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var responseNodes []model.Node
	err := json.Unmarshal(w.Body.Bytes(), &responseNodes)
	assert.NoError(t, err)

	assert.Len(t, responseNodes, 1)
	// Verify the response node has the assigned grid ID
	assert.Equal(t, "new-grid-id", responseNodes[0].GridId)

	// Verify the original node object was NOT modified
	assert.Equal(t, "original-grid-id", originalNode.GridId)
}
