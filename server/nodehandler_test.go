// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/stretchr/testify/assert"
)

type updateNodeDatastore struct {
	*FakeDatastore
	updated *model.Node
}

func (d *updateNodeDatastore) UpdateNode(ctx context.Context, node *model.Node) (*model.Node, error) {
	d.updated = node
	return node, nil
}

func TestPostNodeStampsEventsHealth(t *testing.T) {
	srv := NewFakeAuthorizedServer(nil)
	datastore := &updateNodeDatastore{FakeDatastore: NewFakeDatastore()}
	srv.Datastore = datastore
	srv.Eventstore = NewFakeEventstore()
	h := &NodeHandler{server: srv}

	req := httptest.NewRequest("POST", "/node", bytes.NewReader([]byte(`{"id":"node-1","role":"so-manager"}`)))
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestStart, time.Now())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.postNode(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// The broadcast node must carry the derived flag (regression: rows
	// replaced by broadcasts hid the events health link)
	if assert.NotNil(t, datastore.updated) {
		assert.True(t, datastore.updated.EventsHealthAvailable)
	}
}
