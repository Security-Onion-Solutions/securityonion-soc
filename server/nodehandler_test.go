// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

type nodeHandlerDatastore struct {
	*FakeDatastore
	updateNodeResult *model.Node
	updateNodeErr    error
	updateNodeCalls  int
	getNextJobCalls  int
	getNextJobNodeId string
}

func (ds *nodeHandlerDatastore) UpdateNode(ctx context.Context, newNode *model.Node) (*model.Node, error) {
	ds.updateNodeCalls++
	return ds.updateNodeResult, ds.updateNodeErr
}

func (ds *nodeHandlerDatastore) GetNextJob(ctx context.Context, nodeId string) *model.Job {
	ds.getNextJobCalls++
	ds.getNextJobNodeId = nodeId
	return nil
}

func postNodeForTest(srv *Server, ds *nodeHandlerDatastore, body string) (*httptest.ResponseRecorder, int, *model.Node) {
	updateNodeMetricsCalls := 0
	var metricsNode *model.Node
	srv.Datastore = ds
	srv.Metrics = &MockMetrics{
		UpdateNodeMetricsFunc: func(ctx context.Context, node *model.Node) bool {
			updateNodeMetricsCalls++
			metricsNode = node
			return false
		},
	}
	srv.Host = web.NewHost("", "", 0, "", nil)
	h := &NodeHandler{server: srv}

	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestStart, time.Now())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.postNode(w, req)
	return w, updateNodeMetricsCalls, metricsNode
}

func TestPostNodeUpdateNodeError(t *testing.T) {
	ds := &nodeHandlerDatastore{
		FakeDatastore: NewFakeDatastore(),
		updateNodeErr: errors.New("update failed"),
	}

	w, metricsCalls, _ := postNodeForTest(NewFakeAuthorizedServer(nil), ds, `{"id":"node1"}`)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, 1, ds.updateNodeCalls)
	assert.Equal(t, 0, metricsCalls)
	assert.Equal(t, 0, ds.getNextJobCalls)
}

func TestPostNodeMissingId(t *testing.T) {
	servers := map[string]*Server{
		"authorized":   NewFakeAuthorizedServer(nil),
		"unauthorized": NewFakeUnauthorizedServer(),
	}

	for name, srv := range servers {
		t.Run(name, func(t *testing.T) {
			ds := &nodeHandlerDatastore{
				FakeDatastore:    NewFakeDatastore(),
				updateNodeResult: model.NewNode(""),
			}

			w, metricsCalls, _ := postNodeForTest(srv, ds, `{"id":""}`)

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Equal(t, "ERROR_NODE_ID_REQUIRED", w.Body.String())
			assert.Equal(t, 0, ds.updateNodeCalls)
			assert.Equal(t, 0, metricsCalls)
			assert.Equal(t, 0, ds.getNextJobCalls)
		})
	}
}

func TestPostNodeSuccess(t *testing.T) {
	ds := &nodeHandlerDatastore{
		FakeDatastore:    NewFakeDatastore(),
		updateNodeResult: model.NewNode("node1"),
	}

	w, metricsCalls, metricsNode := postNodeForTest(NewFakeAuthorizedServer(nil), ds, `{"id":"node1"}`)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, ds.updateNodeCalls)
	assert.Equal(t, 1, metricsCalls)
	assert.Equal(t, 1, ds.getNextJobCalls)
	assert.Equal(t, "node1", ds.getNextJobNodeId)
	assert.Same(t, ds.updateNodeResult, metricsNode)
}

func TestPostNodeMissingIdKey(t *testing.T) {
	ds := &nodeHandlerDatastore{
		FakeDatastore:    NewFakeDatastore(),
		updateNodeResult: model.NewNode("node1"),
	}

	w, metricsCalls, _ := postNodeForTest(NewFakeAuthorizedServer(nil), ds, `{}`)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "ERROR_NODE_ID_REQUIRED", w.Body.String())
	assert.Equal(t, 0, ds.updateNodeCalls)
	assert.Equal(t, 0, metricsCalls)
	assert.Equal(t, 0, ds.getNextJobCalls)
}

func TestPostNodeMalformedJson(t *testing.T) {
	ds := &nodeHandlerDatastore{
		FakeDatastore:    NewFakeDatastore(),
		updateNodeResult: model.NewNode("node1"),
	}

	w, metricsCalls, _ := postNodeForTest(NewFakeAuthorizedServer(nil), ds, `{"id":"node1"`)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NotEqual(t, "ERROR_NODE_ID_REQUIRED", w.Body.String())
	assert.Equal(t, 0, ds.updateNodeCalls)
	assert.Equal(t, 0, metricsCalls)
	assert.Equal(t, 0, ds.getNextJobCalls)
}

func TestPostNodeNilMetrics(t *testing.T) {
	ds := &nodeHandlerDatastore{
		FakeDatastore:    NewFakeDatastore(),
		updateNodeResult: model.NewNode("node1"),
	}
	srv := NewFakeAuthorizedServer(nil)
	srv.Datastore = ds
	srv.Metrics = nil
	srv.Host = web.NewHost("", "", 0, "", nil)
	h := &NodeHandler{server: srv}

	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"id":"node1"}`))
	req = req.WithContext(context.WithValue(req.Context(), web.ContextKeyRequestStart, time.Now()))
	w := httptest.NewRecorder()

	h.postNode(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, ds.updateNodeCalls)
	assert.Equal(t, 1, ds.getNextJobCalls)
}
