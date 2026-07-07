// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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

type MockMetrics struct {
	GetGridEpsFunc           func(ctx context.Context) int
	UpdateNodeMetricsFunc    func(ctx context.Context, node *model.Node) bool
	GetTimeSeriesMetricsFunc func(ctx context.Context, nodeId string, metricType string, startTime, endTime time.Time) (map[string][]model.MetricSample, error)
}

func (m *MockMetrics) GetGridEps(ctx context.Context) int {
	if m.GetGridEpsFunc != nil {
		return m.GetGridEpsFunc(ctx)
	}
	return 0
}

func (m *MockMetrics) UpdateNodeMetrics(ctx context.Context, node *model.Node) bool {
	if m.UpdateNodeMetricsFunc != nil {
		return m.UpdateNodeMetricsFunc(ctx, node)
	}
	return false
}

func (m *MockMetrics) GetTimeSeriesMetrics(ctx context.Context, nodeId string, metricType string, startTime, endTime time.Time) (map[string][]model.MetricSample, error) {
	if m.GetTimeSeriesMetricsFunc != nil {
		return m.GetTimeSeriesMetricsFunc(ctx, nodeId, metricType, startTime, endTime)
	}
	return nil, nil
}

type customTestError struct{}

func (e customTestError) Error() string { return "custom error" }

func TestGetMetricsHistory(t *testing.T) {
	t.Run("missing metric", func(t *testing.T) {
		srv := &Server{}
		h := &GridHandler{server: srv}

		req := httptest.NewRequest("GET", "/metrics?range=now-1h:now", nil)
		ctx := context.WithValue(req.Context(), web.ContextKeyRequestStart, time.Now())
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		h.getMetricsHistory(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid date range", func(t *testing.T) {
		srv := &Server{}
		h := &GridHandler{server: srv}

		req := httptest.NewRequest("GET", "/metrics?metric=cpu&range=invalid%20-%202023/01/15%205:00:00%20PM", nil)
		ctx := context.WithValue(req.Context(), web.ContextKeyRequestStart, time.Now())
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		h.getMetricsHistory(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("metrics nil", func(t *testing.T) {
		srv := &Server{Metrics: nil}
		h := &GridHandler{server: srv}

		req := httptest.NewRequest("GET", "/metrics?metric=cpu&range=now-1h:now", nil)
		ctx := context.WithValue(req.Context(), web.ContextKeyRequestStart, time.Now())
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		h.getMetricsHistory(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var res map[string][]model.MetricSample
		err := json.Unmarshal(w.Body.Bytes(), &res)
		assert.NoError(t, err)
		assert.Empty(t, res)
	})

	t.Run("successful query", func(t *testing.T) {
		now := time.Now()
		samples := []model.MetricSample{
			{Timestamp: now, Value: 12.34},
		}
		expectedData := map[string][]model.MetricSample{
			"cpu_used": samples,
		}

		mockMetrics := &MockMetrics{
			GetTimeSeriesMetricsFunc: func(ctx context.Context, nodeId string, metricType string, startTime, endTime time.Time) (map[string][]model.MetricSample, error) {
				assert.Equal(t, "node1", nodeId)
				assert.Equal(t, "cpu", metricType)
				return expectedData, nil
			},
		}

		srv := &Server{Metrics: mockMetrics}
		h := &GridHandler{server: srv}

		req := httptest.NewRequest("GET", "/metrics?metric=cpu&range=now-1h:now&nodeId=node1", nil)
		ctx := context.WithValue(req.Context(), web.ContextKeyRequestStart, time.Now())
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		h.getMetricsHistory(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var res map[string][]model.MetricSample
		err := json.Unmarshal(w.Body.Bytes(), &res)
		assert.NoError(t, err)
		assert.Contains(t, res, "cpu_used")
		assert.Len(t, res["cpu_used"], 1)
		assert.Equal(t, 12.34, res["cpu_used"][0].Value)
	})

	t.Run("unauthorized error", func(t *testing.T) {
		mockMetrics := &MockMetrics{
			GetTimeSeriesMetricsFunc: func(ctx context.Context, nodeId string, metricType string, startTime, endTime time.Time) (map[string][]model.MetricSample, error) {
				return nil, model.NewUnauthorized("user", "read", "nodes")
			},
		}

		srv := &Server{Metrics: mockMetrics}
		h := &GridHandler{server: srv}

		req := httptest.NewRequest("GET", "/metrics?metric=cpu&range=now-1h:now", nil)
		ctx := context.WithValue(req.Context(), web.ContextKeyRequestStart, time.Now())
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		h.getMetricsHistory(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("internal error", func(t *testing.T) {
		mockMetrics := &MockMetrics{
			GetTimeSeriesMetricsFunc: func(ctx context.Context, nodeId string, metricType string, startTime, endTime time.Time) (map[string][]model.MetricSample, error) {
				return nil, customTestError{}
			},
		}

		srv := &Server{Metrics: mockMetrics}
		h := &GridHandler{server: srv}

		req := httptest.NewRequest("GET", "/metrics?metric=cpu&range=now-1h:now", nil)
		ctx := context.WithValue(req.Context(), web.ContextKeyRequestStart, time.Now())
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		h.getMetricsHistory(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}
