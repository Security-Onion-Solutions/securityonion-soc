// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

func TestFilterMissing(t *testing.T) {
	t.Parallel()

	table := []struct {
		Name          string
		Path          string
		ExpectedQuery string
	}{
		{
			Name:          "Include",
			Path:          "/api/query/filtered?query=*+%7C+groupby+unit.type*&field=unit.type&value=__missing__&scalar=false&mode=INCLUDE",
			ExpectedQuery: `"* AND NOT _exists_:\"unit.type\" | groupby unit.type*"`,
		},
		{
			Name:          "Exclude",
			Path:          "/api/query/filtered?query=*+%7C+groupby+unit.type*&field=unit.type&value=__missing__&scalar=false&mode=EXCLUDE",
			ExpectedQuery: `"* AND _exists_:\"unit.type\" | groupby unit.type*"`,
		},
		{
			Name:          "Drilldown",
			Path:          "/api/query/filtered?query=*+%7C+groupby+unit.type*&field=unit.type&value=__missing__&scalar=false&mode=DRILLDOWN",
			ExpectedQuery: `"* AND NOT _exists_:\"unit.type\""`,
		},
	}

	handler := &QueryHandler{}

	c := chi.NewRouteContext()
	c.URLParams.Add("operation", "filtered")
	ctx := context.WithValue(context.Background(), chi.RouteCtxKey, c)
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())

	for _, tt := range table {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(ctx, "GET", tt.Path, nil)
			assert.NoError(t, err)

			handler.getQuery(w, r)

			altered := w.Body.String()
			assert.Equal(t, tt.ExpectedQuery, altered)
			assert.Equal(t, http.StatusOK, w.Code)
		})
	}
}

type MockEventstore struct{}

func (m *MockEventstore) EventSearch(context context.Context, criteria *model.EventSearchCriteria) (*model.EventSearchResults, error) {
	return nil, nil
}
func (m *MockEventstore) Search(context context.Context, criteria *model.EventSearchCriteria) (*model.EventSearchResults, error) {
	return nil, nil
}
func (m *MockEventstore) MSearch(context context.Context, criteria []*model.EventMSearchCriteria) (*model.EventMSearchResults, error) {
	return nil, nil
}
func (m *MockEventstore) Scroll(context context.Context, criteria *model.EventScrollCriteria, indexes []string) (*model.EventScrollResults, error) {
	return nil, nil
}
func (m *MockEventstore) Index(ctx context.Context, index string, document map[string]interface{}, id string) (*model.EventIndexResults, error) {
	return nil, nil
}
func (m *MockEventstore) Update(context context.Context, criteria *model.EventUpdateCriteria) (*model.EventUpdateResults, error) {
	return nil, nil
}
func (m *MockEventstore) Delete(context context.Context, index string, id string) error {
	return nil
}
func (m *MockEventstore) Acknowledge(context context.Context, criteria *model.EventAckCriteria) (*model.EventUpdateResults, error) {
	return nil, nil
}
func (m *MockEventstore) GetActiveQueries(ctx context.Context, filter bool) ([]*model.QueryTask, error) {
	// Create some mock QueryTask data
	queries := []*model.QueryTask{
		{
			TaskId:  "1",
			Details: "test query 1",
		},
		{
			TaskId:  "2",
			Details: "test query 2",
		},
	}
	return queries, nil
}

func (m *MockEventstore) CancelQuery(ctx context.Context, queryId string) error {
	if queryId == "notFound" {
		return errors.New("query not found")
	} else if queryId == "error" {
		return errors.New("some error")
	}
	return nil
}

func TestGetActiveQueriesNoLicense(t *testing.T) {
	// Create a mock QueryHandler
	handler := &QueryHandler{
		server: &Server{
			Eventstore: &MockEventstore{},
		},
	}

	// Create a mock HTTP request
	r := httptest.NewRequest("GET", "/api/query/active", nil)
	r = r.WithContext(context.WithValue(r.Context(), web.ContextKeyRequestStart, time.Now()))

	// Create a mock HTTP recorder
	w := httptest.NewRecorder()

	// Call the getActiveQueries method
	handler.getActiveQueries(w, r)

	// Check the response code
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Check the response body
	expected := `ERROR_LICENSE_INVALID`
	assert.Equal(t, expected, w.Body.String())
}

func TestGetActiveQueries(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_QRY, 0, 0, "", "")

	// Create a mock QueryHandler
	handler := &QueryHandler{
		server: &Server{
			Eventstore: &MockEventstore{},
		},
	}

	// Create a mock HTTP request
	r := httptest.NewRequest("GET", "/api/query/active", nil)
	r = r.WithContext(context.WithValue(r.Context(), web.ContextKeyRequestStart, time.Now()))

	// Create a mock HTTP recorder
	w := httptest.NewRecorder()

	// Call the getActiveQueries method
	handler.getActiveQueries(w, r)

	// Check the response code
	assert.Equal(t, http.StatusOK, w.Code)

	// Check the response body
	expected := `[
		{
			"gridId": "",
			"taskId": "1",
			"details": "test query 1",
			"startTime": "0001-01-01T00:00:00Z",
			"elapsedMs": 0,
			"cancelable": false
		},
		{
			"gridId": "",
			"taskId": "2",
			"details": "test query 2",
			"startTime": "0001-01-01T00:00:00Z",
			"elapsedMs": 0,
			"cancelable": false
		}
	]`
	assert.JSONEq(t, expected, w.Body.String())
}

func TestPostCancelQueryNoLicense(t *testing.T) {
	// Create a mock QueryHandler
	handler := &QueryHandler{
		server: &Server{
			Eventstore: &MockEventstore{},
		},
	}

	// Create a mock HTTP request
	r := httptest.NewRequest("POST", "/api/query/cancel/123", nil)
	r = r.WithContext(context.WithValue(r.Context(), web.ContextKeyRequestStart, time.Now()))

	// Create a mock HTTP recorder
	w := httptest.NewRecorder()

	// Create a chi router context and set the queryId parameter
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("queryId", "123")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	// Call the postCancelQuery method
	handler.postCancelQuery(w, r)

	// Check the response code
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Check the response body
	expected := `ERROR_LICENSE_INVALID`
	assert.Equal(t, expected, w.Body.String())
}

func TestPostCancelQueryNotFound(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_QRY, 0, 0, "", "")

	// Create a mock QueryHandler
	handler := &QueryHandler{
		server: &Server{
			Eventstore: &MockEventstore{},
		},
	}

	// Create a mock HTTP request
	r := httptest.NewRequest("POST", "/api/query/cancel/notFound", nil)
	r = r.WithContext(context.WithValue(r.Context(), web.ContextKeyRequestStart, time.Now()))

	// Create a mock HTTP recorder
	w := httptest.NewRecorder()

	// Create a chi router context and set the queryId parameter
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("queryId", "notFound")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	// Call the postCancelQuery method
	handler.postCancelQuery(w, r)

	// Check the response code
	assert.Equal(t, http.StatusNotFound, w.Code)

	// Check the response body
	expected := `ERROR_QUERY_NOT_FOUND`
	assert.Equal(t, expected, w.Body.String())
}

func TestPostCancelQuerySuccess(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_QRY, 0, 0, "", "")

	// Create a mock QueryHandler
	handler := &QueryHandler{
		server: &Server{
			Eventstore: &MockEventstore{},
		},
	}

	// Create a mock HTTP request
	r := httptest.NewRequest("POST", "/api/query/cancel/success", nil)
	r = r.WithContext(context.WithValue(r.Context(), web.ContextKeyRequestStart, time.Now()))

	// Create a mock HTTP recorder
	w := httptest.NewRecorder()

	// Create a chi router context and set the queryId parameter
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("queryId", "success")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	// Call the postCancelQuery method
	handler.postCancelQuery(w, r)

	// Check the response code
	assert.Equal(t, http.StatusOK, w.Code)

	// Check the response body
	expected := ""
	assert.Equal(t, expected, w.Body.String())
}

func TestPostCancelQueryError(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_QRY, 0, 0, "", "")

	// Create a mock QueryHandler
	handler := &QueryHandler{
		server: &Server{
			Eventstore: &MockEventstore{},
		},
	}

	// Create a mock HTTP request
	r := httptest.NewRequest("POST", "/api/query/cancel/error", nil)
	r = r.WithContext(context.WithValue(r.Context(), web.ContextKeyRequestStart, time.Now()))

	// Create a mock HTTP recorder
	w := httptest.NewRecorder()

	// Create a chi router context and set the queryId parameter
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("queryId", "error")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	// Call the postCancelQuery method
	handler.postCancelQuery(w, r)

	// Check the response code
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Check the response body
	expected := `The request could not be processed.`
	assert.Equal(t, expected, w.Body.String())
}
