// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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

	"github.com/go-chi/chi/v5"
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
