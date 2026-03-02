// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	. "github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"go.uber.org/mock/gomock"

	"github.com/stretchr/testify/assert"
)

func TestReverseLookupHandler(t *testing.T) {
	tests := []struct {
		Name                string
		EnableReverseLookup bool
		ExpectedResults     int
	}{
		{
			Name:                "No DNS",
			EnableReverseLookup: false,
			ExpectedResults:     1,
		},
		{
			Name:                "With DNS",
			EnableReverseLookup: true,
			ExpectedResults:     4,
		},
	}

	for _, test := range tests {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := &config.ServerConfig{
			EnableReverseLookup: test.EnableReverseLookup,
		}

		srv := NewMockServer(t, ctrl, cfg)

		h := NewUtilHandler(srv)

		fakeEventStore := srv.Eventstore.(*FakeEventstore)

		fakeEventStore.MSearchResults = append(fakeEventStore.MSearchResults, &model.EventMSearchResults{
			Responses: []*model.EventSearchResults{
				{},
				{},
				{},
				{
					Events: []*model.EventRecord{
						{
							Payload: map[string]interface{}{
								"so.ip_address":  "4.0.0.4",
								"so.description": "host4",
							},
						},
					},
				},
			},
		})

		body := []byte(`["1.0.0.1", "2.0.0.2", "3.0.0.3", "4.0.0.4", "badip"]`)

		r := httptest.NewRequest("PUT", "/reverse-lookup", bytes.NewReader(body))

		ctx := context.WithValue(context.Background(), web.ContextKeyRequestStart, time.Now())
		r = r.WithContext(ctx)

		w := httptest.NewRecorder()

		h.PutReverseLookup(w, r)

		raw := w.Body.Bytes()
		results := map[string][]string{}

		err := json.Unmarshal(raw, &results)
		assert.NoError(t, err)

		assert.Equal(t, test.ExpectedResults, len(results))
		for _, names := range results {
			assert.NotEmpty(t, names)
		}

		assert.Equal(t, []string{"host4"}, results["4.0.0.4"])
	}
}
