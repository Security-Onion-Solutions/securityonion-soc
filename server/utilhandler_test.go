// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/stretchr/testify/assert"
)

func TestReverseLookupHandler(t *testing.T) {
	fakeEventStore := &FakeEventstore{}
	h := UtilHandler{
		server: &Server{
			Eventstore: fakeEventStore,
			Config: &config.ServerConfig{
				Dns: "",
			},
		},
	}

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

	h.putReverseLookup(w, r)

	raw := w.Body.Bytes()
	results := map[string][]string{}

	err := json.Unmarshal(raw, &results)
	assert.NoError(t, err)

	assert.Equal(t, 4, len(results))
	for _, names := range results {
		assert.NotEmpty(t, names)
	}

	assert.Equal(t, []string{"host4"}, results["4.0.0.4"])
}
