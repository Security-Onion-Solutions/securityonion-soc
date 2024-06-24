// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// Note that this file is not autogenerated. These mocks were created manually.

package mock

import (
	"errors"
	"net/http"
	"testing"

	"github.com/elastic/go-elasticsearch/v8"
)

type MockTransport struct {
	requests    []*http.Request
	responses   []*http.Response
	roundTripFn func(req *http.Request) (*http.Response, error)
}

func (t *MockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.requests = append(t.requests, req)
	return t.roundTripFn(req)
}

func (t *MockTransport) AddResponse(res *http.Response) {
	if res.Body == nil {
		res.Body = http.NoBody
	}

	t.responses = append(t.responses, res)
}

func (t *MockTransport) GetRequests() []*http.Request {
	return t.requests
}

func NewMockClient(t *testing.T) (*elasticsearch.Client, *MockTransport) {
	mocktrans := MockTransport{}
	mocktrans.roundTripFn = func(req *http.Request) (*http.Response, error) {
		if len(mocktrans.responses) != 0 {
			res := mocktrans.responses[0]
			mocktrans.responses = mocktrans.responses[1:]

			return res, nil
		} else {
			return nil, errors.New("unexpected call to client")
		}
	}

	client, err := elasticsearch.NewClient(elasticsearch.Config{
		Transport: &mocktrans,
	})
	if err != nil {
		t.Fatalf("Error creating Elasticsearch client: %s", err)
	}

	return client, &mocktrans
}
