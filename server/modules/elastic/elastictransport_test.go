// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
	"context"
	"net/http"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

type DummyTransport struct {
	username string
}

func (transport *DummyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	transport.username = req.Header.Get("es-security-runas-user")
	return nil, nil
}

func TestRoundTrip(tester *testing.T) {
	dummy := &DummyTransport{}
	transport := &ElasticTransport{}
	transport.internal = dummy

	user := model.NewUser()
	user.Email = "test"
	request, _ := http.NewRequest("GET", "", nil)
	request = request.WithContext(context.WithValue(context.Background(), web.ContextKeyRequestor, user))
	transport.RoundTrip(request)
	assert.Equal(tester, "test", dummy.username)
}

func TestRoundTripSearchUsername(tester *testing.T) {
	dummy := &DummyTransport{}
	transport := &ElasticTransport{}
	transport.internal = dummy

	user := model.NewUser()
	user.Email = "test"
	user.SearchUsername = "mysearchuser"
	request, _ := http.NewRequest("GET", "", nil)
	request = request.WithContext(context.WithValue(context.Background(), web.ContextKeyRequestor, user))
	transport.RoundTrip(request)
	assert.Equal(tester, "mysearchuser", dummy.username)
}
