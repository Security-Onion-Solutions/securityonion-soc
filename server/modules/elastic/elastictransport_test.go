// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

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
