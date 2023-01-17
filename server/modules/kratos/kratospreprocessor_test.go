// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package kratos

import (
	"context"
	"net/http"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

func TestPreprocessPriority(tester *testing.T) {
	handler := NewKratosPreprocessor(nil)
	assert.Equal(tester, 110, handler.PreprocessPriority())
}
func TestPreprocess(tester *testing.T) {
	expectedId := "112233"

	user := model.NewUser()
	user.Id = expectedId
	userstore := NewKratosUserstore(server.NewFakeAuthorizedServer(make(map[string][]string)))
	userstore.Init("some/url")
	kratosUsersResponseJson := `
    [
      {
        "credentials": {},
        "id": "112233",
        "recovery_addresses": [],
        "state": "active",
        "traits": {
          "email": "",
          "firstname": "",
          "lastname": "",
          "note": ""
        },
        "verifiable_addresses": []
      }
    ]`
	userstore.client.MockStringResponse(kratosUsersResponseJson, 200, nil)

	handler := NewKratosPreprocessor(userstore)
	request, _ := http.NewRequest("GET", "", nil)

	request.Header.Set("x-user-id", expectedId)

	ctx, statusCode, err := handler.Preprocess(context.Background(), request)
	if assert.Nil(tester, err) {
		assert.Zero(tester, statusCode)
		assert.NotNil(tester, ctx)
	}

	requestor := ctx.Value(web.ContextKeyRequestor)
	assert.NotNil(tester, requestor)

	actualId := requestor.(*model.User).Id
	assert.Equal(tester, expectedId, actualId)

	requestorId := ctx.Value(web.ContextKeyRequestorId)
	if assert.NotNil(tester, requestorId) {
		assert.Equal(tester, expectedId, requestorId)
	}
}
