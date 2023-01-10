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
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestUserstoreInit(tester *testing.T) {
	ai := NewKratosUserstore(nil)
	err := ai.Init("abc")
	assert.Nil(tester, err)
}

func TestUnauthorized(tester *testing.T) {
	userStore := NewKratosUserstore(server.NewFakeUnauthorizedServer())

	_, err := userStore.GetUsers(context.Background())
	ensureUnauthorized(tester, err)

	_, err = userStore.GetUser(context.Background(), "some-id")
	ensureUnauthorized(tester, err)
}

func ensureUnauthorized(tester *testing.T, err error) {
	var authErr *model.Unauthorized
	assert.ErrorAs(tester, err, &authErr)
}
