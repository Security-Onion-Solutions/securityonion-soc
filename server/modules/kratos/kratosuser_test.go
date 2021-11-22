// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package kratos

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/stretchr/testify/assert"
)

func TestCopyFromUser(tester *testing.T) {
	kratosUser := &KratosUser{}
	user := model.NewUser()
	user.Email = "my@email"
	user.FirstName = "myFirstname"
	user.LastName = "myLastname"
	user.Note = "myNote"
	user.Status = "locked"
	kratosUser.copyFromUser(user)
	assert.Equal(tester, user.Email, kratosUser.Traits.Email)
	assert.Equal(tester, user.FirstName, kratosUser.Traits.FirstName)
	assert.Equal(tester, user.LastName, kratosUser.Traits.LastName)
	assert.Equal(tester, user.Note, kratosUser.Traits.Note)
	assert.Equal(tester, "inactive", kratosUser.State)
	assert.Equal(tester, user.Email, kratosUser.Addresses[0].Value)
}

func TestCopyFromUserActive(tester *testing.T) {
	kratosUser := &KratosUser{}
	user := model.NewUser()
	user.Status = ""
	kratosUser.copyFromUser(user)
	assert.Equal(tester, "active", kratosUser.State)
}

func TestCopyToUser(tester *testing.T) {
	kratosUser := NewKratosUser("myEmail", "myFirst", "myLast", "note", "inactive")
	user := model.NewUser()
	kratosUser.copyToUser(user)
	assert.Equal(tester, kratosUser.Traits.Email, user.Email)
	assert.Equal(tester, kratosUser.Traits.FirstName, user.FirstName)
	assert.Equal(tester, kratosUser.Traits.LastName, user.LastName)
	assert.Equal(tester, kratosUser.Traits.Note, user.Note)
	assert.Equal(tester, kratosUser.Addresses[0].Value, user.Email)
	assert.Equal(tester, "locked", user.Status)
}

func TestCopyToUserActive(tester *testing.T) {
	kratosUser := NewKratosUser("myEmail", "myFirst", "myLast", "myNote", "active")
	user := model.NewUser()
	kratosUser.copyToUser(user)
	assert.Equal(tester, "", user.Status)
}
