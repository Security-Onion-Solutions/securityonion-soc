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
)

func TestCopyFromUser(tester *testing.T) {
	kratosUser := &KratosUser{}
	user := model.NewUser()
	user.Email = "my@email"
	user.FirstName = "myFirstname"
	user.LastName = "myLastname"
	user.Role = "myRole"
  user.Role = "locked"
  kratosUser.copyFromUser(user)
  if kratosUser.Traits.Email != user.Email {
    tester.Errorf("Email failed to convert")
	} 
  if kratosUser.Traits.FirstName != user.FirstName {
    tester.Errorf("FirstName failed to convert")
  } 
  if kratosUser.Traits.LastName != user.LastName {
    tester.Errorf("LastName failed to convert")
  } 
  if kratosUser.Traits.Role != user.Role {
    tester.Errorf("Role failed to convert")
	} 
  if kratosUser.Traits.Role != user.Role {
    tester.Errorf("Role failed to convert")
  } 
  if kratosUser.Addresses[0].Value != user.Email {
    tester.Errorf("Address failed to convert")
  } 
}

func TestCopyToUser(tester *testing.T) {
	kratosUser := NewKratosUser("myEmail", "myFirst", "myLast", "myRole", "locked")
	user := model.NewUser()
	kratosUser.copyToUser(user)
  if kratosUser.Traits.Email != user.Email {
    tester.Errorf("Email failed to convert")
	} 
  if kratosUser.Traits.FirstName != user.FirstName {
    tester.Errorf("FirstName failed to convert")
  } 
  if kratosUser.Traits.LastName != user.LastName {
    tester.Errorf("LastName failed to convert")
  } 
  if kratosUser.Traits.Role != user.Role {
    tester.Errorf("Role failed to convert")
	} 
  if kratosUser.Traits.Status != user.Status {
    tester.Errorf("Role failed to convert")
  } 
  if kratosUser.Addresses[0].Value != user.Email {
    tester.Errorf("Address failed to convert")
  } 
}