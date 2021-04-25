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
	"github.com/security-onion-solutions/securityonion-soc/model"
	"time"
)

type KratosTraits struct {
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Role      string `json:"role"`
	Status    string `json:"status"`
}

func NewTraits(email string, firstName string, lastName string, role string, status string) *KratosTraits {
	traits := &KratosTraits{
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
		Role:      role,
		Status:    status,
	}
	return traits
}

type KratosAddress struct {
	Id             string    `json:"id"`
	Value          string    `json:"value"`
	ExpirationTime time.Time `json:"expires_at"`
	VerifiedTime   time.Time `json:"verified_at"`
	Verified       bool      `json:"verified"`
	VerifiedVia    string    `json:"via"`
}

func NewAddress(email string) *KratosAddress {
	address := &KratosAddress{
		Value: email,
	}
	return address
}

func NewAddresses(email string) []*KratosAddress {
	addresses := make([]*KratosAddress, 1)
	addresses[0] = NewAddress(email)
	return addresses
}

type KratosUser struct {
	Id        string           `json:"id"`
	SchemaId  string           `json:"schema_id"`
	SchemaUrl string           `json:"schema_url"`
	Traits    *KratosTraits    `json:"traits"`
	Addresses []*KratosAddress `json:"verifiable_addresses"`
}

func NewKratosUser(email string, firstName string, lastName string, role string, status string) *KratosUser {
	kratosUser := &KratosUser{
		Traits:    NewTraits(email, firstName, lastName, role, status),
		Addresses: NewAddresses(email),
	}
	return kratosUser
}

func (kratosUser *KratosUser) copyToUser(user *model.User) {
	user.Id = kratosUser.Id
	user.Email = kratosUser.Traits.Email
	user.FirstName = kratosUser.Traits.FirstName
	user.LastName = kratosUser.Traits.LastName
	user.Role = kratosUser.Traits.Role
	user.Status = kratosUser.Traits.Status
}

func (kratosUser *KratosUser) copyFromUser(user *model.User) {
	if kratosUser.Traits == nil {
		kratosUser.Traits = &KratosTraits{}
	}
	kratosUser.Traits.Email = user.Email
	kratosUser.Traits.FirstName = user.FirstName
	kratosUser.Traits.LastName = user.LastName
	kratosUser.Traits.Role = user.Role
	kratosUser.Traits.Status = user.Status
	if len(kratosUser.Addresses) == 0 {
		kratosUser.Addresses = make([]*KratosAddress, 1)
		kratosUser.Addresses[0] = &KratosAddress{}
	}
	kratosUser.Addresses[0].Value = user.Email
	kratosUser.Addresses[0].Verified = true
}
