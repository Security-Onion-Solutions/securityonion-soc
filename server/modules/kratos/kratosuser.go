// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package kratos

import (
	"github.com/security-onion-solutions/securityonion-soc/model"
	"time"
)

type KratosTraits struct {
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Note      string `json:"note"`
}

func NewTraits(email string, firstName string, lastName string, note string) *KratosTraits {
	traits := &KratosTraits{
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
		Note:      note,
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

type KratosCredential struct {
	Type        string    `json:"type"`
	Identifiers []string  `json:"identifiers"`
	CreateDate  time.Time `json:"created_at"`
	UpdateDate  time.Time `json:"updated_at"`
}

type KratosUser struct {
	Id          string                       `json:"id"`
	SchemaId    string                       `json:"schema_id"`
	SchemaUrl   string                       `json:"schema_url"`
	State       string                       `json:"state"`
	Traits      *KratosTraits                `json:"traits"`
	Addresses   []*KratosAddress             `json:"verifiable_addresses"`
	Credentials map[string]*KratosCredential `json:"credentials"`
	CreateDate  time.Time                    `json:"created_at"`
	UpdateDate  time.Time                    `json:"updated_at"`
}

func NewKratosUser(email string, firstName string, lastName string, note string, state string) *KratosUser {
	kratosUser := &KratosUser{
		Traits:    NewTraits(email, firstName, lastName, note),
		Addresses: NewAddresses(email),
		State:     state,
	}
	return kratosUser
}

func (kratosUser *KratosUser) copyToUser(user *model.User) {
	user.Id = kratosUser.Id
	user.Email = kratosUser.Traits.Email
	user.FirstName = kratosUser.Traits.FirstName
	user.LastName = kratosUser.Traits.LastName
	user.Note = kratosUser.Traits.Note
	if kratosUser.State == "inactive" {
		user.Status = "locked"
	} else {
		user.Status = ""
	}
	if len(kratosUser.Credentials) > 0 {
		if kratosUser.Credentials["totp"] != nil {
			user.MfaStatus = "enabled"
		} else {
			user.MfaStatus = "disabled"
		}
	}
}

func (kratosUser *KratosUser) copyFromUser(user *model.User) {
	if kratosUser.Traits == nil {
		kratosUser.Traits = &KratosTraits{}
	}
	kratosUser.Traits.Email = user.Email
	kratosUser.Traits.FirstName = user.FirstName
	kratosUser.Traits.LastName = user.LastName
	kratosUser.Traits.Note = user.Note
	if user.Status == "locked" {
		kratosUser.State = "inactive"
	} else {
		kratosUser.State = "active"
	}
	if len(kratosUser.Addresses) == 0 {
		kratosUser.Addresses = make([]*KratosAddress, 1)
		kratosUser.Addresses[0] = &KratosAddress{}
	}
	kratosUser.Addresses[0].Value = user.Email
	kratosUser.Addresses[0].Verified = true
}
