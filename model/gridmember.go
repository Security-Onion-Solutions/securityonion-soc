// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"strings"
)

const GridMemberAccepted = "accepted"
const GridMemberUnaccepted = "unaccepted"
const GridMemberRejected = "rejected"
const GridMemberDenied = "denied"

type GridMember struct {
	// The unique ID for this grid member
	Id string `json:"id" example:"myserver_standalone"`
	// The name of the grid member
	Name string `json:"name" example:"myserver"`
	// The role of this grid member, assigned during Security Onion setup
	Role string `json:"role" example:"standalone"`
	// The security fingerprint to ensure the grid member requesting to join the grid matches is the actual grid member that was just setup
	Fingerprint string `json:"fingerprint" example:"89:b2:75:46:7e:a7:5d:b2:bf:3a:d8:5d:62:fa:23:cf:43:e7:74:f5:68:4f:03:02:3c:24:0c:47:d6:29:86:af"`
	// The current membership status of this grid member
	Status string `json:"status" example:"accepted"`
}

func NewGridMember(id string, status string, fingerprint string) *GridMember {
	pieces := strings.Split(id, "_")
	role := pieces[len(pieces)-1]
	name := strings.TrimSuffix(id, "_"+role)
	return &GridMember{
		Id:          id,
		Name:        name,
		Role:        role,
		Status:      status,
		Fingerprint: fingerprint,
	}
}
