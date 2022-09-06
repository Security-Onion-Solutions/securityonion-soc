// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
	Id          string `json:"id"`
	Name        string `json:"name"`
	Role        string `json:"role"`
	Fingerprint string `json:"fingerprint"`
	Status      string `json:"status"`
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
