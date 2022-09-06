// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"fmt"
	"time"
)

type Unauthorized struct {
	CreateTime time.Time
	Subject    string
	Operation  string
	Target     string
}

func NewUnauthorized(subject string, operation string, target string) *Unauthorized {
	return &Unauthorized{
		CreateTime: time.Now(),
		Subject:    subject,
		Operation:  operation,
		Target:     target,
	}
}

func (err *Unauthorized) Error() string {
	return fmt.Sprintf("Subject '%v' is not authorized to perform operation '%v' on target '%v' @ '%v'", err.Subject, err.Operation, err.Target, err.CreateTime)
}
