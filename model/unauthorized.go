// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

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
