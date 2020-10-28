// Copyright 2020 Security Onion Solutions. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package model

import (
  "time"
)

type Case struct {
  Id              string      `json:"id"`
  CreateTime      time.Time   `json:"createTime"`
  StartTime       time.Time   `json:"startTime"`
  CompleteTime    time.Time   `json:"completeTime"`
  Title           string      `json:"title"`
  Description     string      `json:"description"`
  Priority        int         `json:"priority"`
  Severity        int         `json:"severity"`
  Status          string      `json:"status"`
  Template        string      `json:"template"`
}

func NewCase() *Case {
  newCase := &Case{}
  return newCase
}