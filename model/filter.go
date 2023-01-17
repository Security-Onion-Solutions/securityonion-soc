// Copyright 2019 Jason Ertel (jertel). All rights reserved.
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
  "time"
)

type Filter struct {
  ImportId   string                 `json:"importId"`
  BeginTime  time.Time              `json:"beginTime"`
  EndTime    time.Time              `json:"endTime"`
  SrcIp      string                 `json:"srcIp"`
  SrcPort    int                    `json:"srcPort"`
  DstIp      string                 `json:"dstIp"`
  DstPort    int                    `json:"dstPort"`
  Parameters map[string]interface{} `json:"parameters"`
}

func NewFilter() *Filter {
  return &Filter{
    Parameters: make(map[string]interface{}),
  }
}
