// Copyright 2019 Jason Ertel (jertel). All rights reserved.
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

type Sensor struct {
  Id											string		`json:"id"`
  OnlineTime              time.Time `json:"onlineTime"`
  UpdateTime            	time.Time `json:"updateTime"`
  EpochTime								time.Time	`json:"epochTime"`
  UptimeSeconds						int				`json:"uptimeSeconds"`
  Description             string    `json:"description"`
  Version									string		`json:"version"`
}

func NewSensor(id string) *Sensor {
  return &Sensor{
    Id: id,
    OnlineTime: time.Now(),
    UpdateTime: time.Now(),
  }
}
