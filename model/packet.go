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

type Packet struct {
  Number        int       `json:"number"`
  Type          string    `json:"type"`
  SrcMac        string    `json:"srcMac"`
  DstMac        string    `json:"dstMac"`
  SrcIp         string    `json:"srcIp"`
  SrcPort       int       `json:"srcPort"`
  DstIp         string    `json:"dstIp"`
  DstPort       int       `json:"dstPort"`
  Length        int       `json:"length"`
  Timestamp     time.Time `json:"timestamp"`
  Sequence      int       `json:"sequence"`
  Acknowledge   int       `json:"acknowledge"`
  Window        int       `json:"window"`
  Checksum      int       `json:"checksum"`
  Flags         []string  `json:"flags"`
  Payload       string    `json:"payload"`
  PayloadOffset int       `json:"payloadOffset"`
}

func NewPacket(number int) *Packet {
  return &Packet{
    Number: number,
    Type:   "UNKNOWN",
  }
}
