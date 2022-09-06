// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

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
