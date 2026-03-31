// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"time"
)

type Packet struct {
	// The sequential packet number in the packet stream
	Number int `json:"number" example:"0"`
	// The packet type. Note that Security Onion only supports specific packet types in the PCAP retrieval and viewing system.
	Type string `json:"type" example:"DNS"`
	// The packet source MAC address
	SrcMac string `json:"srcMac" example:"0a:1b:2c:3d:4e:5f"`
	// The packet destination MAC address
	DstMac string `json:"dstMac" example:"a0:b1:c2:d3:e4:f5"`
	// The packet source IP address
	SrcIp string `json:"srcIp" example:"1.2.3.4"`
	// The packet source port
	SrcPort int `json:"srcPort" example:"80"`
	// The packet destination IP address
	DstIp string `json:"dstIp" example:"41.51.61.71"`
	// The packet destination port
	DstPort int `json:"dstPort" example:"55423"`
	// The size of the packet, including headers.
	Length int `json:"length" example:"79"`
	// The timestamp when the packet was captured
	Timestamp time.Time `json:"timestamp" example:"2024-10-06T19:29:39.332211Z"`
	// This packet's sequence number
	Sequence int `json:"sequence" example:"2023436470"`
	// An optional packet sequence number this packet is acknowledging having been received
	Acknowledge int `json:"acknowledge" example:"1400892081"`
	// The packet window size
	Window int `json:"window" example:"64296"`
	// The packet checksum value, used for integrity checking
	Checksum int `json:"checksum" example:"4868"`
	// The optional packet flags. Ex: SYN PSH FIN
	Flags []string `json:"flags" example:"SYN,ACK"`
	// The packet payload base64-encoded bytes
	Payload string `json:"payload" example:"oDaf1FD="`
	// The offset in the packet payload where the application-specific payload begins, if an application payload is applicable to this packet.
	PayloadOffset int `json:"payloadOffset" example:"0"`
}

func NewPacket(number int) *Packet {
	return &Packet{
		Number: number,
		Type:   "UNKNOWN",
	}
}
