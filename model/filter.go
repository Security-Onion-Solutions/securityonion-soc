// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"time"
)

const PROTOCOL_ICMP = "icmp"
const PROTOCOL_TCP = "tcp"
const PROTOCOL_UDP = "udp"

type Filter struct {
	// An optional import ID to use for locating related import packets
	ImportId string `json:"importId" example:"bd77c8bc7498c795cc6608c5d45bd51b"`
	// The begin time for the packet filtering; only packets with timestamps between the BeginTime and EndTime will be included in this filter
	BeginTime time.Time `json:"beginTime" example:"2024-12-03T00:25:09.899Z"`
	// The end time for the packet filtering; only packets with timestamps between the BeginTime and EndTime will be included in this filter
	EndTime time.Time `json:"endTime" example:"2024-12-03T00:29:09.899Z"`
	// The source IP to capture; Note that the PCAP job will allow destination and source data to be interchanged to ensure packets are not missed in certain capture scenarios"
	SrcIp string `json:"srcIp" example:"44.2.12.63"`
	// The source port to capture; Note that the PCAP job will allow destination and source data to be interchanged to ensure packets are not missed in certain capture scenarios"
	SrcPort int `json:"srcPort" example:"55312"`
	// The destintion IP to capture; Note that the PCAP job will allow destination and source data to be interchanged to ensure packets are not missed in certain capture scenarios"
	DstIp string `json:"dstIp" example:"1.2.3.4"`
	// The destination port to capture; Note that the PCAP job will allow destination and source data to be interchanged to ensure packets are not missed in certain capture scenarios"
	DstPort int `json:"dstPort" example:"80"`
	// Require the captured packets to be using this protocol"
	Protocol string `json:"protocol" example:"tcp"`
	// Additional, untyped filter parameters; used by non-PCAP job processors
	Parameters map[string]interface{} `json:"parameters"`
}

func NewFilter() *Filter {
	return &Filter{
		Parameters: make(map[string]interface{}),
	}
}
