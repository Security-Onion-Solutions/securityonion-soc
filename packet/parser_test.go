// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package packet

import (
	"os"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/stretchr/testify/assert"
)

func TestOverrideType(tester *testing.T) {
	p := model.NewPacket(1)
	p.Type = "foo"
	overrideType(p, gopacket.LayerTypePayload)
	assert.Equal(tester, "foo", p.Type)
	overrideType(p, gopacket.LayerTypeFragment)
	assert.Equal(tester, "Fragment", p.Type)
}

func TestUnwrapPcap(tester *testing.T) {
	filename := "test_resources/parser_resource.pcap"
	tmpFile, err := os.CreateTemp("", "unwrap-test")
	assert.Nil(tester, err, "Unable to execute test due to bad temp file")
	unwrappedFilename := tmpFile.Name()
	os.Remove(unwrappedFilename)       // Don't need the actual file right now, delete it. We only need a filename.
	defer os.Remove(unwrappedFilename) // Delete it again after test finishes.
	unwrapped := UnwrapPcap(filename, unwrappedFilename)
	assert.True(tester, unwrapped)
}

func TestParseAndStream(tester *testing.T) {
	path := "test_resources/so-pcap.1575817346"
	filter := model.NewFilter()
	startTime, _ := time.Parse(time.RFC3339, "2019-12-08T00:00:00Z")
	filter.BeginTime = startTime
	endTime, _ := time.Parse(time.RFC3339, "2019-12-08T23:59:59Z")
	filter.EndTime = endTime
	filter.Protocol = model.PROTOCOL_TCP
	filter.SrcIp = "185.47.63.113"
	filter.SrcPort = 19
	filter.DstIp = "176.126.243.198"
	filter.DstPort = 34515

	packets, perr := ParseRawPcap(path, 999, filter)
	assert.Nil(tester, perr)
	assert.Len(tester, packets, 22)

	reader, size, err := ToStream(packets)

	assert.Nil(tester, err)
	pcap_length := 14918 // correlates to so-pcap test file
	bytes := make([]byte, 32768)
	count, err := reader.Read(bytes)
	assert.Nil(tester, err)
	assert.Equal(tester, pcap_length, count)
	assert.Equal(tester, pcap_length, size)
}

func TestParseWrongProtocol(tester *testing.T) {
	path := "test_resources/so-pcap.1575817346"
	filter := model.NewFilter()
	startTime, _ := time.Parse(time.RFC3339, "2019-12-08T00:00:00Z")
	filter.BeginTime = startTime
	endTime, _ := time.Parse(time.RFC3339, "2019-12-08T23:59:59Z")
	filter.EndTime = endTime
	filter.Protocol = model.PROTOCOL_ICMP
	filter.SrcIp = "185.47.63.113"
	filter.DstIp = "176.126.243.198"

	packets, perr := ParseRawPcap(path, 999, filter)
	assert.Nil(tester, perr)
	assert.Len(tester, packets, 0)
}

func TestParseAndStreamFail(tester *testing.T) {
	path := "test_resources/so-pcap.nonexistent"
	filter := model.NewFilter()

	_, perr := ParseRawPcap(path, 999, filter)
	assert.ErrorContains(tester, perr, "No such file")
}

func TestParseAndStreamIcmp(tester *testing.T) {
	path := "test_resources/icmp.pcap"
	filter := model.NewFilter()
	startTime, _ := time.Parse(time.RFC3339, "2024-02-12T00:00:00Z")
	filter.BeginTime = startTime
	endTime, _ := time.Parse(time.RFC3339, "2024-02-12T23:59:59Z")
	filter.EndTime = endTime
	filter.Protocol = model.PROTOCOL_ICMP
	filter.SrcIp = "90.151.225.16"
	filter.SrcPort = 19 // will be ignored since Protocol = ICMP
	filter.DstIp = "192.168.10.128"
	filter.DstPort = 34515 // will be ignored since Protocol = ICMP

	packets, perr := ParseRawPcap(path, 999, filter)
	assert.Nil(tester, perr)
	assert.Len(tester, packets, 2)

	reader, size, err := ToStream(packets)

	assert.Nil(tester, err)
	pcap_length := 196 // correlates to two icmp packets in icmp.pcap
	bytes := make([]byte, 32768)
	count, err := reader.Read(bytes)
	assert.Nil(tester, err)
	assert.Equal(tester, pcap_length, count)
	assert.Equal(tester, pcap_length, size)
}

func TestCreateBpf(tester *testing.T) {
	filter := model.NewFilter()
	startTime, _ := time.Parse(time.RFC3339, "2024-02-12T00:00:00Z")
	filter.BeginTime = startTime
	endTime, _ := time.Parse(time.RFC3339, "2024-02-12T23:59:59Z")
	filter.EndTime = endTime
	filter.Protocol = model.PROTOCOL_ICMP
	filter.SrcIp = "90.151.225.16"
	filter.SrcPort = 19 // will be ignored since Protocol = ICMP
	filter.DstIp = "192.168.10.128"
	filter.DstPort = 34515 // will be ignored since Protocol = ICMP

	actual := createBpf(filter)
	expected := "(icmp and host 90.151.225.16 and host 192.168.10.128) or (vlan and icmp and host 90.151.225.16 and host 192.168.10.128)"
	assert.Equal(tester, expected, actual)
}
