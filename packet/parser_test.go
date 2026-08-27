// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package packet

import (
	"os"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

func TestAddBpf(tester *testing.T) {
	assert.Equal(tester, "a and b", AddBpf("a", "b"))
	assert.Equal(tester, "a", AddBpf("a", ""))
	assert.Equal(tester, "b", AddBpf("", "b"))
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

	actual := CreateBpf(filter, true)
	expected := "((icmp or icmp6) and host 90.151.225.16 and host 192.168.10.128) or (vlan and (icmp or icmp6) and host 90.151.225.16 and host 192.168.10.128)"
	assert.Equal(tester, expected, actual)

	actual = CreateBpf(filter, false)
	expected = "(icmp or icmp6) and host 90.151.225.16 and host 192.168.10.128"
	assert.Equal(tester, expected, actual)
}

func TestCreateBpfIcmp6(tester *testing.T) {
	filter := model.NewFilter()
	startTime, _ := time.Parse(time.RFC3339, "2024-02-12T00:00:00Z")
	filter.BeginTime = startTime
	endTime, _ := time.Parse(time.RFC3339, "2024-02-12T23:59:59Z")
	filter.EndTime = endTime
	filter.Protocol = model.PROTOCOL_ICMP
	filter.SrcIp = "fe80::aa28:fadf:ab5a:bff7"
	filter.SrcPort = 19 // will be ignored since Protocol = ICMP
	filter.DstIp = "fe80::17:b601:2ab3:4397"
	filter.DstPort = 34515 // will be ignored since Protocol = ICMP

	actual := CreateBpf(filter, true)
	expected := "((icmp or icmp6) and host fe80::aa28:fadf:ab5a:bff7 and host fe80::17:b601:2ab3:4397) or (vlan and (icmp or icmp6) and host fe80::aa28:fadf:ab5a:bff7 and host fe80::17:b601:2ab3:4397)"
	assert.Equal(tester, expected, actual)
}

func TestToStreamWithDecodeFailure(tester *testing.T) {
	// Truncated Ethernet packet (3 bytes is less than the 14-byte Ethernet header)
	rawBytes := []byte{0x01, 0x02, 0x03}
	p := gopacket.NewPacket(rawBytes, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true})
	p.Metadata().CaptureInfo = gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(rawBytes),
		Length:        len(rawBytes),
	}

	assert.NotNil(tester, p.ErrorLayer())

	// Test ToStream does not fail on DecodeFailure packet
	reader, size, err := ToStream([]gopacket.Packet{p})
	assert.Nil(tester, err)
	assert.Greater(tester, size, 0)
	assert.NotNil(tester, reader)

	// Test parseData properly sets DecodeFailure type and Error field
	modelPacket := model.NewPacket(0)
	parseData(p, modelPacket, false)
	assert.Equal(tester, "DecodeFailure", modelPacket.Type)
	assert.NotEmpty(tester, modelPacket.Error)
}

func TestParseRawIPv4Packet(tester *testing.T) {
	// Raw IPv4 SYN packet:
	// 45 00 00 28 00 01 00 00  40 06 B8 24 C0 A8 00 01
	// 01 01 01 01 88 BE D9 48  00 00 07 8C 00 00 00 00
	// 50 02 20 00 63 A4 00 00
	rawBytes := []byte{
		0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00,
		0x40, 0x06, 0xb8, 0x24, 0xc0, 0xa8, 0x00, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x88, 0xbe, 0xd9, 0x48,
		0x00, 0x00, 0x07, 0x8c, 0x00, 0x00, 0x00, 0x00,
		0x50, 0x02, 0x20, 0x00, 0x63, 0xa4, 0x00, 0x00,
	}

	// When initially parsed as Ethernet (which yields EtherType 49320 DecodeFailure)
	p := gopacket.NewPacket(rawBytes, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true})
	p.Metadata().CaptureInfo = gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(rawBytes),
		Length:        len(rawBytes),
	}

	// parseData should recover and decode it as IPv4 TCP SYN packet
	modelPacket := model.NewPacket(0)
	parseData(p, modelPacket, false)

	assert.Empty(tester, modelPacket.Error)
	assert.Equal(tester, "TCP", modelPacket.Type)
	assert.Equal(tester, "192.168.0.1", modelPacket.SrcIp)
	assert.Equal(tester, "1.1.1.1", modelPacket.DstIp)
	assert.Equal(tester, 35006, modelPacket.SrcPort)
	assert.Equal(tester, 55624, modelPacket.DstPort)
	assert.Contains(tester, modelPacket.Flags, "SYN")

	// ToStream should properly detect IPv4 link type
	reader, size, err := ToStream([]gopacket.Packet{p})
	assert.NoError(tester, err)
	assert.Greater(tester, size, 0)
	assert.NotNil(tester, reader)
}

func TestParsePcapFilePanicRecovery(tester *testing.T) {
	path := "test_resources/so-pcap.1575817346"
	err := parsePcapFile(path, "", func(index int, pcapPacket gopacket.Packet) bool {
		panic("simulated decoder panic")
	})
	assert.Error(tester, err)
	assert.Contains(tester, err.Error(), "packet decode panic: simulated decoder panic")
}
