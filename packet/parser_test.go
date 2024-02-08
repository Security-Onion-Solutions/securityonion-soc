// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
	filter.SrcIp = "185.47.63.113"
	filter.SrcPort = 19
	filter.DstIp = "176.126.243.198"
	filter.DstPort = 34515

	packets, perr := ParseRawPcap(path, 999, filter)
	assert.Nil(tester, perr)
	assert.Len(tester, packets, 12)

	reader, err := ToStream(packets)

	assert.Nil(tester, err)
	pcap_length := 14122 // correlates to so-pcap test file
	bytes := make([]byte, 32768)
	count, err := reader.Read(bytes)
	assert.Nil(tester, err)
	assert.Equal(tester, pcap_length, count)
}

func TestParseAndStreamFail(tester *testing.T) {
	path := "test_resources/so-pcap.nonexistent"
	filter := model.NewFilter()

	_, perr := ParseRawPcap(path, 999, filter)
	assert.ErrorContains(tester, perr, "No such file")
}
