// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package packet

import (
	"io/ioutil"
	"os"
	"testing"

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
	filename := "parser_resource.pcap"
	tmpFile, err := ioutil.TempFile("", "unwrap-test")
	assert.Nil(tester, err, "Unable to execute test due to bad temp file")
	unwrappedFilename := tmpFile.Name()
	os.Remove(unwrappedFilename)       // Don't need the actual file right now, delete it. We only need a filename.
	defer os.Remove(unwrappedFilename) // Delete it again after test finishes.
	unwrapped := UnwrapPcap(filename, unwrappedFilename)
	assert.True(tester, unwrapped)
}
