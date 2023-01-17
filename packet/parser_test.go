// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

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
