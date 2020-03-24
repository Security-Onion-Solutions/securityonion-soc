// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package packet

import (
  "testing"
  "github.com/google/gopacket"
  "github.com/sensoroni/sensoroni/model"
)

func TestOverrideType(tester *testing.T) {
  p := model.NewPacket(1)
  p.Type = "foo"
  overrideType(p, gopacket.LayerTypePayload)
  if p.Type != "foo" {
    tester.Errorf("expected Type %s but got %s", "foo", p.Type) 
  }
  overrideType(p, gopacket.LayerTypeFragment)
  if p.Type != "Fragment" {
    tester.Errorf("expected Type %s but got %s", "Fragment", p.Type) 
  }
}
