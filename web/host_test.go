// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package web

import (
  "testing"
	"github.com/gorilla/websocket"
)

func TestAddRemoveConnection(tester *testing.T) {
  host := NewHost("http://some.where/path", "/tmp/foo", "unit test")
	conn := &websocket.Conn{}
	tester.Run("testing add connection", func(t *testing.T) {
	  host.AddConnection(conn);
		if len(host.connections) != 1 {
			tester.Errorf("begin expected %d but got %d", 1, len(host.connections))
		}
	})
	tester.Run("testing remove connection", func(t *testing.T) {
		host.RemoveConnection(conn);
		if len(host.connections) != 0 {
			t.Errorf("final expected %d but got %d", 0, len(host.connections))
		}
	})
}