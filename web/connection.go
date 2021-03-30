// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package web

import (
  "time"
  "github.com/gorilla/websocket"
)

type Connection struct {
  websocket     *websocket.Conn
  lastPingTime  time.Time
} 

func NewConnection(wsConn *websocket.Conn) *Connection {
  conn := &Connection{
    websocket: wsConn,
  }
  conn.UpdatePingTime()
  return conn
}

func (connection *Connection) IsAuthorized(kind string) bool {
  return true
}

func (connection *Connection) UpdatePingTime() {
  connection.lastPingTime = time.Now()
}