// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package web

import (
  "github.com/gorilla/websocket"
  "time"
)

type Connection struct {
  websocket    *websocket.Conn
  lastPingTime time.Time
  ip           string
}

func NewConnection(wsConn *websocket.Conn, ip string) *Connection {
  conn := &Connection{
    websocket: wsConn,
    ip:        ip,
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
