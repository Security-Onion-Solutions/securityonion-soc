// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package web

import (
	"time"

	"github.com/gorilla/websocket"
)

type Connection struct {
	websocket    *websocket.Conn
	lastPingTime time.Time
	ip           string
	userId       string
}

func NewConnection(userId string, wsConn *websocket.Conn, ip string) *Connection {
	conn := &Connection{
		websocket: wsConn,
		ip:        ip,
		userId:    userId,
	}
	conn.UpdatePingTime()
	return conn
}

func (connection *Connection) UpdatePingTime() {
	connection.lastPingTime = time.Now()
}
