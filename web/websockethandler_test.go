// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package web

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestHandlePingMessage(tester *testing.T) {
	webSocketHandler := NewWebSocketHandler(nil)
	conn := NewConnection(nil, nil, "")
	oldPingTime := conn.lastPingTime
	time.Sleep(3 * time.Millisecond)
	msg := &WebSocketMessage{Kind: "Ping"}
	webSocketHandler.handleMessage(msg, conn)
	newPingTime := conn.lastPingTime
	assert.GreaterOrEqual(tester, newPingTime.Sub(oldPingTime).Milliseconds(), int64(3))
}
