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
	"errors"
	"net/http"
  "github.com/apex/log"
  "github.com/gorilla/websocket"
  "github.com/security-onion-solutions/securityonion-soc/json"
)

type WebSocketHandler struct {
	BaseHandler
}

func NewWebSocketHandler(host *Host) *WebSocketHandler {
	handler := &WebSocketHandler {}
	handler.Host = host
	handler.Impl = handler
	return handler
}

func (webSocketHandler *WebSocketHandler) HandleNow(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  upgrader := websocket.Upgrader{}
  connection, err := upgrader.Upgrade(writer, request, nil)
  if err != nil {
    log.WithError(err).WithFields(log.Fields{
      "sourceIp": request.RemoteAddr,
      "path": request.URL.Path,
    }).Warn("Failed to upgrade websocket")
    return http.StatusBadRequest, nil, errors.New("Unable to upgrade request to websocket")
  }

  log.WithFields(log.Fields{
    "sourceIp": request.RemoteAddr,
    "path": request.URL.Path,
  }).Info("WebSocket connected")
  conn := webSocketHandler.Host.AddConnection(connection)

  defer connection.Close()
  for {
    messageType, messageBytes, err := connection.ReadMessage()
    if err != nil {
      break
    }
    log.WithFields(log.Fields{
      "sourceIp": request.RemoteAddr,
      "path": request.URL.Path,
      "msg": string(messageBytes),
      "type": messageType,
    }).Info("WebSocket message received")

    msg := &WebSocketMessage{}
    json.LoadJson(messageBytes, msg)
    webSocketHandler.handleMessage(msg, conn)
  }
  log.WithFields(log.Fields{
    "sourceIp": request.RemoteAddr,
    "path": request.URL.Path,
  }).Info("WebSocket disconnected")
  webSocketHandler.Host.RemoveConnection(connection)
	return http.StatusOK, nil, nil
}

func (webSocketHandler *WebSocketHandler) handleMessage(msg *WebSocketMessage, conn *Connection) {
  if msg.Kind == "Ping" {
    conn.UpdatePingTime();
  }
}