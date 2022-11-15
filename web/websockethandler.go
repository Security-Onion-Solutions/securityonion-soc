// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package web

import (
  "context"
  "errors"
  "github.com/apex/log"
  "github.com/gorilla/websocket"
  "github.com/security-onion-solutions/securityonion-soc/json"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "net/http"
)

type WebSocketHandler struct {
  BaseHandler
}

func NewWebSocketHandler(host *Host) *WebSocketHandler {
  handler := &WebSocketHandler{}
  handler.Host = host
  handler.Impl = handler
  return handler
}

func (webSocketHandler *WebSocketHandler) HandleNow(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  upgrader := websocket.Upgrader{}
  connection, err := upgrader.Upgrade(writer, request, nil)
  ip := webSocketHandler.Host.GetSourceIp(request)
  if err != nil {
    log.WithError(err).WithFields(log.Fields{
      "remoteAddr": request.RemoteAddr,
      "sourceIp":   ip,
      "path":       request.URL.Path,
    }).Warn("Failed to upgrade websocket")
    return http.StatusBadRequest, nil, errors.New("Unable to upgrade request to websocket")
  }

  var user *model.User
  var ok bool
  user, ok = ctx.Value(ContextKeyRequestor).(*model.User)
  if !ok {
    log.WithError(err).WithFields(log.Fields{
      "remoteAddr": request.RemoteAddr,
      "sourceIp":   ip,
      "path":       request.URL.Path,
    }).Warn("User does not exist in context")
    return http.StatusBadRequest, nil, errors.New("User does not exist in context; unable to complete websocket")
  }

  log.WithFields(log.Fields{
    "remoteAddr": request.RemoteAddr,
    "sourceIp":   ip,
    "path":       request.URL.Path,
  }).Info("WebSocket connected")
  conn := webSocketHandler.Host.AddConnection(user, connection, ip)

  defer connection.Close()
  for {
    messageType, messageBytes, err := connection.ReadMessage()
    if err != nil {
      break
    }
    log.WithFields(log.Fields{
      "remoteAddr": request.RemoteAddr,
      "sourceIp":   ip,
      "path":       request.URL.Path,
      "msg":        string(messageBytes),
      "type":       messageType,
    }).Info("WebSocket message received")

    msg := &WebSocketMessage{}
    json.LoadJson(messageBytes, msg)
    webSocketHandler.handleMessage(msg, conn)
  }
  log.WithFields(log.Fields{
    "remoteAddr": request.RemoteAddr,
    "sourceIp":   ip,
    "path":       request.URL.Path,
  }).Info("WebSocket disconnected")
  webSocketHandler.Host.RemoveConnection(connection)
  return http.StatusOK, nil, nil
}

func (webSocketHandler *WebSocketHandler) handleMessage(msg *WebSocketMessage, conn *Connection) {
  if msg.Kind == "Ping" {
    conn.UpdatePingTime()
  }
}
