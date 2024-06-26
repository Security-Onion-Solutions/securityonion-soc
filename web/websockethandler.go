// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package web

import (
	"errors"
	"net/http"

	"github.com/apex/log"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
	"github.com/security-onion-solutions/securityonion-soc/json"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

type WebSocketHandler struct {
	Host *Host
}

func NewWebSocketHandler(host *Host) *WebSocketHandler {
	handler := &WebSocketHandler{}
	handler.Host = host

	return handler
}

func RegisterWebSocketRoutes(host *Host, r chi.Router) {
	handler := &WebSocketHandler{
		Host: host,
	}

	r.Group(func(r chi.Router) {
		r.Use(Middleware(host, true))

		r.Get("/ws", handler.Handle)
	})
}

func (webSocketHandler *WebSocketHandler) Handle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ip := GetSourceIp(r)

	var user *model.User
	var ok bool
	user, ok = ctx.Value(ContextKeyRequestor).(*model.User)
	if !ok {
		log.WithFields(log.Fields{
			"messageRemoteAddr": r.RemoteAddr,
			"messageSourceIp":   ip,
			"messagePath":       r.URL.Path,
		}).Warn("User does not exist in context")
		Respond(w, r, http.StatusBadRequest, errors.New("User does not exist in context; unable to complete websocket"))

		return
	}

	upgrader := websocket.Upgrader{}
	connection, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			"messageRemoteAddr": r.RemoteAddr,
			"messageSourceIp":   ip,
			"messagePath":       r.URL.Path,
		}).Warn("Failed to upgrade websocket")
		Respond(w, r, http.StatusBadRequest, err)

		return
	}

	log.WithFields(log.Fields{
		"messageRemoteAddr": r.RemoteAddr,
		"messageSourceIp":   ip,
		"messagePath":       r.URL.Path,
	}).Info("WebSocket connected")

	conn := webSocketHandler.Host.AddConnection(user, connection, ip)

	defer connection.Close()
	for {
		messageType, messageBytes, err := connection.ReadMessage()
		if err != nil {
			break
		}
		log.WithFields(log.Fields{
			"messageRemoteAddr": r.RemoteAddr,
			"messageSourceIp":   ip,
			"messagePath":       r.URL.Path,
			"messageContent":    string(messageBytes),
			"messageType":       messageType,
		}).Info("WebSocket message received")

		msg := &WebSocketMessage{}
		json.LoadJson(messageBytes, msg)
		webSocketHandler.handleMessage(msg, conn)
	}
	log.WithFields(log.Fields{
		"messageRemoteAddr": r.RemoteAddr,
		"messageSourceIp":   ip,
		"messagePath":       r.URL.Path,
	}).Info("WebSocket disconnected")
	webSocketHandler.Host.RemoveConnection(connection)

	Respond(nil, r, http.StatusOK, nil)
}

func (webSocketHandler *WebSocketHandler) handleMessage(msg *WebSocketMessage, conn *Connection) {
	if msg.Kind == "Ping" {
		conn.UpdatePingTime()
	}
}
