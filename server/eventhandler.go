// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
  "context"
  "encoding/json"
  "errors"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/web"
  "net/http"
)

type EventHandler struct {
  web.BaseHandler
  server *Server
}

func NewEventHandler(srv *Server) *EventHandler {
  handler := &EventHandler{}
  handler.Host = srv.Host
  handler.server = srv
  handler.Impl = handler
  return handler
}

func (eventHandler *EventHandler) HandleNow(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  if eventHandler.server.Eventstore != nil {
    switch request.Method {
    case http.MethodGet:
      return eventHandler.get(ctx, writer, request)
    case http.MethodPost:
      obj := eventHandler.GetPathParameter(request.URL.Path, 2)
      if obj == "ack" {
        return eventHandler.ack(ctx, writer, request)
      }
    }
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (eventHandler *EventHandler) get(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  var results *model.EventSearchResults
  statusCode := http.StatusBadRequest

  err := request.ParseForm()
  if err == nil {
    criteria := model.NewEventSearchCriteria()
    err = criteria.Populate(request.Form.Get("query"),
      request.Form.Get("range"),
      request.Form.Get("format"),
      request.Form.Get("zone"),
      request.Form.Get("metricLimit"),
      request.Form.Get("eventLimit"))
    if err == nil {
      results, err = eventHandler.server.Eventstore.Search(ctx, criteria)
      if err == nil {
        statusCode = http.StatusOK
      } else {
        statusCode = http.StatusInternalServerError
      }
    }
  }
  return statusCode, results, err
}

func (eventHandler *EventHandler) ack(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  var results *model.EventUpdateResults
  statusCode := http.StatusBadRequest

  ackCriteria := model.NewEventAckCriteria()
  err := json.NewDecoder(request.Body).Decode(&ackCriteria)
  if err == nil {
    results, err = eventHandler.server.Eventstore.Acknowledge(ctx, ackCriteria)
    if err == nil {
      statusCode = http.StatusOK
    } else {
      statusCode = http.StatusBadRequest
    }
  }
  return statusCode, results, err
}
