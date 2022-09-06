// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
  "context"
  "errors"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/web"
  "net/http"
)

type GridMembersHandler struct {
  web.BaseHandler
  server *Server
}

func NewGridMembersHandler(srv *Server) *GridMembersHandler {
  handler := &GridMembersHandler{}
  handler.Host = srv.Host
  handler.server = srv
  handler.Impl = handler
  return handler
}

func (gridMembersHandler *GridMembersHandler) HandleNow(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  if gridMembersHandler.server.GridMembersstore == nil {
    return http.StatusMethodNotAllowed, nil, errors.New("GridMembers module not enabled")
  }

  switch request.Method {
  case http.MethodGet:
    return gridMembersHandler.get(ctx, writer, request)
  case http.MethodPost:
    return gridMembersHandler.post(ctx, writer, request)
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (gridMembersHandler *GridMembersHandler) get(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  members, err := gridMembersHandler.server.GridMembersstore.GetMembers(ctx)
  if err != nil {
    return http.StatusBadRequest, nil, err
  }
  return http.StatusOK, members, nil
}

func (gridMembersHandler *GridMembersHandler) post(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  var err error

  id := gridMembersHandler.GetPathParameter(request.URL.Path, 2)
  if !model.IsValidMinionId(id) {
    err = errors.New("Invalid minion ID")
  }

  op := gridMembersHandler.GetPathParameter(request.URL.Path, 3)
  if op != "add" && op != "reject" && op != "delete" {
    err = errors.New("Invalid operation")
  }

  if err == nil {
    err = gridMembersHandler.server.GridMembersstore.ManageMember(ctx, op, id)
  }

  if err != nil {
    return http.StatusBadRequest, nil, err
  }
  return http.StatusOK, nil, nil
}
