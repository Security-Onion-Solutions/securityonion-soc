// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
  "context"
  "errors"
  "github.com/security-onion-solutions/securityonion-soc/web"
  "net/http"
)

type RolesHandler struct {
  web.BaseHandler
  server *Server
}

func NewRolesHandler(srv *Server) *RolesHandler {
  handler := &RolesHandler{}
  handler.Host = srv.Host
  handler.server = srv
  handler.Impl = handler
  return handler
}

func (rolesHandler *RolesHandler) HandleNow(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  if rolesHandler.server.Rolestore == nil {
    return http.StatusMethodNotAllowed, nil, errors.New("Roles module not enabled")
  }

  switch request.Method {
  case http.MethodGet:
    return rolesHandler.get(ctx, writer, request)
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (rolesHandler *RolesHandler) get(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  roles := rolesHandler.server.Rolestore.GetRoles(ctx)
  return http.StatusOK, roles, nil
}
