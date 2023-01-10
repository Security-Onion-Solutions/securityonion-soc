// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

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
  roles, err := rolesHandler.server.Rolestore.GetAssignments(ctx)
  if err != nil {
    return http.StatusBadRequest, nil, err
  }
  return http.StatusOK, roles, nil
}
