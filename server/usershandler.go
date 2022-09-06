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
  "regexp"
)

type UsersHandler struct {
  web.BaseHandler
  server *Server
}

func NewUsersHandler(srv *Server) *UsersHandler {
  handler := &UsersHandler{}
  handler.Host = srv.Host
  handler.server = srv
  handler.Impl = handler
  return handler
}

func (usersHandler *UsersHandler) HandleNow(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  if usersHandler.server.Userstore == nil {
    if usersHandler.server.Config.DeveloperEnabled {
      return http.StatusOK, nil, nil
    }
    return http.StatusMethodNotAllowed, nil, errors.New("Users module not enabled")
  }

  switch request.Method {
  case http.MethodGet:
    return usersHandler.get(ctx, writer, request)
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (usersHandler *UsersHandler) get(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  users, err := usersHandler.server.Userstore.GetUsers(ctx)
  if err != nil {
    return http.StatusBadRequest, nil, err
  }
  return http.StatusOK, users, nil
}

func (usersHandler *UsersHandler) delete(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  id := usersHandler.GetPathParameter(request.URL.Path, 2)
  safe, _ := regexp.MatchString(`^[A-Za-z0-9-]+$`, id)
  if !safe {
    return http.StatusBadRequest, nil, errors.New("Invalid id")
  }
  err := usersHandler.server.Userstore.DeleteUser(ctx, id)
  if err != nil {
    return http.StatusBadRequest, nil, err
  }
  return http.StatusOK, nil, nil
}
