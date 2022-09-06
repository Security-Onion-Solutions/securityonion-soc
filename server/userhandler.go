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
  "regexp"
)

type UserHandler struct {
  web.BaseHandler
  server *Server
}

func NewUserHandler(srv *Server) *UserHandler {
  handler := &UserHandler{}
  handler.Host = srv.Host
  handler.server = srv
  handler.Impl = handler
  return handler
}

func (userHandler *UserHandler) HandleNow(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  if userHandler.server.Userstore == nil {
    if userHandler.server.Config.DeveloperEnabled {
      return http.StatusOK, nil, nil
    }
    return http.StatusMethodNotAllowed, nil, errors.New("Users module not enabled")
  }

  switch request.Method {
  case http.MethodGet:
    return userHandler.get(ctx, writer, request)
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (userHandler *UserHandler) get(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  id := userHandler.GetPathParameter(request.URL.Path, 2)
  safe, _ := regexp.MatchString(`^[A-Za-z0-9-]+$`, id)
  if !safe {
    return http.StatusBadRequest, nil, errors.New("Invalid id")
  }
  user, err := userHandler.server.Userstore.GetUser(ctx, id)
  if err != nil {
    return http.StatusBadRequest, nil, err
  }
  return http.StatusOK, user, nil
}

func (userHandler *UserHandler) put(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  id := userHandler.GetPathParameter(request.URL.Path, 2)
  safe, _ := regexp.MatchString(`^[A-Za-z0-9-]+$`, id)
  if !safe {
    return http.StatusBadRequest, nil, errors.New("Invalid id")
  }
  user := model.NewUser()
  err := userHandler.ReadJson(request, user)
  if err != nil {
    return http.StatusBadRequest, nil, errors.New("Invalid user object")
  }
  err = userHandler.server.Userstore.UpdateUser(ctx, id, user)
  if err != nil {
    return http.StatusBadRequest, nil, err
  }
  return http.StatusOK, nil, nil
}
