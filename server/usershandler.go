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
  case http.MethodPost:
    return usersHandler.post(ctx, writer, request)
  case http.MethodPut:
    return usersHandler.put(ctx, writer, request)
  case http.MethodDelete:
    return usersHandler.delete(ctx, writer, request)
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

func (usersHandler *UsersHandler) post(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  var err error

  id := usersHandler.GetPathParameter(request.URL.Path, 2)
  if id == "" {
    user := model.NewUser()
    err = usersHandler.ReadJson(request, user)
    if err == nil {
      err = usersHandler.server.AdminUserstore.AddUser(ctx, user)
    }
  } else {
    safe, _ := regexp.MatchString(`^[A-Za-z0-9-]+$`, id)
    if !safe {
      return http.StatusBadRequest, nil, errors.New("Invalid id")
    }

    object := usersHandler.GetPathParameter(request.URL.Path, 3)
    switch object {
    case "role":
      role := usersHandler.GetPathParameter(request.URL.Path, 4)
      safe, _ := regexp.MatchString(`^[A-Za-z0-9-_]+$`, role)
      if !safe {
        err = errors.New("Invalid role")
      } else {
        err = usersHandler.server.AdminUserstore.AddRole(ctx, id, role)
      }
    default:
      err = errors.New("Invalid object specified for deletion")
    }
  }

  if err != nil {
    return http.StatusBadRequest, nil, err
  }
  return http.StatusOK, nil, nil
}

func (usersHandler *UsersHandler) delete(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  id := usersHandler.GetPathParameter(request.URL.Path, 2)
  safe, _ := regexp.MatchString(`^[A-Za-z0-9-]+$`, id)
  if !safe {
    return http.StatusBadRequest, nil, errors.New("Invalid id")
  }

  object := usersHandler.GetPathParameter(request.URL.Path, 3)
  var err error
  switch object {
  case "role":
    role := usersHandler.GetPathParameter(request.URL.Path, 4)
    safe, _ := regexp.MatchString(`^[A-Za-z0-9-_]+$`, role)
    if !safe {
      err = errors.New("Invalid role")
    } else {
      err = usersHandler.server.AdminUserstore.DeleteRole(ctx, id, role)
    }
  case "":
    err = usersHandler.server.AdminUserstore.DeleteUser(ctx, id)
  default:
    err = errors.New("Invalid object specified for deletion")
  }

  if err != nil {
    return http.StatusBadRequest, nil, err
  }
  return http.StatusOK, nil, nil
}

func (usersHandler *UsersHandler) put(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  var err error
  id := usersHandler.GetPathParameter(request.URL.Path, 2)
  safe, _ := regexp.MatchString(`^[A-Za-z0-9-]+$`, id)
  if !safe {
    return http.StatusBadRequest, nil, errors.New("Invalid id")
  }

  if id == "sync" {
    err = usersHandler.server.AdminUserstore.SyncUsers(ctx)
  } else {
    object := usersHandler.GetPathParameter(request.URL.Path, 3)
    switch object {
    case "enable":
      err = usersHandler.server.AdminUserstore.EnableUser(ctx, id)
    case "disable":
      err = usersHandler.server.AdminUserstore.DisableUser(ctx, id)
    case "password":
      user := model.NewUser()
      err = usersHandler.ReadJson(request, user)
      if err == nil {
        err = usersHandler.server.AdminUserstore.ResetPassword(ctx, id, user.Password)
      }
    case "":
      user := model.NewUser()
      err = usersHandler.ReadJson(request, user)
      if err == nil {
        user.Id = id
        err = usersHandler.server.AdminUserstore.UpdateProfile(ctx, user)
      }
    default:
      err = errors.New("Invalid object specified for deletion")
    }
  }

  if err != nil {
    return http.StatusBadRequest, nil, err
  }
  return http.StatusOK, nil, nil
}
