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

type ConfigHandler struct {
  web.BaseHandler
  server *Server
}

func NewConfigHandler(srv *Server) *ConfigHandler {
  handler := &ConfigHandler{}
  handler.Host = srv.Host
  handler.server = srv
  handler.Impl = handler
  return handler
}

func (configHandler *ConfigHandler) HandleNow(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  if configHandler.server.Configstore == nil {
    return http.StatusMethodNotAllowed, nil, errors.New("Config module not enabled")
  }

  switch request.Method {
  case http.MethodGet:
    return configHandler.get(ctx, writer, request)
  case http.MethodPost:
    return configHandler.put(ctx, writer, request)
  case http.MethodPut:
    return configHandler.put(ctx, writer, request)
  case http.MethodDelete:
    return configHandler.delete(ctx, writer, request)
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (configHandler *ConfigHandler) get(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  settings, err := configHandler.server.Configstore.GetSettings(ctx)
  if err != nil {
    return http.StatusBadRequest, nil, err
  }
  return http.StatusOK, settings, nil
}

func (configHandler *ConfigHandler) put(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  var err error
  op := configHandler.GetPathParameter(request.URL.Path, 2)
  if op == "sync" {
    err = configHandler.server.Configstore.SyncSettings(ctx)
  } else {
    setting := model.Setting{}
    err = json.NewDecoder(request.Body).Decode(&setting)
    if err == nil {
      if !model.IsValidSettingId(setting.Id) || (setting.NodeId != "" && !model.IsValidMinionId(setting.NodeId)) {
        err = errors.New("Invalid setting")
      } else {
        remove := false
        err = configHandler.server.Configstore.UpdateSetting(ctx, &setting, remove)
      }
    }
  }

  if err != nil {
    return http.StatusBadRequest, nil, err
  }
  return http.StatusOK, nil, nil
}

func (configHandler *ConfigHandler) delete(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  id := request.URL.Query().Get("id")
  minion := request.URL.Query().Get("minion")
  setting := model.NewSetting(id)
  setting.NodeId = minion

  var err error
  if !model.IsValidSettingId(setting.Id) || (setting.NodeId != "" && !model.IsValidMinionId(setting.NodeId)) {
    err = errors.New("Invalid setting")
  } else {
    remove := true
    err = configHandler.server.Configstore.UpdateSetting(ctx, setting, remove)
  }
  if err != nil {
    return http.StatusBadRequest, nil, err
  }
  return http.StatusOK, nil, nil
}
