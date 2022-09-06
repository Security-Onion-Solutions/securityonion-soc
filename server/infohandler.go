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
  "os"
)

type InfoHandler struct {
  web.BaseHandler
  server    *Server
  timezones []string
}

func NewInfoHandler(srv *Server) *InfoHandler {
  handler := &InfoHandler{}
  handler.Host = srv.Host
  handler.server = srv
  handler.Impl = handler
  handler.timezones = srv.GetTimezones()
  return handler
}

func (infoHandler *InfoHandler) HandleNow(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  switch request.Method {
  case http.MethodGet:
    return infoHandler.get(ctx, writer, request)
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (infoHandler *InfoHandler) get(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  var err error
  var info *model.Info
  if user, ok := request.Context().Value(web.ContextKeyRequestor).(*model.User); ok {
    var srvToken string
    srvToken, err = model.GenerateSrvToken(infoHandler.server.Config.SrvKeyBytes, user.Id, infoHandler.server.Config.SrvExpSeconds)
    if err == nil {
      info = &model.Info{
        Version:        infoHandler.Host.Version,
        License:        "Elastic License 2.0 (ELv2)",
        Parameters:     &infoHandler.server.Config.ClientParams,
        ElasticVersion: os.Getenv("ELASTIC_VERSION"),
        WazuhVersion:   os.Getenv("WAZUH_VERSION"),
        UserId:         user.Id,
        Timezones:      infoHandler.timezones,
        SrvToken:       srvToken,
      }
    }
  } else {
    err = errors.New("Unable to determine logged in user from context")
  }
  return http.StatusOK, info, err
}
