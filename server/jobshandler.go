// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
  "context"
  "errors"
  "github.com/security-onion-solutions/securityonion-soc/json"
  "github.com/security-onion-solutions/securityonion-soc/web"
  "net/http"
)

type JobsHandler struct {
  web.BaseHandler
  server *Server
}

func NewJobsHandler(srv *Server) *JobsHandler {
  handler := &JobsHandler{}
  handler.Host = srv.Host
  handler.server = srv
  handler.Impl = handler
  return handler
}

func (jobsHandler *JobsHandler) HandleNow(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  switch request.Method {
  case http.MethodGet:
    return jobsHandler.get(ctx, writer, request)
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (jobsHandler *JobsHandler) get(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  kind := request.URL.Query().Get("kind")
  paramsStr := request.URL.Query().Get("parameters")
  var params map[string]interface{}
  if paramsStr != "" {
    err := json.LoadJson([]byte(paramsStr), &params)
    if err != nil {
      return http.StatusBadRequest, nil, err
    }
  }
  return http.StatusOK, jobsHandler.server.Datastore.GetJobs(ctx, kind, params), nil
}
