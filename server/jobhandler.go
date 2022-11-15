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
  "strconv"
)

type JobHandler struct {
  web.BaseHandler
  server *Server
}

func NewJobHandler(srv *Server) *JobHandler {
  handler := &JobHandler{}
  handler.Host = srv.Host
  handler.server = srv
  handler.Impl = handler
  return handler
}

func (jobHandler *JobHandler) HandleNow(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  switch request.Method {
  case http.MethodGet:
    return jobHandler.get(ctx, writer, request)
  case http.MethodPost:
    return jobHandler.post(ctx, writer, request)
  case http.MethodPut:
    return jobHandler.put(ctx, writer, request)
  case http.MethodDelete:
    return jobHandler.delete(ctx, writer, request)
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (jobHandler *JobHandler) get(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  statusCode := http.StatusBadRequest
  jobId, err := strconv.ParseInt(request.URL.Query().Get("jobId"), 10, 32)
  job := jobHandler.server.Datastore.GetJob(ctx, int(jobId))
  if job != nil {
    statusCode = http.StatusOK
  } else {
    statusCode = http.StatusNotFound
  }
  return statusCode, job, err
}

func (jobHandler *JobHandler) post(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  statusCode := http.StatusBadRequest
  job := jobHandler.server.Datastore.CreateJob(ctx)
  err := jobHandler.ReadJson(request, job)
  if err == nil {
    err = jobHandler.server.Datastore.AddJob(ctx, job)
    if err == nil {
      jobHandler.Host.Broadcast("job", "jobs", job)
      statusCode = http.StatusCreated
    }
  }
  return statusCode, job, err
}

func (jobHandler *JobHandler) put(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  statusCode := http.StatusBadRequest
  job := model.NewJob()
  err := jobHandler.ReadJson(request, job)
  if err == nil {
    err = jobHandler.server.Datastore.UpdateJob(ctx, job)
    if err == nil {
      jobHandler.Host.Broadcast("job", "jobs", job)
      statusCode = http.StatusOK
    } else {
      statusCode = http.StatusNotFound
    }
  } else {
    statusCode = http.StatusBadRequest
  }
  return statusCode, job, err
}

func (jobHandler *JobHandler) delete(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  id := jobHandler.GetPathParameter(request.URL.Path, 2)
  safe, _ := regexp.MatchString(`^[0-9-]+$`, id)
  if !safe {
    return http.StatusBadRequest, nil, errors.New("Invalid id")
  }
  statusCode := http.StatusBadRequest

  jobId, err := strconv.Atoi(id)
  if err == nil {
    var job *model.Job
    job, err = jobHandler.server.Datastore.DeleteJob(ctx, int(jobId))
    if err == nil {
      jobHandler.Host.Broadcast("job", "jobs", job)
      statusCode = http.StatusOK
    }
  }

  return statusCode, nil, err
}
