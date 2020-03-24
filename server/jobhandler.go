// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package server

import (
  "errors"
  "net/http"
  "strconv"
  "github.com/sensoroni/sensoroni/model"
  "github.com/sensoroni/sensoroni/web"
)

type JobHandler struct {
  web.BaseHandler
  server 		*Server
}

func NewJobHandler(srv *Server) *JobHandler {
  handler := &JobHandler {}
  handler.Host = srv.Host
  handler.server = srv
  handler.Impl = handler
  return handler
}

func (jobHandler *JobHandler) HandleNow(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  switch request.Method {
    case http.MethodGet: return jobHandler.get(writer, request)
    case http.MethodPost: return jobHandler.post(writer, request)
    case http.MethodPut: return jobHandler.put(writer, request)
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (jobHandler *JobHandler) get(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  statusCode := http.StatusBadRequest
  jobId, err := strconv.ParseInt(request.URL.Query().Get("jobId"), 10, 32)
  job := jobHandler.server.Datastore.GetJob(int(jobId))
  if job != nil {
    statusCode = http.StatusOK
  } else {
    statusCode = http.StatusNotFound
  }
  return statusCode, job, err
}

func (jobHandler *JobHandler) post(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  statusCode := http.StatusBadRequest
  job := jobHandler.server.Datastore.CreateJob()
  err := jobHandler.ReadJson(request, job)
  if err == nil {
    err = jobHandler.server.Datastore.AddJob(job)
    if err == nil {
      jobHandler.Host.Broadcast("job", job)
      statusCode = http.StatusCreated
    } else {
      statusCode = http.StatusNotFound
    }
  } else {
    statusCode = http.StatusBadRequest
  }
  return statusCode, job, err
}

func (jobHandler *JobHandler) put(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  statusCode := http.StatusBadRequest
  job := model.NewJob()
  err := jobHandler.ReadJson(request, job)
  if err == nil {
    err = jobHandler.server.Datastore.UpdateJob(job)
    if err == nil {
      jobHandler.Host.Broadcast("job", job)
      statusCode = http.StatusOK
    } else {
      statusCode = http.StatusNotFound
    }
  } else {
    statusCode = http.StatusBadRequest
  }
  return statusCode, job, err
}