// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
  "context"
  "errors"
  "github.com/security-onion-solutions/securityonion-soc/server"
  "github.com/security-onion-solutions/securityonion-soc/web"
  "net/http"
  "strconv"
)

type JobLookupHandler struct {
  web.BaseHandler
  server *server.Server
  store  *ElasticEventstore
}

func NewJobLookupHandler(srv *server.Server, store *ElasticEventstore) *JobLookupHandler {
  handler := &JobLookupHandler{}
  handler.Host = srv.Host
  handler.server = srv
  handler.BaseHandler.Impl = handler
  handler.store = store
  return handler
}

func (handler *JobLookupHandler) HandleNow(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  switch request.Method {
  case http.MethodGet:
    return handler.get(ctx, writer, request)
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (handler *JobLookupHandler) get(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  statusCode := http.StatusBadRequest

  timestampStr := request.URL.Query().Get("time") // Elastic doc timestamp

  idField := "_id"
  idValue := request.URL.Query().Get("esid") // Elastic doc ID
  if len(idValue) == 0 {
    idValue = request.URL.Query().Get("ncid") // Network community ID
    idField = "network.community_id"
  }

  job := handler.server.Datastore.CreateJob(ctx)
  err := handler.store.PopulateJobFromDocQuery(ctx, idField, idValue, timestampStr, job)
  if err == nil {
    err = handler.server.Datastore.AddPivotJob(ctx, job)
    if err == nil {
      handler.Host.Broadcast("job", "jobs", job)
      statusCode = http.StatusOK
      redirectUrl := handler.server.Config.BaseUrl + "#/job/" + strconv.Itoa(job.Id)
      http.Redirect(writer, request, redirectUrl, http.StatusFound)
    }
  } else {
    statusCode = http.StatusNotFound
    http.Error(writer, "Elasticsearch document was not found", http.StatusNotFound)
    err = nil
  }
  return statusCode, nil, err
}
