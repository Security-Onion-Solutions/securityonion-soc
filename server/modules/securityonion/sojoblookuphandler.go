// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package securityonion

import (
  "errors"
  "net/http"
  "strconv"
  "github.com/sensoroni/sensoroni/server"
  "github.com/sensoroni/sensoroni/web"
)

type SoJobLookupHandler struct {
  web.BaseHandler
  server							*server.Server
  elastic 						*SoElastic
}

func NewSoJobLookupHandler(srv *server.Server, elastic *SoElastic) *SoJobLookupHandler {
  handler := &SoJobLookupHandler {}
  handler.Host = srv.Host
  handler.server = srv
  handler.BaseHandler.Impl = handler
  handler.elastic = elastic
  return handler
}

func (handler *SoJobLookupHandler) HandleNow(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  switch request.Method {
    case http.MethodGet: return handler.get(writer, request)
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (handler *SoJobLookupHandler) get(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  statusCode := http.StatusBadRequest
  esId := request.URL.Query().Get("esid")
  sensorId, filter, err := handler.elastic.LookupEsId(esId)
  if err == nil {
    job := handler.server.Datastore.CreateJob()
    job.SensorId = sensorId
    job.Filter = filter
    err = handler.server.Datastore.AddJob(job)
    if err == nil {
      handler.Host.Broadcast("job", job)
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
