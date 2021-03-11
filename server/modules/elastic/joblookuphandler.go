// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package elastic

import (
  "errors"
  "fmt"
  "net/http"
  "strconv"
  "github.com/security-onion-solutions/securityonion-soc/server"
  "github.com/security-onion-solutions/securityonion-soc/web"
)

type JobLookupHandler struct {
  web.BaseHandler
  server							*server.Server
  store    						*ElasticEventstore
}

func NewJobLookupHandler(srv *server.Server, store *ElasticEventstore) *JobLookupHandler {
  handler := &JobLookupHandler {}
  handler.Host = srv.Host
  handler.server = srv
  handler.BaseHandler.Impl = handler
  handler.store = store
  return handler
}

func (handler *JobLookupHandler) HandleNow(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  switch request.Method {
    case http.MethodGet: return handler.get(writer, request)
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (handler *JobLookupHandler) get(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  statusCode := http.StatusBadRequest
  esId := request.URL.Query().Get("esid") // Elastic doc ID
  var query string
  if len(esId) > 0 {
    query = fmt.Sprintf(`{"query" : { "bool": { "must": { "match" : { "_id" : "%s" }}}}}`, esId)
  } else {
    ncId := request.URL.Query().Get("ncid") // Network community ID
    query = fmt.Sprintf(`{"query" : { "bool": { "must": { "match" : { "network.community_id" : "%s" }}}}}`, ncId)
  }

  job := handler.server.Datastore.CreateJob()
  err := handler.store.PopulateJobFromDocQuery(query, job)
  if err == nil {
    job.UserId = handler.GetUserId(request)
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
