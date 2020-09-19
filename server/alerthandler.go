// Copyright 2020 Security Onion Solutions. All rights reserved.
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
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/web"
)

type EventHandler struct {
  web.BaseHandler
  server 		*Server
}

func NewEventHandler(srv *Server) *EventHandler {
  handler := &EventHandler {}
  handler.Host = srv.Host
  handler.server = srv
  handler.Impl = handler
  return handler
}

func (eventHandler *EventHandler) HandleNow(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  if eventHandler.server.Eventstore != nil {
    switch request.Method {
      case http.MethodGet: return eventHandler.get(writer, request)
    }
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (eventHandler *EventHandler) get(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  var results *model.EventSearchResults
  statusCode := http.StatusBadRequest

  err := request.ParseForm()
  if err == nil {
    criteria := model.NewEventSearchCriteria()
    err = criteria.Populate(request.Form.Get("query"), 
                            request.Form.Get("range"), 
                            request.Form.Get("format"), 
                            request.Form.Get("zone"),
                            request.Form.Get("metricLimit"),
                            request.Form.Get("eventLimit"))
    if err == nil {
      results, err = eventHandler.server.Eventstore.Search(criteria)
      if err == nil {
        statusCode = http.StatusOK
      } else {
        statusCode = http.StatusInternalServerError
      }
    }
  }
  return statusCode, results, err
}
