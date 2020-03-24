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
  "github.com/sensoroni/sensoroni/web"
)

type SensorsHandler struct {
  web.BaseHandler
  server 		*Server
}

func NewSensorsHandler(srv *Server) *SensorsHandler {
  handler := &SensorsHandler {}
  handler.Host = srv.Host
  handler.server = srv
  handler.Impl = handler
  return handler
}

func (sensorsHandler *SensorsHandler) HandleNow(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  switch request.Method {
    case http.MethodGet: return sensorsHandler.get(writer, request)
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (sensorsHandler *SensorsHandler) get(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  return http.StatusOK, sensorsHandler.server.Datastore.GetSensors(), nil
}