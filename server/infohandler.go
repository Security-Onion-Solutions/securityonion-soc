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
  "github.com/sensoroni/sensoroni/model"
  "github.com/sensoroni/sensoroni/web"
)

type InfoHandler struct {
  web.BaseHandler
  server 		*Server
}

func NewInfoHandler(srv *Server) *InfoHandler {
  handler := &InfoHandler {}
  handler.Host = srv.Host
  handler.server = srv
  handler.Impl = handler
  return handler
}

func (infoHandler *InfoHandler) HandleNow(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  switch request.Method {
    case http.MethodGet: return infoHandler.get(writer, request)
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (infoHandler *InfoHandler) get(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  info := &model.Info{
    Version: infoHandler.Host.Version,
    License: "GPL v2",
  }
  return http.StatusOK, info, nil
}
