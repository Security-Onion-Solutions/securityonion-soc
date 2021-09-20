// Copyright 2020-2021 Security Onion Solutions. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package server

import (
  "context"
  "encoding/json"
  "errors"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/web"
  "net/http"
)

type CaseHandler struct {
  web.BaseHandler
  server *Server
}

func NewCaseHandler(srv *Server) *CaseHandler {
  handler := &CaseHandler{}
  handler.Host = srv.Host
  handler.server = srv
  handler.Impl = handler
  return handler
}

func (caseHandler *CaseHandler) HandleNow(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  if caseHandler.server.Casestore == nil {
    return http.StatusMethodNotAllowed, nil, errors.New("CASE_MODULE_NOT_ENABLED")
  }

  if caseHandler.server.Casestore != nil {
    switch request.Method {
    case http.MethodPost:
      return caseHandler.create(ctx, writer, request)
    }
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (caseHandler *CaseHandler) create(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  statusCode := http.StatusBadRequest
  var outputCase *model.Case

  inputCase := model.NewCase()
  err := json.NewDecoder(request.Body).Decode(&inputCase)
  if err == nil {
    outputCase, err = caseHandler.server.Casestore.Create(ctx, inputCase)
    if err == nil {
      statusCode = http.StatusOK
    } else {
      statusCode = http.StatusBadRequest
    }
  }
  return statusCode, outputCase, err
}
