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
    case http.MethodPut:
      return caseHandler.update(ctx, writer, request)
    case http.MethodGet:
      return caseHandler.get(ctx, writer, request)
    case http.MethodDelete:
      return caseHandler.delete(ctx, writer, request)
    }
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (caseHandler *CaseHandler) create(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  var err error
  var obj interface{}
  statusCode := http.StatusBadRequest
  subpath := caseHandler.GetPathParameter(request.URL.Path, 2)
  switch subpath {
  case "events":
    inputEvent := model.NewRelatedEvent()
    err = json.NewDecoder(request.Body).Decode(&inputEvent)
    if err == nil {
      obj, err = caseHandler.server.Casestore.CreateRelatedEvent(ctx, inputEvent)
    }
  case "comments":
    inputComment := model.NewComment()
    err = json.NewDecoder(request.Body).Decode(&inputComment)
    if err == nil {
      obj, err = caseHandler.server.Casestore.CreateComment(ctx, inputComment)
    }
  case "tasks":
  case "artifacts":
  default:
    inputCase := model.NewCase()
    err = json.NewDecoder(request.Body).Decode(&inputCase)
    if err == nil {
      obj, err = caseHandler.server.Casestore.Create(ctx, inputCase)
    }
  }
  if err == nil {
    statusCode = http.StatusOK
  } else {
    statusCode = http.StatusBadRequest
  }
  return statusCode, obj, err
}

func (caseHandler *CaseHandler) update(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  var err error
  var obj interface{}
  statusCode := http.StatusBadRequest
  subpath := caseHandler.GetPathParameter(request.URL.Path, 2)
  switch subpath {
  case "comments":
    inputComment := model.NewComment()
    err = json.NewDecoder(request.Body).Decode(&inputComment)
    if err == nil {
      obj, err = caseHandler.server.Casestore.UpdateComment(ctx, inputComment)
    }
  case "tasks":
  case "artifacts":
  default:
    inputCase := model.NewCase()
    err = json.NewDecoder(request.Body).Decode(&inputCase)
    if err == nil {
      obj, err = caseHandler.server.Casestore.Update(ctx, inputCase)
    }
  }

  if err == nil {
    statusCode = http.StatusOK
  } else {
    statusCode = http.StatusBadRequest
  }
  return statusCode, obj, err
}

func (caseHandler *CaseHandler) delete(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  var err error
  var obj interface{}
  statusCode := http.StatusBadRequest
  id := request.URL.Query().Get("id")
  subpath := caseHandler.GetPathParameter(request.URL.Path, 2)
  switch subpath {
  case "comments":
    err = caseHandler.server.Casestore.DeleteComment(ctx, id)
  case "events":
    err = caseHandler.server.Casestore.DeleteRelatedEvent(ctx, id)
  case "tasks":
  case "artifacts":
  default:
    err = errors.New("Delete not supported")
  }

  if err == nil {
    statusCode = http.StatusOK
  } else {
    statusCode = http.StatusBadRequest
  }
  return statusCode, obj, err
}

func (caseHandler *CaseHandler) get(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  statusCode := http.StatusBadRequest
  id := request.URL.Query().Get("id")
  var err error
  var obj interface{}
  subpath := caseHandler.GetPathParameter(request.URL.Path, 2)
  switch subpath {
  case "events":
    obj, err = caseHandler.server.Casestore.GetRelatedEvents(ctx, id)
  case "comments":
    obj, err = caseHandler.server.Casestore.GetComments(ctx, id)
  case "tasks":
  case "artifacts":
  case "history":
    obj, err = caseHandler.server.Casestore.GetCaseHistory(ctx, id)
  default:
    obj, err = caseHandler.server.Casestore.GetCase(ctx, id)
  }
  if obj != nil {
    statusCode = http.StatusOK
  } else {
    statusCode = http.StatusNotFound
  }
  return statusCode, obj, err
}
