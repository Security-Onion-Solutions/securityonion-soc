// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
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
  "errors"
  "net/http"
	"regexp"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

type UserHandler struct {
  web.BaseHandler
  server 		*Server
}

func NewUserHandler(srv *Server) *UserHandler {
  handler := &UserHandler {}
  handler.Host = srv.Host
  handler.server = srv
  handler.Impl = handler
  return handler
}

func (userHandler *UserHandler) HandleNow(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
	if userHandler.server.Userstore == nil {
		return http.StatusMethodNotAllowed, nil, errors.New("Users module not enabled")
	}

  switch request.Method {
    case http.MethodGet: return userHandler.get(ctx, writer, request)
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (userHandler *UserHandler) get(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  id := userHandler.GetPathParameter(request.URL.Path, 2)
  safe, _ := regexp.MatchString(`^[A-Za-z0-9-]+$`, id)
  if !safe {
    return http.StatusBadRequest, nil, errors.New("Invalid id")
	}
	user, err := userHandler.server.Userstore.GetUser(id)
  if err != nil {
    return http.StatusBadRequest, nil, err
  }
  return http.StatusOK, user, nil
}

func (userHandler *UserHandler) put(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  id := userHandler.GetPathParameter(request.URL.Path, 2)
  safe, _ := regexp.MatchString(`^[A-Za-z0-9-]+$`, id)
  if !safe {
    return http.StatusBadRequest, nil, errors.New("Invalid id")
	}
  user := model.NewUser()
	err := userHandler.ReadJson(request, user)
	if err != nil {
		return http.StatusBadRequest, nil, errors.New("Invalid user object")
	}
	err = userHandler.server.Userstore.UpdateUser(id, user)
	if err != nil {
		return http.StatusBadRequest, nil, err
	}	
  return http.StatusOK, nil, nil
}