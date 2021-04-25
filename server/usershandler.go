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
	"errors"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"net/http"
	"regexp"
)

type UsersHandler struct {
	web.BaseHandler
	server *Server
}

func NewUsersHandler(srv *Server) *UsersHandler {
	handler := &UsersHandler{}
	handler.Host = srv.Host
	handler.server = srv
	handler.Impl = handler
	return handler
}

func (usersHandler *UsersHandler) HandleNow(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
	if usersHandler.server.Userstore == nil {
		return http.StatusMethodNotAllowed, nil, errors.New("Users module not enabled")
	}

	switch request.Method {
	case http.MethodGet:
		return usersHandler.get(writer, request)
	}
	return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (usersHandler *UsersHandler) get(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
	users, err := usersHandler.server.Userstore.GetUsers()
	if err != nil {
		return http.StatusBadRequest, nil, err
	}
	return http.StatusOK, users, nil
}

func (usersHandler *UsersHandler) delete(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
	id := usersHandler.GetPathParameter(request.URL.Path, 2)
	safe, _ := regexp.MatchString(`^[A-Za-z0-9-]+$`, id)
	if !safe {
		return http.StatusBadRequest, nil, errors.New("Invalid id")
	}
	err := usersHandler.server.Userstore.DeleteUser(id)
	if err != nil {
		return http.StatusBadRequest, nil, err
	}
	return http.StatusOK, nil, nil
}
