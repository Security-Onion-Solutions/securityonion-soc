// Copyright 2020-2022 Security Onion Solutions, LLC. All rights reserved.
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

type QueryHandler struct {
	web.BaseHandler
	server *Server
}

func NewQueryHandler(srv *Server) *QueryHandler {
	handler := &QueryHandler{}
	handler.Host = srv.Host
	handler.server = srv
	handler.Impl = handler
	return handler
}

func (queryHandler *QueryHandler) HandleNow(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
	switch request.Method {
	case http.MethodGet:
		return queryHandler.get(ctx, writer, request)
	}
	return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (queryHandler *QueryHandler) get(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
	operation := queryHandler.GetPathParameter(request.URL.Path, 2)
	safe, _ := regexp.MatchString(`^[a-z]+$`, operation)
	if !safe {
		return http.StatusBadRequest, nil, errors.New("Invalid query operation")
	}

	err := request.ParseForm()
	if err != nil {
		return http.StatusBadRequest, nil, errors.New("Invalid query operation inputs")
	}

	queryStr := request.Form.Get("query")
	query := model.NewQuery()
	err = query.Parse(queryStr)
	if err != nil {
		return http.StatusBadRequest, nil, errors.New("Invalid query input")
	}

	var alteredQuery string
	switch operation {
	case "filtered":
		field := request.Form.Get("field")
		scalar := request.Form.Get("scalar") == "true"
		mode := request.Form.Get("mode")
		value := request.Form.Get("value")
		condense := request.Form.Get("condense") == "true"
		if len(value) > 0 {
			alteredQuery, err = query.Filter(field, value, scalar, mode, condense)
		} else {
			values := request.Form["value[]"]
			for _, value := range values {
				alteredQuery, err = query.Filter(field, value, scalar, mode, condense)
				queryStr = query.String()
				query = model.NewQuery()
				err = query.Parse(queryStr)
				if err != nil {
					return http.StatusBadRequest, nil, errors.New("Invalid query after filter applied")
				}
			}
		}
	case "grouped":
		field := request.Form.Get("field")
		alteredQuery, err = query.Group(field)
	case "sorted":
		field := request.Form.Get("field")
		alteredQuery, err = query.Sort(field)
	default:
		return http.StatusBadRequest, nil, errors.New("Unsupported query operation")
	}

	if err != nil {
		return http.StatusBadRequest, nil, err
	}

	return http.StatusOK, alteredQuery, nil
}
