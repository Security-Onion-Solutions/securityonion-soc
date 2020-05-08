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
	"regexp"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/web"
)

type QueryHandler struct {
  web.BaseHandler
  server 		*Server
}

func NewQueryHandler(srv *Server) *QueryHandler {
  handler := &QueryHandler {}
  handler.Host = srv.Host
  handler.server = srv
  handler.Impl = handler
  return handler
}

func (queryHandler *QueryHandler) HandleNow(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
	switch request.Method {
		case http.MethodGet: return queryHandler.get(writer, request)
	}
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (queryHandler *QueryHandler) get(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
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
		value := request.Form.Get("value")
		include := request.Form.Get("include") == "true"
		alteredQuery, err = query.Filter(field, value, include)
	case "grouped": 
		field := request.Form.Get("field") 
		alteredQuery, err = query.Group(field)
	default:
		return http.StatusBadRequest, nil, errors.New("Unsupported query operation")
	}

  if err != nil {
		return http.StatusBadRequest, nil, err
	}

	return http.StatusOK, alteredQuery, nil
}
