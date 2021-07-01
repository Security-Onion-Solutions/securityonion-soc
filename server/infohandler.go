// Copyright 2019 Jason Ertel (jertel). All rights reserved.
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
  "os"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/web"
)

type InfoHandler struct {
  web.BaseHandler
  server 		*Server
  timezones []string
}

func NewInfoHandler(srv *Server) *InfoHandler {
  handler := &InfoHandler {}
  handler.Host = srv.Host
  handler.server = srv
  handler.Impl = handler
  handler.timezones = srv.GetTimezones()
  return handler
}

func (infoHandler *InfoHandler) HandleNow(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  switch request.Method {
    case http.MethodGet: return infoHandler.get(ctx, writer, request)
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (infoHandler *InfoHandler) get(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  var err error
  var info *model.Info
  if user, ok := request.Context().Value(web.ContextKeyRequestor).(*model.User); ok {
    info = &model.Info{
      Version: infoHandler.Host.Version,
      License: "GPL v2",
      Parameters: &infoHandler.server.Config.ClientParams,
      ElasticVersion: os.Getenv("ELASTIC_VERSION"),
      WazuhVersion: os.Getenv("WAZUH_VERSION"),
      UserId: user.Id,
      Timezones: infoHandler.timezones,
    }
  } else {
    err = errors.New("Unable to determine logged in user from context")
  }
  return http.StatusOK, info, err
}
