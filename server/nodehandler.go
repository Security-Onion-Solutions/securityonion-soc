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
  "errors"
  "net/http"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/web"
)

type NodeHandler struct {
  web.BaseHandler
  server 		*Server
}

func NewNodeHandler(srv *Server) *NodeHandler {
  handler := &NodeHandler {}
  handler.Host = srv.Host
  handler.server = srv
  handler.Impl = handler
  return handler
}

func (nodeHandler *NodeHandler) HandleNow(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  switch request.Method {
    case http.MethodPost: return nodeHandler.post(writer, request)
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (nodeHandler *NodeHandler) post(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  var job *model.Job
  node := model.NewNode("")
  err := nodeHandler.ReadJson(request, node)
  if err == nil {
    err = nodeHandler.server.Datastore.UpdateNode(node)
    if err == nil {
      nodeHandler.Host.Broadcast("node", node)
      job = nodeHandler.server.Datastore.GetNextJob(node.Id)
    }
  }
  return http.StatusOK, job, err
}