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
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/web"
  "net/http"
)

type NodeHandler struct {
  web.BaseHandler
  server *Server
}

func NewNodeHandler(srv *Server) *NodeHandler {
  handler := &NodeHandler{}
  handler.Host = srv.Host
  handler.server = srv
  handler.Impl = handler
  return handler
}

func (nodeHandler *NodeHandler) HandleNow(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  switch request.Method {
  case http.MethodPost:
    return nodeHandler.post(ctx, writer, request)
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (nodeHandler *NodeHandler) post(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  var job *model.Job
  node := model.NewNode("")
  err := nodeHandler.ReadJson(request, node)
  if err == nil {
    node, err = nodeHandler.server.Datastore.UpdateNode(node)
    if err == nil {
      nodeHandler.server.Metrics.UpdateNodeMetrics(node)
      nodeHandler.Host.Broadcast("node", node)
      job = nodeHandler.server.Datastore.GetNextJob(ctx, node.Id)
    }
  }
  return http.StatusOK, job, err
}
