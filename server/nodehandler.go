// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

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
    node, err = nodeHandler.server.Datastore.UpdateNode(ctx, node)
    if err == nil {
      nodeHandler.server.Metrics.UpdateNodeMetrics(ctx, node)
      nodeHandler.Host.Broadcast("node", "nodes", node)
      job = nodeHandler.server.Datastore.GetNextJob(ctx, node.Id)
    }
  }
  return http.StatusOK, job, err
}
