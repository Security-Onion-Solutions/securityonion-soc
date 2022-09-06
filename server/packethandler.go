// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
  "context"
  "errors"
  "github.com/security-onion-solutions/securityonion-soc/web"
  "net/http"
  "strconv"
)

type PacketHandler struct {
  web.BaseHandler
  server *Server
}

func NewPacketHandler(srv *Server) *PacketHandler {
  handler := &PacketHandler{}
  handler.Host = srv.Host
  handler.server = srv
  handler.Impl = handler
  return handler
}

func (packetHandler *PacketHandler) HandleNow(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  switch request.Method {
  case http.MethodGet:
    return packetHandler.get(ctx, writer, request)
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (packetHandler *PacketHandler) get(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  statusCode := http.StatusBadRequest
  jobId, err := strconv.ParseInt(request.URL.Query().Get("jobId"), 10, 32)
  if err != nil {
    return statusCode, nil, err
  }
  unwrap, err := strconv.ParseBool(request.URL.Query().Get("unwrap"))
  if err != nil {
    unwrap = false
  }
  offset, err := strconv.ParseInt(request.URL.Query().Get("offset"), 10, 32)
  if offset <= 0 || err != nil {
    offset = 0
  }
  count := packetHandler.server.Config.MaxPacketCount
  count64, err := strconv.ParseInt(request.URL.Query().Get("count"), 10, 32)
  if err == nil {
    tmpCount := int(count64)
    if tmpCount > 0 && tmpCount < count {
      count = tmpCount
    }
  }
  packets, err := packetHandler.server.Datastore.GetPackets(ctx, int(jobId), int(offset), count, unwrap)
  if err == nil {
    statusCode = http.StatusOK
  } else {
    statusCode = http.StatusNotFound
  }
  return statusCode, packets, err
}
