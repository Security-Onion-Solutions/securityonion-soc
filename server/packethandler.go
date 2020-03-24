// Copyright 2019 Jason Ertel (jertel). All rights reserved.
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
  "strconv"
  "github.com/sensoroni/sensoroni/web"
)

type PacketHandler struct {
  web.BaseHandler
  server 		*Server
}

func NewPacketHandler(srv *Server) *PacketHandler {
  handler := &PacketHandler {}
  handler.Host = srv.Host
  handler.server = srv
  handler.Impl = handler
  return handler
}

func (packetHandler *PacketHandler) HandleNow(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  switch request.Method {
    case http.MethodGet: return packetHandler.get(writer, request)
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (packetHandler *PacketHandler) get(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  statusCode := http.StatusBadRequest
  jobId, err := strconv.ParseInt(request.URL.Query().Get("jobId"), 10, 32)
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
  packets, err := packetHandler.server.Datastore.GetPackets(int(jobId), int(offset), count)
  if err == nil {
    statusCode = http.StatusOK
  } else {
    statusCode = http.StatusNotFound
  }
  return statusCode, packets, err
}
