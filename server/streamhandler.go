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
  "io"
  "net/http"
  "strconv"
  "github.com/sensoroni/sensoroni/web"
)

type StreamHandler struct {
  web.BaseHandler
  server 		*Server
}

func NewStreamHandler(srv *Server) *StreamHandler {
  handler := &StreamHandler {}
  handler.Host = srv.Host
  handler.server = srv
  handler.Impl = handler
  return handler
}

func (streamHandler *StreamHandler) HandleNow(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  switch request.Method {
    case http.MethodGet: return streamHandler.get(writer, request)
    case http.MethodPost: return streamHandler.post(writer, request)
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (streamHandler *StreamHandler) get(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  statusCode := http.StatusBadRequest
  jobId, err := strconv.ParseInt(request.URL.Query().Get("jobId"), 10, 32)
  reader, filename, err := streamHandler.server.Datastore.GetPacketStream(int(jobId))
  if err == nil {
    defer reader.Close()
    statusCode = http.StatusOK
    writer.Header().Set("Content-Type", "application/octet-stream")
    writer.Header().Set("Content-Disposition", "attachment; filename=\"" + filename + "\"");
    writer.Header().Set("Content-Transfer-Encoding", "binary");
    io.Copy(writer, reader)
  } else {
    statusCode = http.StatusNotFound
  }
  return statusCode, reader, err
}

func (streamHandler *StreamHandler) post(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  statusCode := http.StatusBadRequest
  jobId, err := strconv.ParseInt(request.URL.Query().Get("jobId"), 10, 32)
  err = streamHandler.server.Datastore.SavePacketStream(int(jobId), request.Body)
  if err == nil {
    statusCode = http.StatusOK
  }
  return statusCode, nil, err
}
