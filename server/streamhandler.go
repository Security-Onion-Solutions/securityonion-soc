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
  "io"
  "net/http"
  "regexp"
  "strconv"
  "strings"
  "github.com/apex/log"
  "github.com/security-onion-solutions/securityonion-soc/web"
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

func (streamHandler *StreamHandler) HandleNow(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  switch request.Method {
    case http.MethodGet: return streamHandler.get(ctx, writer, request)
    case http.MethodPost: return streamHandler.post(ctx, writer, request)
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (streamHandler *StreamHandler) get(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  statusCode := http.StatusBadRequest
  jobId, err := strconv.ParseInt(request.URL.Query().Get("jobId"), 10, 32)
  if err != nil {
    return statusCode, nil, err
  }
  unwrap, err := strconv.ParseBool(request.URL.Query().Get("unwrap"))
  if err != nil {
    return statusCode, nil, err
  }
  reader, filename, length, err := streamHandler.server.Datastore.GetPacketStream(int(jobId), unwrap)
  extension := request.URL.Query().Get("ext")
  if len(extension) > 0 {
    safe, _ := regexp.MatchString(`^[a-zA-Z0-9-_]+$`, extension)
    if !safe {
      return http.StatusBadRequest, nil, errors.New("Invalid extension")
    }
    filename = strings.TrimSuffix(filename, ".bin") + "." + extension
  }

  if err == nil {
    defer reader.Close()
    statusCode = http.StatusOK
    writer.Header().Set("Content-Type", "vnd.tcpdump.pcap")
    writer.Header().Set("Content-Length", strconv.FormatInt(length, 10))
    writer.Header().Set("Content-Disposition", "inline; filename=\"" + filename + "\"");
    writer.Header().Set("Content-Transfer-Encoding", "binary");
    written, err := io.Copy(writer, reader)
    if err != nil {
      log.WithError(err).WithFields(log.Fields {
        "name": filename,
      }).Error("Failed to copy stream")
    }
    log.WithFields(log.Fields {
      "name": filename,
      "size": written,
    }).Info("Copied stream to response")
  } else {
    statusCode = http.StatusNotFound
  }
  return statusCode, nil, err
}

func (streamHandler *StreamHandler) post(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  statusCode := http.StatusBadRequest
  jobId, err := strconv.ParseInt(request.URL.Query().Get("jobId"), 10, 32)
  err = streamHandler.server.Datastore.SavePacketStream(int(jobId), request.Body)
  if err == nil {
    statusCode = http.StatusOK
  }
  return statusCode, nil, err
}
