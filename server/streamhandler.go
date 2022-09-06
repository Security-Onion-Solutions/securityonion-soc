// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
  "context"
  "errors"
  "github.com/apex/log"
  "github.com/security-onion-solutions/securityonion-soc/web"
  "io"
  "net/http"
  "regexp"
  "strconv"
  "strings"
)

type StreamHandler struct {
  web.BaseHandler
  server *Server
}

func NewStreamHandler(srv *Server) *StreamHandler {
  handler := &StreamHandler{}
  handler.Host = srv.Host
  handler.server = srv
  handler.Impl = handler
  return handler
}

func (streamHandler *StreamHandler) HandleNow(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  switch request.Method {
  case http.MethodGet:
    return streamHandler.get(ctx, writer, request)
  case http.MethodPost:
    return streamHandler.post(ctx, writer, request)
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
  reader, filename, length, err := streamHandler.server.Datastore.GetPacketStream(ctx, int(jobId), unwrap)
  extension := request.URL.Query().Get("ext")
  if len(extension) > 0 {
    safe, _ := regexp.MatchString(`^[a-zA-Z0-9-_]+$`, extension)
    if !safe {
      return http.StatusBadRequest, nil, errors.New("Invalid extension")
    }
    extension = "." + extension
    if !strings.HasSuffix(filename, extension) {
      filename = strings.TrimSuffix(filename, ".bin") + extension
    }
  }

  if err == nil {
    defer reader.Close()
    statusCode = http.StatusOK
    writer.Header().Set("Content-Type", "vnd.tcpdump.pcap")
    writer.Header().Set("Content-Length", strconv.FormatInt(length, 10))
    writer.Header().Set("Content-Disposition", "inline; filename=\""+filename+"\"")
    writer.Header().Set("Content-Transfer-Encoding", "binary")
    written, err := io.Copy(writer, reader)
    if err != nil {
      log.WithError(err).WithFields(log.Fields{
        "name": filename,
      }).Error("Failed to copy stream")
    }
    log.WithFields(log.Fields{
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
  err = streamHandler.server.Datastore.SavePacketStream(ctx, int(jobId), request.Body)
  if err == nil {
    statusCode = http.StatusOK
  }
  return statusCode, nil, err
}
