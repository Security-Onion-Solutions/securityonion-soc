// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package web

import (
  "bytes"
  "compress/gzip"
  "context"
  "encoding/json"
  "errors"
  "net/http"
  "reflect"
  "strings"
  "time"
  "github.com/apex/log"
  "github.com/security-onion-solutions/securityonion-soc/model"
)

type HandlerImpl interface {
  HandleNow(ctx context.Context, responseWriter http.ResponseWriter, request *http.Request) (int, interface{}, error)
}

type BaseHandler struct {
  Host					*Host
  Impl					HandlerImpl
}

func (handler *BaseHandler) Handle(responseWriter http.ResponseWriter, request *http.Request) {
  var statusCode, contentLength int
 	var err error

  defer request.Body.Close()
  start := time.Now()

  context, statusCode, err := handler.Host.Preprocess(request.Context(), request)
  if err == nil {
    var obj interface{}
    responseWriter.Header().Set("Version", handler.Host.Version)

    statusCode, obj, err = handler.Impl.HandleNow(context, responseWriter, request.WithContext(context))
    if err == nil && obj != nil {
      contentLength, err = handler.WriteJson(responseWriter, request, statusCode, obj)
    }
  }
  stop := time.Now()
  elapsed := stop.Sub(start).Milliseconds()

  if err != nil {
    log.WithError(err).WithFields(log.Fields{
	    "requestId": context.Value(ContextKeyRequestId),
	    "requestor": context.Value(ContextKeyRequestor),
    }).Warn("Request did not complete successfully")
  
    var unauthorizedError *model.Unauthorized
    if errors.As(err, &unauthorizedError) {
      statusCode = http.StatusUnauthorized
    } else if statusCode < http.StatusBadRequest {
      statusCode = http.StatusInternalServerError
    }
    responseWriter.WriteHeader(statusCode)
    bytes := []byte(err.Error())
    contentLength = len(bytes)
    responseWriter.Write(bytes)
  }
  log.WithFields(log.Fields{
    "remoteAddr": request.RemoteAddr,
    "sourceIp": handler.Host.GetSourceIp(request),
    "path": request.URL.Path,
    "query": request.URL.Query(),
    "impl": reflect.TypeOf(handler.Impl),
    "statusCode": statusCode,
    "contentLength": contentLength,
    "method": request.Method,
    "elapsedMs": elapsed,
    "requestId": context.Value(ContextKeyRequestId),
    "requestor": context.Value(ContextKeyRequestor),
  }).Info("Handled request")
}

func (handler *BaseHandler) WriteJson(responseWriter http.ResponseWriter, request *http.Request, statusCode int, obj interface{}) (int, error) {
  jsonBytes, err := json.Marshal(obj)
  length := 0
  if err == nil {
    if strings.Contains(request.Header.Get("Accept-Encoding"), "gzip") {
      var buf bytes.Buffer
      gzipWriter := gzip.NewWriter(&buf)
      _, err = gzipWriter.Write(jsonBytes)
      defer gzipWriter.Close()
      if err == nil {
        responseWriter.Header().Set("Content-Encoding", "gzip")
        gzipWriter.Flush()
        jsonBytes = buf.Bytes()
      }
    }
    responseWriter.Header().Set("Content-Type", "application/json")
    responseWriter.WriteHeader(statusCode)
    length, err = responseWriter.Write(jsonBytes)
  } else {
    log.WithError(err).Error("Unable to serialize object")
  }
  return length, err
}

func (handler *BaseHandler) ReadJson(request *http.Request, obj interface{}) error {
  return json.NewDecoder(request.Body).Decode(obj)
}

func (handler *BaseHandler) GetPathParameter(path string, paramIndex int) string {
  p := strings.Split(path, "/")
  if paramIndex < 0 || paramIndex + 1 >= len(p) {
    return ""
  } else {
    return p[paramIndex + 1]
  }
}