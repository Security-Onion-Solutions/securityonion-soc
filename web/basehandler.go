// Copyright 2019 Jason Ertel (jertel). All rights reserved.
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
  "encoding/json"
  "errors"
  "net/http"
  "reflect"
  "strings"
  "github.com/apex/log"
)

type HandlerImpl interface {
  HandleNow(responseWriter http.ResponseWriter, request *http.Request) (int, interface{}, error)
}

type BaseHandler struct {
  Host					*Host
  Impl					HandlerImpl
}

func (handler *BaseHandler) Handle(responseWriter http.ResponseWriter, request *http.Request) {
  var statusCode, contentLength int
  var err error
  defer request.Body.Close()
  if handler.Host.Auth == nil {
    err = errors.New("Agent auth module has not been initialized; ensure a valid auth module has been defined in the configuration")
  } else {
    if !handler.Host.Auth.IsAuthorized(request) {
      statusCode = http.StatusUnauthorized
      responseWriter.WriteHeader(statusCode)
    } else {
      var obj interface{}
      responseWriter.Header().Set("Version", handler.Host.Version)
      statusCode, obj, err = handler.Impl.HandleNow(responseWriter, request)
      if err == nil && obj != nil {
        contentLength, err = handler.WriteJson(responseWriter, request, statusCode, obj)
      }
    }
  }

  if err != nil {
    log.WithError(err).WithFields(log.Fields{
      "sourceIp": request.RemoteAddr,
      "path": request.URL.Path,
      "impl": reflect.TypeOf(handler.Impl),
      "statusCode": statusCode,
      "contentLength": contentLength,
      "method": request.Method,
    }).Error("Failed request")
  
    if statusCode < http.StatusBadRequest {
      statusCode = http.StatusInternalServerError
    }
    responseWriter.WriteHeader(statusCode)
  } else {
    log.WithFields(log.Fields{
      "sourceIp": request.RemoteAddr,
      "path": request.URL.Path,
      "impl": reflect.TypeOf(handler.Impl),
      "statusCode": statusCode,
      "contentLength": contentLength,
      "method": request.Method,
    }).Info("Handled request")
  }
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