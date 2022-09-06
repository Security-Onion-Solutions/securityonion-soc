// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package web

import (
  "bytes"
  "compress/gzip"
  "context"
  "encoding/json"
  "errors"
  "github.com/apex/log"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "net/http"
  "reflect"
  "strings"
  "time"
)

const GENERIC_ERROR_MESSAGE = "The request could not be processed. Contact a server admin for assistance with reviewing error details in SOC logs."

type HandlerImpl interface {
  HandleNow(ctx context.Context, responseWriter http.ResponseWriter, request *http.Request) (int, interface{}, error)
}

type BaseHandler struct {
  Host *Host
  Impl HandlerImpl
}

func (handler *BaseHandler) validateRequest(ctx context.Context, request *http.Request) error {
  if request.Method == http.MethodPost ||
    request.Method == http.MethodPut ||
    request.Method == http.MethodPatch ||
    request.Method == http.MethodDelete {

    userId := ctx.Value(ContextKeyRequestorId).(string)
    if userId != handler.Host.SrvExemptId {

      token := request.Header.Get("x-srv-token")
      if len(token) == 0 {
        return errors.New("Missing SRV token on request")
      }

      return model.ValidateSrvToken(handler.Host.SrvKey, userId, token)
    }
  }
  return nil
}

func (handler *BaseHandler) Handle(responseWriter http.ResponseWriter, request *http.Request) {
  var statusCode, contentLength int
  var err error

  defer request.Body.Close()
  start := time.Now()

  context, statusCode, err := handler.Host.Preprocess(request.Context(), request)
  if err == nil {
    var obj interface{}

    err = handler.validateRequest(context, request)
    if err == nil {
      responseWriter.Header().Set("Version", handler.Host.Version)

      statusCode, obj, err = handler.Impl.HandleNow(context, responseWriter, request.WithContext(context))
      if err == nil && obj != nil {
        contentLength, err = handler.WriteJson(responseWriter, request, statusCode, obj)
      }
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

    bytes := []byte(handler.convertErrorToSafeString(err))
    contentLength = len(bytes)
    responseWriter.Write(bytes)
  }
  log.WithFields(log.Fields{
    "remoteAddr":    request.RemoteAddr,
    "sourceIp":      handler.Host.GetSourceIp(request),
    "path":          request.URL.Path,
    "query":         request.URL.Query(),
    "impl":          reflect.TypeOf(handler.Impl),
    "statusCode":    statusCode,
    "contentLength": contentLength,
    "method":        request.Method,
    "elapsedMs":     elapsed,
    "requestId":     context.Value(ContextKeyRequestId),
    "requestor":     context.Value(ContextKeyRequestor),
  }).Info("Handled request")
}

func (handler *BaseHandler) convertErrorToSafeString(err error) string {
  msg := err.Error()
  if !strings.HasPrefix(msg, "ERROR_") {
    msg = GENERIC_ERROR_MESSAGE
  }
  return msg
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
  if paramIndex < 0 || paramIndex+1 >= len(p) {
    return ""
  } else {
    return p[paramIndex+1]
  }
}
