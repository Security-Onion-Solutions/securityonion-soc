// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package web

import (
	"context"
	jsonpkg "encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/apex/log"
	"github.com/go-chi/chi"
	"github.com/gorilla/websocket"
	"github.com/security-onion-solutions/securityonion-soc/json"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

type WebSocketHandler struct {
	Host *Host
}

func NewWebSocketHandler(host *Host) *WebSocketHandler {
	handler := &WebSocketHandler{}
	handler.Host = host

	return handler
}

func RegisterWebSocketRoutes(host *Host, r chi.Router) {
	handler := &WebSocketHandler{
		Host: host,
	}

	r.Group(func(r chi.Router) {
		r.Use(middleware(host))

		r.Get("/ws", handler.Handle)
	})
}

func middleware(host *Host) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Version", host.Version)

			ctx := r.Context()
			ctx = context.WithValue(ctx, ContextKeyRequestStart, time.Now())

			ctx, statusCode, err := host.Preprocess(ctx, r)
			if err != nil {
				r = r.WithContext(ctx)
				RespondWS(w, r, statusCode, err)
				return
			}

			r = r.WithContext(ctx)

			// no validateRequest for WS

			next.ServeHTTP(w, r)
		})
	}
}

func (webSocketHandler *WebSocketHandler) Handle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ip := GetSourceIp(r)

	var user *model.User
	var ok bool
	user, ok = ctx.Value(ContextKeyRequestor).(*model.User)
	if !ok {
		log.WithFields(log.Fields{
			"remoteAddr": r.RemoteAddr,
			"sourceIp":   ip,
			"path":       r.URL.Path,
		}).Warn("User does not exist in context")
		RespondWS(w, r, http.StatusBadRequest, errors.New("User does not exist in context; unable to complete websocket"))

		return
	}

	upgrader := websocket.Upgrader{}
	connection, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			"remoteAddr": r.RemoteAddr,
			"sourceIp":   ip,
			"path":       r.URL.Path,
		}).Warn("Failed to upgrade websocket")
		RespondWS(w, r, http.StatusBadRequest, err)

		return
	}

	log.WithFields(log.Fields{
		"remoteAddr": r.RemoteAddr,
		"sourceIp":   ip,
		"path":       r.URL.Path,
	}).Info("WebSocket connected")

	conn := webSocketHandler.Host.AddConnection(user, connection, ip)

	defer connection.Close()
	for {
		messageType, messageBytes, err := connection.ReadMessage()
		if err != nil {
			break
		}
		log.WithFields(log.Fields{
			"remoteAddr": r.RemoteAddr,
			"sourceIp":   ip,
			"path":       r.URL.Path,
			"msg":        string(messageBytes),
			"type":       messageType,
		}).Info("WebSocket message received")

		msg := &WebSocketMessage{}
		json.LoadJson(messageBytes, msg)
		webSocketHandler.handleMessage(msg, conn)
	}
	log.WithFields(log.Fields{
		"remoteAddr": r.RemoteAddr,
		"sourceIp":   ip,
		"path":       r.URL.Path,
	}).Info("WebSocket disconnected")
	webSocketHandler.Host.RemoveConnection(connection)

	RespondWS(nil, r, http.StatusOK, nil)
}

func (webSocketHandler *WebSocketHandler) handleMessage(msg *WebSocketMessage, conn *Connection) {
	if msg.Kind == "Ping" {
		conn.UpdatePingTime()
	}
}

func RespondWS(w http.ResponseWriter, r *http.Request, statusCode int, obj any) {
	var contentLength int

	ctx := r.Context()
	start := ctx.Value(ContextKeyRequestStart).(time.Time)
	elapsed := time.Since(start).Milliseconds()

	err, isErr := obj.(error)
	if isErr {
		log.WithError(err).WithFields(log.Fields{
			"requestId": ctx.Value(ContextKeyRequestId),
			"requestor": ctx.Value(ContextKeyRequestor),
		}).Warn("Request did not complete successfully")

		var unauthorizedError *model.Unauthorized
		if errors.As(err, &unauthorizedError) {
			statusCode = http.StatusUnauthorized
		} else if statusCode < http.StatusBadRequest {
			statusCode = http.StatusInternalServerError
		}

		bytes := []byte(ConvertErrorToSafeString(err))
		contentLength = len(bytes)

		if w != nil {
			w.WriteHeader(statusCode)
			_, _ = w.Write(bytes)
		}
	} else if obj != nil {
		switch data := obj.(type) {
		case []byte:
			contentLength = len(data)
			if w != nil {
				_, _ = w.Write(data)
			}
		default:
			bytes, err := jsonpkg.Marshal(obj)
			if err != nil {
				RespondWS(w, r, http.StatusInternalServerError, err)
				return
			}

			contentLength = len(bytes)

			if w != nil {
				w.WriteHeader(statusCode)
				_, _ = w.Write(bytes)
			}
		}
	}

	fnc, file, line := getCallerDetails(0)

	impl := "unknown"
	if line != -1 {
		impl = fmt.Sprintf("%s:%d:%s", file, line, fnc)
	}

	log.WithFields(log.Fields{
		"remoteAddr":    r.RemoteAddr,
		"sourceIp":      GetSourceIp(r),
		"path":          r.URL.Path,
		"query":         r.URL.Query(),
		"impl":          impl,
		"statusCode":    statusCode,
		"contentLength": contentLength,
		"method":        r.Method,
		"elapsedMs":     elapsed,
		"requestId":     ctx.Value(ContextKeyRequestId),
		"requestor":     ctx.Value(ContextKeyRequestor),
	}).Info("Handled request")
}

func getCallerDetails(skip int) (funcName string, file string, line int) {
	// yes, runtime.Callers and runtime.Caller treat their `skip` parameters
	// differently and so have different offsets in this function to account for
	// it

	pc := make([]uintptr, 4+skip) // more than enough room

	// skip = 3
	// 0 => runtime.Callers
	// 1 => getCallingFuncName
	// 2 => the function being called (i.e. Respond)
	// 3 => the calling function (i.e. the handler)
	count := runtime.Callers(3+skip, pc)

	if count == 0 {
		return "", "", -1
	}

	frames := runtime.CallersFrames(pc[:count])
	f, _ := frames.Next()

	// skip = 2
	// 0 => getCallerDetails
	// 1 => Respond
	// 2 => the caller we're interested in
	_, file, line, _ = runtime.Caller(2 + skip)

	return f.Function, file, line
}
