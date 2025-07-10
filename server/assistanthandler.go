// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/go-chi/chi/v5"
)

type AssistantHandler struct {
	server *Server
}

func NewAssistantHandler(srv *Server) *AssistantHandler {
	return &AssistantHandler{
		server: srv,
	}
}

func RegisterAssistantRoutes(srv *Server, r chi.Router, prefix string) {
	h := NewAssistantHandler(srv)

	r.Route(prefix, func(r chi.Router) {
		r.Post("/chat", h.PostChat)
		r.Get("/balance", h.GetBalance)
	})
}

func (h *AssistantHandler) PostChat(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	accept := strings.TrimSpace(r.Header.Get("Accept"))
	streaming := strings.EqualFold(accept, "text/event-stream")

	type TempBody struct {
		Msg      string               `json:"msg"`
		Messages []*model.ChatMessage `json:"messages,omitempty"`
	}

	tb := &TempBody{}
	err := json.NewDecoder(r.Body).Decode(tb)
	if err != nil {
		logger.WithError(err).Error("unable to decode request body")
		web.Respond(w, r, http.StatusBadRequest, err)

		return
	}

	// Use provided messages if available, otherwise create from current message
	var messages []*model.ChatMessage
	if len(tb.Messages) > 0 {
		// Add the new user message to the existing conversation
		messages = append(tb.Messages, &model.ChatMessage{
			Role:    "user",
			Content: tb.Msg,
		})
	} else {
		// Fallback to single message for backward compatibility
		messages = []*model.ChatMessage{
			{
				Role:    "user",
				Content: tb.Msg,
			},
		}
	}

	flusher, ok := w.(http.Flusher)
	if streaming && !ok {
		logger.WithField("acceptHeader", accept).Warn("incoming request accepts streaming but is not flushable, issuing non-streaming response")
	}

	if !streaming || !ok {
		response, err := h.server.AssistantManager.Chat(ctx, messages)
		if err != nil {
			logger.WithError(err).Error("unable to chat with assistant")
			web.Respond(w, r, http.StatusInternalServerError, err)

			return
		}

		web.Respond(w, r, http.StatusOK, response)

		return
	}

	response, err := h.server.AssistantManager.ChatStream(ctx, messages)
	if err != nil {
		logger.WithError(err).Error("unable to chat (stream) with assistant")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	for k, v := range response.Header {
		for _, val := range v {
			w.Header().Add(k, val)
		}
	}

	w.WriteHeader(response.StatusCode)

	// Stream response back to client as quickly as it comes in
	var n, total int
	buf := make([]byte, 1024)

	for {
		n, err = response.Body.Read(buf)
		if n > 0 {
			total += n

			_, writeErr := w.Write(buf[:n])
			if writeErr != nil {
				logger.WithError(writeErr).Error("client appears to have closed the connection")
				break
			}

			flusher.Flush()

			logger.WithFields(log.Fields{
				"mostRecentBufferSize": n,
				"totalTransferred":     total,
			}).Debug("streaming AI response")
		}
		if err != nil {
			break // EOF or error, exit loop
		}
	}
	if err != io.EOF {
		logger.WithError(err).Error("problem while streaming response")
		return
	}
}

func (h *AssistantHandler) GetBalance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	response, err := h.server.AssistantManager.Balance(ctx)
	if err != nil {
		logger.WithError(err).Error("unable to chat with assistant")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	web.Respond(w, r, http.StatusOK, response)
}
