// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

	sse_parser "github.com/GiGurra/sse-parser"
	"github.com/apex/log"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
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
		r.Post("/tool/{name}", h.PostTool)
		r.Get("/balance", h.GetBalance)
	})
}

func (h *AssistantHandler) PostChat(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	accept := strings.TrimSpace(r.Header.Get("Accept"))
	streaming := strings.EqualFold(accept, "text/event-stream")

	type TempBody struct {
		Msg       string           `json:"msg"`
		Messages  []*model.Message `json:"messages"`
		SessionId string           `json:"sessionId"`
	}

	tb := &TempBody{}
	err := json.NewDecoder(r.Body).Decode(tb)
	if err != nil {
		logger.WithError(err).Error("unable to decode request body")
		web.Respond(w, r, http.StatusBadRequest, err)

		return
	}

	if tb.SessionId == "" {
		tb.SessionId = uuid.NewString()
	}

	newMsg := &model.Message{
		Role: "user",
		Content: []model.ContentBlock{
			{
				Type: "text",
				Text: tb.Msg,
			},
		},
	}

	err = h.server.Assistantstore.SaveChat(ctx, newMsg.PrepareForStorage(tb.SessionId))
	if err != nil {
		logger.WithError(err).Error("unable to save chat message")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	// use provided messages for now, eventually look up history by session ID
	messages := append(tb.Messages, newMsg)

	_, ok := w.(http.Flusher)
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

		err = h.server.Assistantstore.SaveChat(ctx, response.PrepareForStorage(tb.SessionId))
		if err != nil {
			logger.WithError(err).Error("unable to save chat message")
			return
		}

		return
	}

	response, err := h.server.AssistantManager.ChatStream(ctx, messages)
	if err != nil {
		logger.WithError(err).Error("unable to chat (stream) with assistant")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	entireResponse, err := streamResponse(ctx, w, r, response)
	if err != nil {
		logger.WithError(err).Error("error streaming response")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	msg, err := unstreamResponse(string(entireResponse))
	if err != nil {
		logger.WithError(err).Error("error unstreaming response")
		return
	}

	err = h.server.Assistantstore.SaveChat(ctx, msg.PrepareForStorage(tb.SessionId))
	if err != nil {
		logger.WithError(err).Error("unable to save chat message")
		return
	}
}

func (h *AssistantHandler) PostTool(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	accept := strings.TrimSpace(r.Header.Get("Accept"))
	streaming := strings.EqualFold(accept, "text/event-stream")

	toolName := chi.URLParam(r, "name")
	toolReq := &model.ToolRequest{}

	err := json.NewDecoder(r.Body).Decode(&toolReq)
	if err != nil {
		logger.WithError(err).Error("unable to decode request body")
		web.Respond(w, r, http.StatusBadRequest, err)

		return
	}

	result, err := h.server.AssistantManager.ExecuteTool(ctx, toolName, string(toolReq.Params))
	if err != nil {
		logger.WithError(err).Error("unable to execute tool")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	content, err := json.Marshal(result.Result)
	if err != nil {
		logger.WithError(err).Error("unable to marshal tool result")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	toolMsg := &model.Message{
		Role: "user",
		Content: []model.ContentBlock{
			{
				Type:      "tool_result",
				ToolUseID: toolReq.ToolUseId,
				Content:   string(content),
			},
		},
	}

	err = h.server.Assistantstore.SaveChat(ctx, toolMsg.PrepareForStorage(toolReq.SessionId))
	if err != nil {
		logger.WithError(err).Error("unable to save tool result message")
		return
	}

	msgs := append(toolReq.History, toolMsg)

	if !streaming {
		response, err := h.server.AssistantManager.Chat(ctx, msgs)
		if err != nil {
			logger.WithError(err).Error("unable to chat with assistant after tool execution")
			web.Respond(w, r, http.StatusInternalServerError, err)

			return
		}

		web.Respond(w, r, http.StatusOK, response)

		err = h.server.Assistantstore.SaveChat(ctx, response.PrepareForStorage(toolReq.SessionId))
		if err != nil {
			logger.WithError(err).Error("unable to save tool result response message")
			return
		}
		return
	}

	response, err := h.server.AssistantManager.ChatStream(ctx, msgs)
	if err != nil {
		logger.WithError(err).Error("unable to chat (stream) with assistant after tool execution")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	entireResponse, err := streamResponse(ctx, w, r, response)
	if err != nil {
		logger.WithError(err).Error("error streaming response after tool execution")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	msg, err := unstreamResponse(string(entireResponse))
	if err != nil {
		logger.WithError(err).Error("error unstreaming response")
		return
	}

	err = h.server.Assistantstore.SaveChat(ctx, msg.PrepareForStorage(toolReq.SessionId))
	if err != nil {
		logger.WithError(err).Error("unable to save chat message")
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

func streamResponse(ctx context.Context, w http.ResponseWriter, r *http.Request, response *http.Response) (entireResponse []byte, err error) {
	logger := log.FromContext(ctx)
	flusher, ok := w.(http.Flusher)
	if !ok {
		logger.Error("response writer does not support flushing, cannot stream response")
		web.Respond(w, r, http.StatusInternalServerError, "streaming not supported")

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
	last := time.Now()
	entireResponse = []byte{}

	for {
		n, err = response.Body.Read(buf)
		if n > 0 {
			total += n
			entireResponse = append(entireResponse, buf[:n]...)

			_, writeErr := w.Write(buf[:n])
			if writeErr != nil {
				logger.WithError(writeErr).Error("client appears to have closed the connection")
				break
			}

			flusher.Flush()

			since := time.Since(last)
			last = time.Now()

			logger.WithFields(log.Fields{
				"mostRecentBufferSize": n,
				"totalTransferred":     total,
				"timeSinceLastChunk":   since.String(),
			}).Debug("streaming AI response")
		}
		if err != nil {
			break // EOF or error, exit loop
		}
	}

	logger.WithField("entireResponse", string(entireResponse)).Debug("entire response streamed")

	if err == io.EOF {
		err = nil // EOF is not an error in this context
	}

	return entireResponse, err
}

func unstreamResponse(rawResponse string) (*model.Message, error) {
	type Delta struct {
		Type        string  `json:"type"`
		Text        string  `json:"text,omitempty"`
		PartialJson *string `json:"partial_json,omitempty"`
		StopReason  *string `json:"stop_reason,omitempty"`
	}

	type StreamingMessage struct {
		Type         string              `json:"type"`
		Index        int                 `json:"index"`
		Message      *model.Message      `json:"message"`
		Delta        *Delta              `json:"delta"`
		ContentBlock *model.ContentBlock `json:"content_block,omitempty"`
		Usage        *model.Usage        `json:"usage,omitempty"`
	}

	// Create a parser without a completion function
	parser := sse_parser.NewParser(nil)

	dataMsgs := parser.Add(rawResponse)
	dataMsgs = append(dataMsgs, parser.Finish()...)
	var message *model.Message

	for _, msg := range dataMsgs {
		var sm StreamingMessage
		err := json.Unmarshal([]byte(msg.Data), &sm)
		if err != nil {
			fmt.Printf("Error unmarshalling JSON: %v\n", err)
			continue
		}

		switch sm.Type {
		case "message_start":
			if sm.Message != nil {
				message = sm.Message
				if len(message.Content) == 0 {
					message.Content = []model.ContentBlock{{}}
				}
			}
		case "content_block_start":
			for sm.Index >= len(message.Content) {
				message.Content = append(message.Content, model.ContentBlock{})
			}

			if sm.ContentBlock != nil {
				message.Content[sm.Index] = *sm.ContentBlock
			}
		case "content_block_delta":
			if sm.Delta != nil {
				switch sm.Delta.Type {
				case "text_delta":
					message.Content[sm.Index].Content += sm.Delta.Text
				case "input_json_delta":
					message.Content[sm.Index].Input += *sm.Delta.PartialJson
				}
			}
		case "message_delta":
			if sm.Usage != nil {
				message.Usage = sm.Usage
			}
			if sm.Delta != nil && sm.Delta.StopReason != nil {
				message.StopReason = new(string)
				*message.StopReason = *sm.Delta.StopReason
			}
		}
	}

	return message, nil
}
