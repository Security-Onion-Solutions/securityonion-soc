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
		r.Get("/sessions", h.GetSessions)
		r.Get("/sessions/{sessionId}", h.GetSessionHistory)
		r.Delete("/sessions/{sessionId}", h.DeleteSession)
	})
}

func (h *AssistantHandler) PostChat(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	accept := strings.TrimSpace(r.Header.Get("Accept"))
	streaming := strings.EqualFold(accept, "text/event-stream")

	type TempBody struct {
		Msg       string `json:"msg"`
		SessionId string `json:"sessionId"`
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
		ContentBlocks: []model.ContentBlock{
			{
				Type: "text",
				Text: tb.Msg,
			},
		},
	}

	stored, err := h.server.Assistantstore.GetChatHistory(ctx, tb.SessionId)
	if err != nil {
		logger.WithError(err).Error("unable to get chat history")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	messages := make([]*model.Message, 0, len(stored))
	for _, msg := range stored {
		messages = append(messages, msg.Message)
	}

	err = h.server.Assistantstore.SaveChat(ctx, newMsg.PrepareForStorage(tb.SessionId, nil))
	if err != nil {
		logger.WithError(err).Error("unable to save chat message")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	messages = append(messages, newMsg)

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

		for _, msg := range response {
			err = h.server.Assistantstore.SaveChat(ctx, msg.PrepareForStorage(tb.SessionId, nil))
			if err != nil {
				logger.WithError(err).Error("unable to save chat message")
				return
			}
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

	entireResponse, err := streamResponse(ctx, w, r, response)
	if err != nil {
		logger.WithError(err).Error("error streaming response")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	noTimeOutCtx := context.Background()
	val := ctx.Value(web.ContextKeyRunAsUsername)
	if val != nil {
		if username, ok := val.(string); ok {
			noTimeOutCtx = context.WithValue(noTimeOutCtx, web.ContextKeyRunAsUsername, username)
		}
	}
	noTimeOutCtx = context.WithValue(noTimeOutCtx, web.ContextKeyRequestorId, ctx.Value(web.ContextKeyRequestorId).(string))

	go func() {
		msg, err := unstreamResponse(string(entireResponse))
		if err != nil {
			logger.WithError(err).Error("error unstreaming response")
			return
		}

		if msg != nil {
			err = h.server.Assistantstore.SaveChat(noTimeOutCtx, msg.PrepareForStorage(tb.SessionId, nil))
			if err != nil {
				logger.WithError(err).Error("unable to save chat message")
				return
			}
		}
	}()
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
	}

	encoded, err := json.Marshal(result.Result)
	if err != nil {
		logger.WithError(err).Error("unable to marshal tool result")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	toolMsg := &model.Message{
		Id:   uuid.NewString(),
		Role: "user",
		ContentBlocks: []model.ContentBlock{
			{
				Type: "text",
				Text: fmt.Sprintf("ToolUseId: %s, Result: %s", toolReq.ToolUseId, string(encoded)),
			},
		},
	}

	stored, err := h.server.Assistantstore.GetChatHistory(ctx, toolReq.SessionId)
	if err != nil {
		logger.WithError(err).Error("unable to get chat history")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	messages := make([]*model.Message, 0, len(stored))
	for _, msg := range stored {
		messages = append(messages, msg.Message)
	}

	err = h.server.Assistantstore.SaveChat(ctx, toolMsg.PrepareForStorage(toolReq.SessionId, []string{"tool_result"}))
	if err != nil {
		logger.WithError(err).Error("unable to save tool result message")
		return
	}

	messages = append(messages, toolMsg)

	if !streaming {
		response, err := h.server.AssistantManager.Chat(ctx, messages)
		if err != nil {
			logger.WithError(err).Error("unable to chat with assistant after tool execution")
			web.Respond(w, r, http.StatusInternalServerError, err)

			return
		}

		web.Respond(w, r, http.StatusOK, response)

		for _, msg := range response {
			err = h.server.Assistantstore.SaveChat(ctx, msg.PrepareForStorage(toolReq.SessionId, nil))
			if err != nil {
				logger.WithError(err).Error("unable to save tool result response message")
				return
			}
		}

		return
	}

	response, err := h.server.AssistantManager.ChatStream(ctx, messages)
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

	noTimeOutCtx := context.Background()
	val := ctx.Value(web.ContextKeyRunAsUsername)
	if val != nil {
		if username, ok := val.(string); ok {
			noTimeOutCtx = context.WithValue(noTimeOutCtx, web.ContextKeyRunAsUsername, username)
		}
	}
	noTimeOutCtx = context.WithValue(noTimeOutCtx, web.ContextKeyRequestorId, ctx.Value(web.ContextKeyRequestorId).(string))

	go func() {
		msg, err := unstreamResponse(string(entireResponse))
		if err != nil {
			logger.WithError(err).Error("error unstreaming response")
			return
		}

		if msg != nil {
			err = h.server.Assistantstore.SaveChat(noTimeOutCtx, msg.PrepareForStorage(toolReq.SessionId, nil))
			if err != nil {
				logger.WithError(err).Error("unable to save chat message")
				return
			}
		}
	}()
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

func (h *AssistantHandler) GetSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	userId := ctx.Value(web.ContextKeyRequestorId).(string)

	sessions, err := h.server.Assistantstore.GetPreviousConversations(ctx, userId)
	if err != nil {
		logger.WithError(err).Error("unable to get previous conversations")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	web.Respond(w, r, http.StatusOK, sessions)
}

func (h *AssistantHandler) GetSessionHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	sessionId := chi.URLParam(r, "sessionId")
	if sessionId == "" {
		logger.Error("sessionId is required")
		web.Respond(w, r, http.StatusBadRequest, "sessionId is required")

		return
	}

	history, err := h.server.Assistantstore.GetChatHistory(ctx, sessionId)
	if err != nil {
		logger.WithError(err).Error("unable to get chat history for session")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	web.Respond(w, r, http.StatusOK, history)
}

func (h *AssistantHandler) DeleteSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	sessionId := chi.URLParam(r, "sessionId")
	if sessionId == "" {
		logger.Error("sessionId is required")
		web.Respond(w, r, http.StatusBadRequest, "sessionId is required")

		return
	}

	err := h.server.Assistantstore.DeleteSession(ctx, sessionId)

	if err != nil {
		logger.WithError(err).Error("unable to delete session")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	web.Respond(w, r, http.StatusNoContent, nil)
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
		if strings.TrimSpace(msg.Data) == "[DONE]" {
			break
		}

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
				if len(message.ContentBlocks) == 0 {
					message.ContentBlocks = []model.ContentBlock{{}}
				}
			}
		case "content_block_start":
			for sm.Index >= len(message.ContentBlocks) {
				message.ContentBlocks = append(message.ContentBlocks, model.ContentBlock{})
			}

			if sm.ContentBlock != nil {
				if string(sm.ContentBlock.Input) == "{}" {
					sm.ContentBlock.Input = json.RawMessage("")
				}
				message.ContentBlocks[sm.Index] = *sm.ContentBlock
			}
		case "content_block_delta":
			if sm.Delta != nil {
				switch sm.Delta.Type {
				case "text_delta":
					if message.ContentBlocks[sm.Index].Content == nil {
						message.ContentBlocks[sm.Index].Content = ""
					}

					message.ContentBlocks[sm.Index].Content = message.ContentBlocks[sm.Index].Content.(string) + sm.Delta.Text
				case "input_json_delta":
					message.ContentBlocks[sm.Index].Input = json.RawMessage(string(message.ContentBlocks[sm.Index].Input) + *sm.Delta.PartialJson)
				}
			}
		case "content_block_stop":
			if message.ContentBlocks[sm.Index].Type == "" {
				message.ContentBlocks[sm.Index].Type = "text"
				message.ContentBlocks[sm.Index].Text = message.ContentBlocks[sm.Index].Content.(string)
				message.ContentBlocks[sm.Index].Content = nil
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
