// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
	"slices"
	"strings"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/util"
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
		r.Get("/balance/*", h.GetBalance)
		r.Get("/sessions", h.GetSessions)
		r.Get("/sessions/{sessionId}", h.GetSessionDetails)
		r.Put("/sessions/{sessionId}", h.UpdateSession)
		r.Delete("/sessions/{sessionId}", h.DeleteSession)

		r.Get("/admin/stats", h.GetUsage)
		r.Get("/admin/sessions", h.getAllSessions)
		r.Get("/admin/{userId}/sessions", h.GetSessionsAdmin)
		r.Get("/admin/{userId}/sessions/{sessionId}/history", h.ManageSessionHistory)
	})
}

func (h *AssistantHandler) checkAssistantAvailable(ctx context.Context, w http.ResponseWriter, r *http.Request) bool {
	if h.server != nil && h.server.Config != nil && h.server.Config.AirgapEnabled {
		log.FromContext(ctx).Error("unable to use assistant on airgap installation")
		web.Respond(w, r, http.StatusInternalServerError, "ERROR_SERVICE_NOT_AVAILABLE")
		return false
	}
	return true
}

// @Summary      Send Chat Message
// @Description  Send a message to the AI assistant and receive a response. Supports both streaming (SSE) and non-streaming responses.
// @Tags         Assistant
// @Security     bearer[assistant/write_authored]
// @Param        request  body  object{msg=string,sessionId=string} true "Chat message object with message text and optional session ID"
// @Param        investigationSocId query string false "corresponding alert's soc_id for investigation sessions"
// @Accept       json
// @Produce      json,text/event-stream
// @Success      200  {array}   model.Message "AI assistant response messages"
// @Failure      400           "The provided input object or parameters are malformed or invalid"
// @Failure      401           "Request was not properly authenticated"
// @Failure      403           "Insufficient permissions for this request"
// @Failure      500           "Internal SOC error; review SOC logs"
// @Router       /api/assistant/chat [post]
func (h *AssistantHandler) PostChat(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	err := h.server.CheckAuthorized(ctx, "write_authored", "assistant")
	if err != nil {
		web.Respond(w, r, http.StatusUnauthorized, err)
		return
	}

	if !h.checkAssistantAvailable(ctx, w, r) {
		return
	}

	accept := strings.TrimSpace(r.Header.Get("Accept"))
	streaming := strings.EqualFold(accept, "text/event-stream")

	incMsg := &model.IncomingMessage{}
	err = json.NewDecoder(r.Body).Decode(incMsg)
	if err != nil {
		logger.WithError(err).Error("unable to decode request body")
		web.Respond(w, r, http.StatusBadRequest, err)

		return
	}

	if incMsg.SessionId == "" {
		incMsg.SessionId = uuid.NewString()
	}

	// Check for investigationSocId query parameter
	investigationSocId := r.URL.Query().Get("investigationSocId")
	if investigationSocId != "" {
		// Mark the alert as investigated with the session ID
		err = h.markAlertAsInvestigated(ctx, investigationSocId, incMsg.SessionId)
		if err != nil {
			logger.WithError(err).WithField("investigationSocId", investigationSocId).Warn("unable to mark alert as investigated")
			// Don't fail the request, just log the warning
		}
	}

	newMsg := &model.Message{
		Role: "user",
		ContentBlocks: []model.ContentBlock{
			{
				Type: "text",
				Text: incMsg.Msg,
			},
		},
	}

	history, err := h.server.Assistantstore.GetChatHistory(ctx, incMsg.SessionId)
	if err != nil && !strings.Contains(err.Error(), "not found") {
		logger.WithError(err).Error("unable to get chat history")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	if len(history) == 0 {
		// create new session
		session := &model.AssistantSession{
			SessionId: incMsg.SessionId,
			Title:     incMsg.Msg,
		}

		// If this is an investigation session, set the type and entityId
		if investigationSocId != "" {
			session.Type = "alert_investigation"
			session.EntityId = investigationSocId
		}

		err = h.server.Assistantstore.CreateSession(ctx, session)
		if err != nil {
			logger.WithError(err).Error("unable to create session")
			web.Respond(w, r, http.StatusInternalServerError, err)

			return
		}
	}

	messages := historyToContext(history)

	err = h.server.Assistantstore.SaveChat(ctx, newMsg.PrepareForStorage(incMsg.SessionId, incMsg.Tags))
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
		response, err := h.server.AssistantManager.Chat(ctx, incMsg.Model, messages)
		if err != nil {
			logger.WithError(err).Error("unable to chat with assistant")
			web.Respond(w, r, http.StatusInternalServerError, "ERROR_UPSTREAM_SERVICE_ERROR")

			return
		}

		for _, msg := range response {
			err = h.server.Assistantstore.SaveChat(ctx, msg.PrepareForStorage(incMsg.SessionId, nil))
			if err != nil {
				logger.WithError(err).Error("unable to save chat message")
				return
			}
		}

		web.Respond(w, r, http.StatusOK, response)

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

	response, aux, err := h.server.AssistantManager.ChatStream(noTimeOutCtx, incMsg.Model, messages)
	if err != nil {
		logger.WithError(err).Error("unable to chat (stream) with assistant")
		web.Respond(w, r, http.StatusInternalServerError, "ERROR_UPSTREAM_SERVICE_ERROR")

		return
	}

	entireResponse, err := streamResponse(ctx, w, r, response)
	if err != nil {
		logger.WithError(err).Error("error streaming response")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	go func() {
		msg, err := unstreamResponse(noTimeOutCtx, string(entireResponse), aux)
		if err != nil {
			logger.WithError(err).Error("error unstreaming response")
			return
		}

		if msg != nil {
			err = h.server.Assistantstore.SaveChat(noTimeOutCtx, msg.PrepareForStorage(incMsg.SessionId, nil))
			if err != nil {
				logger.WithError(err).Error("unable to save chat message")
				return
			}
		}
	}()
}

// @Summary      Execute Tool
// @Description  Execute a tool on behalf of the assistant and continue the conversation with the result. Note that more permissions may be checked depending on the tool being executed.
// @Tags         Assistant
// @Security     bearer[assistant/write_authored]
// @Param        name     path  string              true  "Name of the tool to execute"
// @Param        request  body  model.ToolRequest   true  "Tool execution request containing session ID, tool use ID, and parameters"
// @Accept       json
// @Produce      json,text/event-stream
// @Success      200  {array}   model.Message "AI assistant response messages after tool execution"
// @Failure      400           "The provided input object or parameters are malformed or invalid"
// @Failure      401           "Request was not properly authenticated"
// @Failure      403           "Insufficient permissions for this request"
// @Failure      500           "Internal SOC error; review SOC logs"
// @Router       /api/assistant/tool/{name} [post]
func (h *AssistantHandler) PostTool(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	err := h.server.CheckAuthorized(ctx, "write_authored", "assistant")
	if err != nil {
		web.Respond(w, r, http.StatusUnauthorized, err)
		return
	}

	if !h.checkAssistantAvailable(ctx, w, r) {
		return
	}

	accept := strings.TrimSpace(r.Header.Get("Accept"))
	streaming := strings.EqualFold(accept, "text/event-stream")

	toolName := chi.URLParam(r, "name")
	toolReq := &model.ToolRequest{}

	err = json.NewDecoder(r.Body).Decode(&toolReq)
	if err != nil {
		logger.WithError(err).Error("unable to decode request body")
		web.Respond(w, r, http.StatusBadRequest, err)

		return
	}

	result, toolErr := h.server.AssistantManager.ExecuteTool(ctx, toolName, string(toolReq.Params), string(toolReq.AuxData))
	if toolErr != nil {
		logger.WithError(toolErr).Error("unable to execute tool")
	}

	var toolResult *model.ToolResult
	if toolErr != nil {
		toolResult = &model.ToolResult{
			ToolUseId: toolReq.ToolUseId,
			Status:    "error",
			IsError:   true,
			Content: []model.ToolResultContent{
				{
					Text: toolErr.Error(),
				},
			},
		}
	} else {
		var res any
		if result != nil {
			res = map[string]any{
				"result": result.Result,
			}
		}
		toolResult = &model.ToolResult{
			Name:      result.ToolName,
			ToolUseId: toolReq.ToolUseId,
			Content: []model.ToolResultContent{
				{
					Json: res,
				},
			},
		}
	}

	toolMsg := &model.Message{
		Id:   uuid.NewString(),
		Role: "user",
		ContentBlocks: []model.ContentBlock{
			{
				ToolResult: toolResult,
			},
		},
	}

	err = h.server.Assistantstore.SaveChat(ctx, toolMsg.PrepareForStorage(toolReq.SessionId, []string{"tool_result"}))
	if err != nil {
		logger.WithError(err).Error("unable to save tool result message")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	history, err := h.server.Assistantstore.GetChatHistory(ctx, toolReq.SessionId)
	if err != nil {
		logger.WithError(err).Error("unable to get chat history")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	messages := historyToContext(history)

	if !streaming {
		response, err := h.server.AssistantManager.Chat(ctx, toolReq.Model, messages)
		if err != nil {
			logger.WithError(err).Error("unable to chat with assistant after tool execution")
			web.Respond(w, r, http.StatusInternalServerError, "ERROR_UPSTREAM_SERVICE_ERROR")

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

	response, aux, err := h.server.AssistantManager.ChatStream(ctx, toolReq.Model, messages)
	if err != nil {
		logger.WithError(err).Error("unable to chat (stream) with assistant after tool execution")
		web.Respond(w, r, http.StatusInternalServerError, "ERROR_UPSTREAM_SERVICE_ERROR")

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
		msg, err := unstreamResponse(noTimeOutCtx, string(entireResponse), aux)
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

// @Summary      Get Assistant Balance
// @Description  Retrieve the current balance/usage information for the AI assistant.
// @Tags         Assistant
// @Security     bearer[assistant/read_authored]
// @Security     bearer[assistant/read_all]
// @Produce      json
// @Success      200  {object}  model.Usage "Current assistant balance and usage information"
// @Failure      401           "Request was not properly authenticated"
// @Failure      403           "Insufficient permissions for this request"
// @Failure      500           "Internal SOC error; review SOC logs"
// @Router       /api/assistant/balance [get]
func (h *AssistantHandler) GetBalance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	self := h.server.CheckAuthorized(ctx, "read_authored", "assistant")
	all := h.server.CheckAuthorized(ctx, "read_all", "assistant")
	if self != nil && all != nil {
		web.Respond(w, r, http.StatusUnauthorized, self)
		return
	}

	if !h.checkAssistantAvailable(ctx, w, r) {
		return
	}

	model := chi.URLParam(r, "*")

	health, err := h.server.AssistantManager.Health(ctx, model)
	if err != nil {
		logger.WithError(err).Error("unable to get assistant health")
		web.Respond(w, r, http.StatusInternalServerError, "ERROR_UPSTREAM_SERVICE_ERROR")
		return
	}

	if health == nil || health.Status == "" {
		logger.WithField("healthResponse", health).Warn("assistant health response is nil or missing status")
		web.Respond(w, r, http.StatusInternalServerError, nil)
		return
	}

	response, err := h.server.AssistantManager.Balance(ctx, model)
	if err != nil {
		logger.WithError(err).Error("unable to retrieve balance")
		web.Respond(w, r, http.StatusInternalServerError, "ERROR_UPSTREAM_SERVICE_ERROR")
		return
	}

	response.HealthStatus = health.Status

	web.Respond(w, r, http.StatusOK, response)
}

// @Summary      Get Assistant Sessions
// @Description  Retrieve a list of all previous chat session metadata for the authenticated user.
// @Tags         Assistant
// @Security     bearer[assistant/read_authored]
// @Produce      json
// @Success      200  {array}   model.AssistantSession "List of previous conversation session metadata"
// @Failure      401           "Request was not properly authenticated"
// @Failure      403           "Insufficient permissions for this request"
// @Failure      500           "Internal SOC error; review SOC logs"
// @Router       /api/assistant/sessions [get]
func (h *AssistantHandler) GetSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	err := h.server.CheckAuthorized(ctx, "read_authored", "assistant")
	if err != nil {
		web.Respond(w, r, http.StatusUnauthorized, err)
		return
	}

	userId := ctx.Value(web.ContextKeyRequestorId).(string)

	sessions, err := h.server.Assistantstore.GetSessions(ctx, model.GetSessionsWithUserId(userId))
	if err != nil {
		logger.WithError(err).Error("unable to get previous conversations")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	web.Respond(w, r, http.StatusOK, sessions)
}

// @Summary      Get Session Details
// @Description  Retrieve the complete chat history and usage for a specific session. Can lookup deleted sessions.
// @Tags         Assistant
// @Security     bearer[assistant/read_authored]
// @Security     bearer[assistant/read_shared]
// @Param        sessionId  path  string  true  "Session ID to retrieve history for"
// @Produce      json
// @Success      200 {object} model.AssistantSessionDetails "Complete chat history and session details"
// @Failure      400           "The provided session ID is invalid or missing"
// @Failure      401           "Request was not properly authenticated"
// @Failure      403           "Insufficient permissions for this request"
// @Failure      500           "Internal SOC error; review SOC logs"
// @Router       /api/assistant/sessions/{sessionId} [get]
func (h *AssistantHandler) GetSessionDetails(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	err := h.server.CheckAuthorized(ctx, "read_authored", "assistant")
	if err != nil {
		web.Respond(w, r, http.StatusUnauthorized, err)
		return
	}

	sessionId := chi.URLParam(r, "sessionId")
	if sessionId == "" {
		logger.Error("sessionId is required")
		web.Respond(w, r, http.StatusBadRequest, "sessionId is required")

		return
	}

	session, err := h.server.Assistantstore.GetSessions(ctx, model.GetSessionsWithSessionId(sessionId), model.GetSessionsWithIncludeDeleted(true), model.GetSessionsWithUsage(true))
	if err != nil {
		logger.WithError(err).Error("unable to get session")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	if len(session) == 0 {
		web.Respond(w, r, http.StatusOK, &model.AssistantSessionDetails{})

		return
	}

	history, err := h.server.Assistantstore.GetChatHistory(ctx, sessionId)
	if err != nil {
		logger.WithError(err).Error("unable to get chat history for session")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	removeAuxData(history)

	web.Respond(w, r, http.StatusOK, &model.AssistantSessionDetails{
		Session: session[0],
		History: history,
	})
}

// @Summary      Update metadata for a Session
// @Description  Allow a user to modify their own session tags.
// @Tags         Assistant
// @Security     bearer[assistant/write_authored]
// @Param        sessionId  path  string  true  "Session ID to modify"
// @Param        request  body  model.UpdateSessionRequest   true  "Indicate what field we're doing what operation with."
// @Produce      json
// @Success      206           "No content"
// @Failure      400           "The provided session ID is invalid or missing"
// @Failure      401           "Request was not properly authenticated"
// @Failure      403           "Insufficient permissions for this request"
// @Failure      404           "Session not found"
// @Failure      500           "Internal SOC error; review SOC logs"
// @Router       /api/assistant/sessions/{sessionId} [put]
func (h *AssistantHandler) UpdateSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	err := h.server.CheckAuthorized(ctx, "write_authored", "assistant")
	if err != nil {
		web.Respond(w, r, http.StatusUnauthorized, err)
		return
	}

	sessionId := chi.URLParam(r, "sessionId")
	if sessionId == "" {
		logger.Error("sessionId is required")
		web.Respond(w, r, http.StatusBadRequest, "sessionId is required")

		return
	}

	updateReq := &model.UpdateSessionRequest{}

	err = json.NewDecoder(r.Body).Decode(updateReq)
	if err != nil {
		logger.WithError(err).Error("unable to decode request body")
		web.Respond(w, r, http.StatusBadRequest, err)

		return
	}

	sessions, err := h.server.Assistantstore.GetSessions(ctx, model.GetSessionsWithSessionId(sessionId))
	if err != nil {
		logger.WithError(err).Error("unable to get session")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	if len(sessions) == 0 {
		logger.Error("session not found")
		web.Respond(w, r, http.StatusNotFound, "session not found")

		return
	}

	session := sessions[0]

	switch updateReq.Action {
	case "add":
		if !slices.Contains(session.Tags, updateReq.Tag) {
			session.Tags = append(session.Tags, updateReq.Tag)
		} else {
			logger.Warn("tag already exists on session")
			web.Respond(w, r, http.StatusConflict, "tag already exists on session")

			return
		}
	case "remove":
		err = h.canRemoveTag(ctx, session, updateReq.Tag)
		if err != nil {
			logger.WithFields(log.Fields{
				"assistantSessionId": sessionId,
				"tag":                updateReq.Tag,
			}).Error("unable to remove tag")
			web.Respond(w, r, http.StatusConflict, err)

			return
		}
		session.Tags = slices.Delete(session.Tags, slices.Index(session.Tags, updateReq.Tag), slices.Index(session.Tags, updateReq.Tag)+1)
	}

	err = h.server.Assistantstore.UpdateSessionTags(ctx, sessionId, session.Tags)
	if err != nil {
		logger.WithError(err).Error("unable to update session")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	web.Respond(w, r, http.StatusNoContent, nil)
}

func (h *AssistantHandler) canRemoveTag(ctx context.Context, session *model.AssistantSession, tag string) error {
	if !slices.Contains(session.Tags, tag) {
		return fmt.Errorf("session does not have tag")
	}

	cases, err := h.server.Casestore.GetCaseIdsWithArtifact(ctx, "assistant_chat", session.SessionId)
	if err != nil {
		return err
	}

	if len(cases) != 0 {
		return fmt.Errorf("ERROR_SESSION_ATTACHED_TO_CASES %d", len(cases))
	}

	return nil
}

// @Summary      Delete Session
// @Description  Delete a specific chat session and all its associated messages.
// @Tags         Assistant
// @Security     bearer[assistant/delete_authored]
// @Param        sessionId  path  string  true  "Session ID to delete"
// @Success      204           "Session successfully deleted"
// @Failure      400           "The provided session ID is invalid or missing"
// @Failure      401           "Request was not properly authenticated"
// @Failure      403           "Insufficient permissions for this request"
// @Failure      500           "Internal SOC error; review SOC logs"
// @Router       /api/assistant/sessions/{sessionId} [delete]
func (h *AssistantHandler) DeleteSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	err := h.server.CheckAuthorized(ctx, "delete_authored", "assistant")
	if err != nil {
		web.Respond(w, r, http.StatusUnauthorized, err)
		return
	}

	sessionId := chi.URLParam(r, "sessionId")
	if sessionId == "" {
		logger.Error("sessionId is required")
		web.Respond(w, r, http.StatusBadRequest, "sessionId is required")

		return
	}

	err = h.server.Assistantstore.DeleteSession(ctx, sessionId)

	if err != nil {
		logger.WithError(err).Error("unable to delete session")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	web.Respond(w, r, http.StatusNoContent, nil)
}

// @Summary      Get Usage Statistics
// @Description  Retrieve usage statistics of the AI assistant over a specified date range for every user.
// @Tags         Assistant
// @Param        range  query  string  true "Date range, in the specified timezone" example(2024/12/03 03:09:31 PM - 2024/12/04 03:09:31 PM)
// @Param        zone  query  string  true "Timezone of the date range" example(America/New_York)
// @Param        format  query  string  true "Date range date format. Use the example, exactly as shown, if not familiar with date formats" example(2006/01/02 3:04:05 PM)
// @Security     bearer[assistant/read_all]
// @Produce      json
// @Success      200  {array}   model.UserUsage "Usage statistics for the AI assistant"
// @Failure      400           "The provided date range is invalid or missing"
// @Failure      401           "Request was not properly authenticated"
// @Failure      403           "Insufficient permissions for this request"
// @Failure      500           "Internal SOC error; review SOC logs"
// @Router       /api/assistant/admin/stats [get]
func (h *AssistantHandler) GetUsage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	err := h.server.CheckAuthorized(ctx, "read_all", "assistant")
	if err != nil {
		web.Respond(w, r, http.StatusUnauthorized, err)
		return
	}

	err = r.ParseForm()
	if err != nil {
		logger.WithError(err).Error("unable to parse query string")
		web.Respond(w, r, http.StatusBadRequest, err)

		return
	}

	start, end, err := util.ParseDateRange(r.Form.Get("range"), r.Form.Get("format"), r.Form.Get("zone"))
	if err != nil {
		logger.WithError(err).Error("unable to parse date range from query string")
		web.Respond(w, r, http.StatusBadRequest, err)

		return
	}

	usage, err := h.server.Assistantstore.GetUsage(ctx, start, end)
	if err != nil {
		logger.WithError(err).Error("unable to get usage")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	web.Respond(w, r, http.StatusOK, usage)
}

// @Summary      Get Assistant Sessions
// @Description  Get a list of all previous chat session metadata across all users.
// @Tags         Assistant
// @Security     bearer[assistant/read_all]
// @Produce      json
// @Success      200  {array}   model.AssistantSession "List of previous chat session metadata"
// @Failure      401           "Request was not properly authenticated"
// @Failure      403           "Insufficient permissions for this request"
// @Failure      500           "Internal SOC error; review SOC logs"
// @Router       /api/assistant/admin/sessions [get]
func (h *AssistantHandler) getAllSessions(w http.ResponseWriter, r *http.Request) {
	h.GetSessionsAdmin(w, r)
}

// @Summary      Get Assistant Sessions
// @Description  Get chat session metadata from a specific user.
// @Tags         Assistant
// @Security     bearer[assistant/read_all]
// @Param        userId     path  string              true  "ID of the user to retrieve sessions from"
// @Produce      json
// @Success      200  {array}   model.AssistantSession "List of previous conversation sessions"
// @Failure      401           "Request was not properly authenticated"
// @Failure      403           "Insufficient permissions for this request"
// @Failure      500           "Internal SOC error; review SOC logs"
// @Router       /api/assistant/admin/{userId}/sessions [get]
func (h *AssistantHandler) GetSessionsAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	err := r.ParseForm()
	if err != nil {
		logger.WithError(err).Error("unable to parse query string")
		web.Respond(w, r, http.StatusBadRequest, err)

		return
	}

	err = h.server.CheckAuthorized(ctx, "read_all", "assistant")
	if err != nil {
		web.Respond(w, r, http.StatusUnauthorized, err)
		return
	}

	start, end, err := util.ParseDateRange(r.Form.Get("range"), r.Form.Get("format"), r.Form.Get("zone"))
	if err != nil {
		logger.WithError(err).Error("unable to parse date range from query string")
		web.Respond(w, r, http.StatusBadRequest, err)

		return
	}

	userId := chi.URLParam(r, "userId")

	opts := []model.GetSessionsOpt{
		model.GetSessionsWithRange(start, end),
		model.GetSessionsWithIncludeDeleted(true),
		model.GetSessionsWithUsage(true),
	}

	if userId != "" {
		opts = append(opts, model.GetSessionsWithUserId(userId))
	}

	sessions, err := h.server.Assistantstore.GetSessions(ctx, opts...)
	if err != nil {
		logger.WithError(err).Error("unable to manage sessions")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	web.Respond(w, r, http.StatusOK, sessions)
}

// @Summary      Get Assistant Session History
// @Description  Retrieve a chat session's messages for a given user and session.
// @Tags         Assistant
// @Security     bearer[assistant/read_all]
// @Param        userId     path  string              true  "ID of the user to retrieve the session from"
// @Param        sessionId  path  string              true  "ID of the session to retrieve, it must belong to the indicated user"
// @Produce      json
// @Success      200  {array}   model.StoredMessage "List of messages belonging to the session"
// @Failure      401           "Request was not properly authenticated"
// @Failure      403           "Insufficient permissions for this request"
// @Failure      500           "Internal SOC error; review SOC logs"
// @Router       /api/assistant/admin/{userId}/sessions/{sessionId}/history [get]
func (h *AssistantHandler) ManageSessionHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	err := h.server.CheckAuthorized(ctx, "read_all", "assistant")
	if err != nil {
		web.Respond(w, r, http.StatusUnauthorized, err)
		return
	}

	userId := chi.URLParam(r, "userId")
	sessionId := chi.URLParam(r, "sessionId")

	sessions, err := h.server.Assistantstore.GetSessions(ctx, model.GetSessionsWithUserId(userId), model.GetSessionsWithSessionId(sessionId), model.GetSessionsWithIncludeDeleted(true))
	if err != nil {
		logger.WithError(err).Error("unable to manage sessions")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	if len(sessions) == 0 {
		logger.WithFields(log.Fields{
			"userId":    userId,
			"sessionId": sessionId,
		}).Warn("no matching session found")
		web.Respond(w, r, http.StatusNotFound, "no matching session found")

		return
	}

	history, err := h.server.Assistantstore.GetChatHistory(ctx, sessionId)
	if err != nil {
		logger.WithError(err).Error("unable to manage session history")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	// Note: Do not convert to context, the UI gets the entire history

	web.Respond(w, r, http.StatusOK, history)
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

	if err == io.EOF {
		err = nil // EOF is not an error in this context
	}

	return entireResponse, err
}

func unstreamResponse(ctx context.Context, rawResponse string, aux *model.AuxMessageData) (*model.Message, error) {
	type Delta struct {
		Type        string  `json:"type"`
		Text        string  `json:"text,omitempty"`
		PartialJson *string `json:"partial_json,omitempty"`
		StopReason  *string `json:"stop_reason,omitempty"`
	}

	type ErrorResponse struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	}

	type StreamingMessage struct {
		Type         string              `json:"type"`
		Index        int                 `json:"index"`
		Message      *model.Message      `json:"message"`
		Delta        *Delta              `json:"delta"`
		ContentBlock *model.ContentBlock `json:"content_block,omitempty"`
		Usage        *model.Usage        `json:"usage,omitempty"`
		Error        ErrorResponse       `json:"error,omitempty"`
	}

	logger := log.FromContext(ctx)

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
			logger.WithError(err).Warn("unable to unmarshal streaming message JSON, skipping")
			continue
		}

		switch sm.Type {
		case "error":
			logger.WithFields(log.Fields{
				"errorType":    sm.Error.Type,
				"errorMessage": sm.Error.Message,
			}).Error("received error in streaming response")

			return nil, fmt.Errorf("type: %s, message: %s", sm.Error.Type, sm.Error.Message)
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
					for len(message.ContentBlocks) <= sm.Index {
						message.ContentBlocks = append(message.ContentBlocks, model.ContentBlock{
							Content: "",
						})
					}

					if message.ContentBlocks[sm.Index].Content == nil {
						message.ContentBlocks[sm.Index].Content = ""
					}

					message.ContentBlocks[sm.Index].Content = message.ContentBlocks[sm.Index].Content.(string) + sm.Delta.Text
				case "input_json_delta":
					message.ContentBlocks[sm.Index].Input = json.RawMessage(string(message.ContentBlocks[sm.Index].Input) + *sm.Delta.PartialJson)
				case "thought_delta":
					message.Thoughts += sm.Delta.Text
				}
			}
		case "content_block_stop":
			for sm.Index >= len(message.ContentBlocks) {
				message.ContentBlocks = append(message.ContentBlocks, model.ContentBlock{})
			}
			if message.ContentBlocks[sm.Index].Type == "" {
				message.ContentBlocks[sm.Index].Type = "text"
				if message.ContentBlocks[sm.Index].Content != nil {
					message.ContentBlocks[sm.Index].Text = message.ContentBlocks[sm.Index].Content.(string)
				} else {
					message.ContentBlocks[sm.Index].Text = ""
				}
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

	if aux != nil {
		for i := 0; i < len(message.ContentBlocks); i++ {
			cb := &message.ContentBlocks[i]
			if cb.Type == "tool_use" {
				ts, ok := aux.ThoughtSignatures[cb.Id]
				if ok {
					cb.ThoughtSignature = ts
				}
			}
		}
	}

	return message, nil
}

// Converts stored message history to only the messages that'll get sent as context.
func historyToContext(history []*model.StoredMessage) []*model.Message {
	messages := make([]*model.Message, 0, len(history))
	for _, msg := range history {
		if slices.Contains(msg.Tags, model.MessageTagContextCompression) {
			// drop older messages, keep capacity
			messages = messages[:0]
		}

		messages = append(messages, msg.Message)
	}

	return messages
}

func removeAuxData(messages []*model.StoredMessage) {
	for _, msg := range messages {
		for i := 0; i < len(msg.Message.ContentBlocks); i++ {
			cb := &msg.Message.ContentBlocks[i]
			cb.ThoughtSignature = nil
		}
	}
}

func (h *AssistantHandler) markAlertAsInvestigated(ctx context.Context, socId string, sessionId string) error {
	logger := log.FromContext(ctx)

	err := h.server.CheckAuthorized(ctx, "write", "events")
	if err != nil {
		return err
	}

	logger.WithFields(log.Fields{
		"socId":     socId,
		"sessionId": sessionId,
	}).Info("Marking alert as investigated")

	// Create update criteria to mark the alert as investigated
	updateCriteria := model.NewEventUpdateCriteria()
	userId := ctx.Value(web.ContextKeyRequestorId).(string)

	// Use the existing addUpdateScripts method with inv=true and sessionId
	if h.server.Eventstore != nil {
		if elasticStore, ok := h.server.Eventstore.(interface {
			AddUpdateScripts(updateCriteria *model.EventUpdateCriteria, timeNow time.Time, ack bool, esc bool, inv bool, userId string, sessionId ...string)
		}); ok {
			elasticStore.AddUpdateScripts(updateCriteria, time.Now(), false, false, true, userId, sessionId)
		} else {
			return fmt.Errorf("eventstore does not support investigation updates")
		}
	} else {
		return fmt.Errorf("eventstore is not available")
	}

	// Create a simple query to match the soc_id
	updateCriteria.ParsedQuery = model.NewQuery()
	searchSegment := model.NewSearchSegmentEmpty()
	searchSegment.AddFilter("soc_id", socId, true, true, false)
	updateCriteria.ParsedQuery.AddSegment(searchSegment)
	updateCriteria.Asynchronous = false

	// Execute the update
	results, err := h.server.Eventstore.Update(ctx, updateCriteria)
	if err != nil {
		return err
	}

	if results.UpdatedCount == 0 && results.UnchangedCount == 0 {
		return fmt.Errorf("no alert found with soc_id: %s", socId)
	}

	logger.WithFields(log.Fields{
		"socId":          socId,
		"updatedCount":   results.UpdatedCount,
		"unchangedCount": results.UnchangedCount,
	}).Info("Successfully marked alert as investigated")

	return nil
}
