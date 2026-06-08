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

type EventstoreUpdater interface {
	AddInvestigationUpdateScripts(updateCriteria *model.EventUpdateCriteria, timeNow time.Time, userId string, isDelete bool, sessionId ...string)
}

// @Summary      Send Chat Message
// @Description  Send a message to the AI assistant and receive a response. Supports both streaming (SSE) and non-streaming responses.
// @Tags         Assistant
// @Security     bearer[assistant/write_authored]
// @Param        request  body  object{msg=string,sessionId=string} true "Chat message object with message text and optional session ID"
// @Param        entityType query string false "Type of entity associated with this session (e.g., 'alert_investigation')"
// @Param        entityId query string false "ID of the entity associated with this session (e.g., alert's soc_id)"
// @Accept       json
// @Produce      json,text/event-stream
// @Success      200  {array}   model.Message "AI assistant response messages"
// @Failure      400           "The provided input object or parameters are malformed or invalid"
// @Failure      401           "Request was not properly authenticated"
// @Failure      403           "Insufficient permissions for this request"
// @Failure      500           "Internal SOC error; review SOC logs"
// @Router       /connect/assistant/chat [post]
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

	entityType := r.URL.Query().Get("entityType")
	entityId := r.URL.Query().Get("entityId")

	if entityType != "" && entityId != "" {
		// Don't fail the request on association errors (already logged in helper)
		_ = h.handleEntityAssociation(ctx, entityType, entityId, incMsg.SessionId)
	}

	if _, ok := w.(http.Flusher); streaming && !ok {
		logger.WithField("acceptHeader", accept).Warn("incoming request accepts streaming but is not flushable, issuing non-streaming response")
		streaming = false
	}

	if !streaming {
		response, err := h.server.AssistantManager.ChatInSession(ctx, incMsg, entityType, entityId)
		if err != nil {
			logger.WithError(err).Error("unable to chat with assistant")
			if isClientError(err) {
				web.Respond(w, r, http.StatusBadRequest, err.Error())
			} else {
				web.Respond(w, r, http.StatusInternalServerError, "ERROR_UPSTREAM_SERVICE_ERROR")
			}

			return
		}

		web.Respond(w, r, http.StatusOK, response)

		return
	}

	response, _, finalize, err := h.server.AssistantManager.ChatStreamInSession(ctx, incMsg, entityType, entityId)
	if err != nil {
		logger.WithError(err).Error("unable to chat (stream) with assistant")
		if isClientError(err) {
			web.Respond(w, r, http.StatusBadRequest, err.Error())
		} else {
			web.Respond(w, r, http.StatusInternalServerError, "ERROR_UPSTREAM_SERVICE_ERROR")
		}

		return
	}

	entireResponse, err := streamResponse(ctx, w, r, response)
	if err != nil {
		logger.WithError(err).Error("error streaming response")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	go func() {
		if err := finalize(entireResponse); err != nil {
			logger.WithError(err).Error("error finalizing streamed response")
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
// @Router       /connect/assistant/tool/{name} [post]
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

	if _, ok := w.(http.Flusher); streaming && !ok {
		logger.WithField("acceptHeader", accept).Warn("incoming request accepts streaming but is not flushable, issuing non-streaming response")
		streaming = false
	}

	if !streaming {
		response, err := h.server.AssistantManager.ToolInSession(ctx, toolReq, toolName)
		if err != nil {
			logger.WithError(err).Error("unable to chat with assistant after tool execution")
			if isClientError(err) {
				web.Respond(w, r, http.StatusBadRequest, err.Error())
			} else {
				web.Respond(w, r, http.StatusInternalServerError, "ERROR_UPSTREAM_SERVICE_ERROR")
			}

			return
		}

		web.Respond(w, r, http.StatusOK, response)

		return
	}

	turn, err := h.server.AssistantManager.ToolStreamInSession(ctx, toolReq, toolName)
	if err != nil {
		logger.WithError(err).Error("unable to chat (stream) with assistant after tool execution")
		if isClientError(err) {
			web.Respond(w, r, http.StatusBadRequest, err.Error())
		} else {
			web.Respond(w, r, http.StatusInternalServerError, "ERROR_UPSTREAM_SERVICE_ERROR")
		}

		return
	}

	if _, ok := w.(http.Flusher); !ok {
		logger.Error("response writer does not support flushing, cannot stream response")
		web.Respond(w, r, http.StatusInternalServerError, "streaming not supported")
		return
	}

	// Stream the tool's turn, then keep chaining turns on this same response while a
	// delegated sub-agent finishes (a text-only turn) and the backend folds its
	// result back into the parent. We stop and hand control back to the client as
	// soon as a turn requests a tool (needs approval) or a top-level turn completes.
	writeStreamHeaders(w, turn.Response)

	// Keep chaining turns on this response while delegated sub-agents resolve. The
	// chain terminates on a tool_use, a top-level session, a stream/parse error, or
	// when a sub-session exhausts its token budget.
	for {
		if turn.Marker != nil {
			if err := writeDelegationMarker(w, turn.Marker); err != nil {
				logger.WithError(err).Error("unable to write delegation marker")
				break
			}
		}

		entireResponse, streamErr := streamBody(ctx, w, turn.Response)

		// Persist this turn's assistant message regardless of what we decide next.
		finalize, raw := turn.Finalize, entireResponse
		go func() {
			if err := finalize(raw); err != nil {
				logger.WithError(err).Error("error finalizing streamed turn after tool execution")
			}
		}()

		// Parse the turn (best-effort). A stream or parse failure leaves msg nil and
		// falls through to the resolution/termination logic below, so a delegated
		// sub-agent is never abandoned with its boundary left open.
		var msg *model.Message
		if streamErr != nil {
			logger.WithError(streamErr).Error("error streaming turn to client after tool execution")
		} else if parsed, parseErr := UnstreamResponse(ctx, string(entireResponse), turn.Aux); parseErr != nil {
			logger.WithError(parseErr).Error("unable to parse streamed turn")
		} else {
			msg = parsed
		}

		// A tool request hands control back to the client (approve and POST again).
		// This legitimately parks a sub-agent mid-task, so do not resolve here.
		if msg != nil && messageHasToolUse(msg) {
			break
		}

		sess := h.loadSession(ctx, turn.SessionId)
		if sess == nil {
			// We can't tell whether this finished turn was a delegated sub-agent, so
			// we can't close its boundary. Log it so a stuck delegate card is
			// diagnosable, then stop chaining.
			logger.WithField("sessionId", turn.SessionId).Warn("unable to load session after streamed turn; cannot resolve possible delegation")
			break
		}
		if sess.ParentSessionId == "" {
			break // top-level conversation completed
		}

		// The session that just finished is a delegated sub-agent. Resolve it into its
		// parent and stream the parent's turn — even when it ended abnormally (empty,
		// nil, or a parse/stream error), so the delegation boundary always closes and
		// the parent resumes instead of being parked forever.
		childText := ""
		if msg != nil {
			childText = messageText(msg)
		}
		next, resolveErr := h.server.AssistantManager.ResolveDelegationStream(ctx, sess, childText)
		if resolveErr != nil {
			logger.WithError(resolveErr).Error("unable to resolve delegation")
			// Resolution failed, but the sub-agent's boundary is still open on the
			// client. Emit a resolved marker so the UI un-nests and closes the
			// delegate card instead of leaving it spinning forever.
			if err := writeResolvedMarker(w, sess.ParentSessionId, sess.ParentToolUseId); err != nil {
				logger.WithError(err).Error("unable to write delegation resolved marker after resolve failure")
			}
			break
		}
		turn = next
	}
}

// writeResolvedMarker writes a delegation_resolved SSE event so the client
// un-nests a delegated sub-agent and closes its delegate tool card. Used both on
// the normal resolution path and to guarantee the boundary closes when backend
// resolution fails.
func writeResolvedMarker(w http.ResponseWriter, parentSessionId, parentToolUseId string) error {
	return writeDelegationMarker(w, &model.DelegationMarker{
		Type:            model.DelegationMarkerResolved,
		ParentSessionId: parentSessionId,
		ParentToolUseId: parentToolUseId,
	})
}

// @Summary      Get Assistant Balance
// @Description  Retrieve the current balance/usage information for the AI assistant.
// @Tags         Assistant
// @Security     bearer[assistant/read_authored]
// @Security     bearer[assistant/read_all]
// @Param        modelAndAdapter  path  string  true  "Model Id (including slashes) and Adapter Name to get balance for" example(qwen/qwen2.5-small@MyOpenAIChatAdapter)
// @Produce      json
// @Success      200  {object}  model.Usage "Current assistant balance and usage information"
// @Failure      401           "Request was not properly authenticated"
// @Failure      403           "Insufficient permissions for this request"
// @Failure      500           "Internal SOC error; review SOC logs"
// @Router       /connect/assistant/balance/{modelAndAdapter} [get]
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
// @Router       /connect/assistant/sessions [get]
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

	// Delegated sub-agent sessions are rendered nested inside their parent
	// conversation, so keep them out of the top-level session list.
	topLevel := make([]*model.AssistantSession, 0, len(sessions))
	for _, s := range sessions {
		if s.ParentSessionId == "" {
			topLevel = append(topLevel, s)
		}
	}

	web.Respond(w, r, http.StatusOK, topLevel)
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
// @Router       /connect/assistant/sessions/{sessionId} [get]
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

	// Fetch the session plus every delegated sub-session descending from it, so the
	// UI can reconstruct nested sub-agent activity when the conversation is reopened.
	sessions, err := h.server.Assistantstore.GetSessions(ctx, model.GetSessionsWithSessionId(sessionId), model.GetSessionsWithIncludeDeleted(true), model.GetSessionsWithUsage(true), model.GetSessionsWithDescendants(true))
	if err != nil {
		logger.WithError(err).Error("unable to get session")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	var root *model.AssistantSession
	var subSessions []*model.AssistantSession
	for _, s := range sessions {
		if s.SessionId == sessionId {
			root = s
		} else {
			subSessions = append(subSessions, s)
		}
	}

	if root == nil {
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

	details := &model.AssistantSessionDetails{
		Session: root,
		History: history,
	}

	for _, sub := range subSessions {
		subHistory, err := h.server.Assistantstore.GetChatHistory(ctx, sub.SessionId)
		if err != nil {
			logger.WithError(err).WithField("subSessionId", sub.SessionId).Error("unable to get chat history for sub-session")
			continue
		}
		removeAuxData(subHistory)
		details.SubSessions = append(details.SubSessions, &model.AssistantSessionDetails{
			Session: sub,
			History: subHistory,
		})
	}

	web.Respond(w, r, http.StatusOK, details)
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
// @Router       /connect/assistant/sessions/{sessionId} [put]
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
// @Router       /connect/assistant/sessions/{sessionId} [delete]
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

	// Clear investigation session from alert if applicable
	h.handleInvestigationSessionCleanup(ctx, sessionId)

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
// @Router       /connect/assistant/admin/stats [get]
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
// @Router       /connect/assistant/admin/sessions [get]
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
// @Router       /connect/assistant/admin/{userId}/sessions [get]
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
// @Router       /connect/assistant/admin/{userId}/sessions/{sessionId}/history [get]
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
	if _, ok := w.(http.Flusher); !ok {
		logger.Error("response writer does not support flushing, cannot stream response")
		web.Respond(w, r, http.StatusInternalServerError, "streaming not supported")

		return
	}

	writeStreamHeaders(w, response)

	return streamBody(ctx, w, response)
}

// writeStreamHeaders copies the upstream response headers and writes the status
// code. It must be called exactly once per HTTP response; when chaining multiple
// streamed turns onto a single response, only the first turn's headers are written.
func writeStreamHeaders(w http.ResponseWriter, response *http.Response) {
	for k, v := range response.Header {
		for _, val := range v {
			w.Header().Add(k, val)
		}
	}

	w.WriteHeader(response.StatusCode)
}

// streamBody streams an upstream response body to the client as fast as it
// arrives, returning the full buffered response. It does not write headers, so it
// is safe to call repeatedly for successive turns on the same HTTP response.
func streamBody(ctx context.Context, w http.ResponseWriter, response *http.Response) (entireResponse []byte, err error) {
	logger := log.FromContext(ctx)
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, fmt.Errorf("streaming not supported")
	}

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

// writeDelegationMarker writes a synthetic SSE event into the stream so the UI can
// nest (delegation_start) or un-nest (delegation_resolved) a delegated sub-agent's
// output. Markers are written directly to the client and are never part of the
// buffered response parsed by UnstreamResponse.
func writeDelegationMarker(w http.ResponseWriter, marker *model.DelegationMarker) error {
	data, err := json.Marshal(marker)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
		return err
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	return nil
}

// messageHasToolUse reports whether the assistant turn requested any tools (and
// therefore must be handed back to the client for approval rather than chained).
// isClientError reports whether an assistant error is caused by the request
// itself (and so should be surfaced as HTTP 400) rather than an internal/upstream
// failure. The assistant module is matched by error string to avoid an import
// cycle between the server package and the module.
func isClientError(err error) bool {
	switch err.Error() {
	case "ERROR_ASSISTANT_REQUEST_TOO_LARGE", "ERROR_ASSISTANT_INVALID_MODEL":
		return true
	default:
		return false
	}
}

func messageHasToolUse(msg *model.Message) bool {
	for _, cb := range msg.ContentBlocks {
		if cb.Type == "tool_use" {
			return true
		}
	}
	return false
}

// messageText concatenates the text content of an assistant turn, used as the
// delegated sub-agent's final answer when resolving a delegation.
func messageText(msg *model.Message) string {
	var b strings.Builder
	for _, cb := range msg.ContentBlocks {
		if cb.Text != "" {
			b.WriteString(cb.Text)
		}
	}
	return b.String()
}

// loadSession returns the session with the given id, or nil if it can't be found.
func (h *AssistantHandler) loadSession(ctx context.Context, sessionId string) *model.AssistantSession {
	sessions, err := h.server.Assistantstore.GetSessions(ctx, model.GetSessionsWithSessionId(sessionId))
	if err != nil || len(sessions) == 0 {
		return nil
	}
	return sessions[0]
}

// UnstreamResponse parses a buffered SSE response stream from the assistant
// into a single assembled model.Message. It is exported so the assistant
// module's streaming finalize path can reuse it.
func UnstreamResponse(ctx context.Context, rawResponse string, aux *model.AuxMessageData) (*model.Message, error) {
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

func removeAuxData(messages []*model.StoredMessage) {
	for _, msg := range messages {
		for i := 0; i < len(msg.Message.ContentBlocks); i++ {
			cb := &msg.Message.ContentBlocks[i]
			cb.ThoughtSignature = nil
		}
	}
}

func (h *AssistantHandler) handleEntityAssociation(ctx context.Context, entityType, entityId, sessionId string) error {
	logger := log.FromContext(ctx)

	// Handle entity-specific logic based on type
	if entityType == "alert_investigation" && entityId != "" {
		// Mark the alert as investigated with the session ID
		err := h.markAlertAsInvestigated(ctx, entityId, sessionId)
		if err != nil {
			logger.WithError(err).WithFields(log.Fields{
				"entityType": entityType,
				"entityId":   entityId,
			}).Warn("unable to mark alert as investigated")
			return err
		}
	}

	return nil
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

	if h.server.Eventstore != nil {
		if updater, ok := h.server.Eventstore.(EventstoreUpdater); ok {
			updater.AddInvestigationUpdateScripts(updateCriteria, time.Now(), userId, false, sessionId)
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

func (h *AssistantHandler) handleInvestigationSessionCleanup(ctx context.Context, sessionId string) {
	logger := log.FromContext(ctx)

	// Retrieve session details before deletion to check if it's an investigation session
	sessions, err := h.server.Assistantstore.GetSessions(ctx, model.GetSessionsWithSessionId(sessionId))
	if err != nil {
		logger.WithError(err).Error("unable to retrieve session before deletion")
		return
	}

	// If this is an investigation session, clear the investigation_session_id from the alert
	if len(sessions) > 0 {
		session := sessions[0]
		if session.Type == "alert_investigation" && session.EntityId != "" {
			err = h.clearInvestigationSessionFromAlert(ctx, session.EntityId, sessionId)
			if err != nil {
				logger.WithError(err).WithFields(log.Fields{
					"sessionId": sessionId,
					"entityId":  session.EntityId,
				}).Warn("unable to clear investigation_session_id from alert")
				// Continue with deletion even if clearing fails
			}
		}
	}
}

func (h *AssistantHandler) clearInvestigationSessionFromAlert(ctx context.Context, socId string, sessionId string) error {
	logger := log.FromContext(ctx)

	// Check write permission on events
	if err := h.server.CheckAuthorized(ctx, "write", "events"); err != nil {
		return err
	}

	logger.WithFields(log.Fields{
		"socId":     socId,
		"sessionId": sessionId,
	}).Info("Clearing investigation_session_id from alert")

	// Create update criteria to remove the investigation_session_id field
	updateCriteria := model.NewEventUpdateCriteria()
	userId := ctx.Value(web.ContextKeyRequestorId).(string)

	if h.server.Eventstore != nil {
		if updater, ok := h.server.Eventstore.(EventstoreUpdater); ok {
			updater.AddInvestigationUpdateScripts(updateCriteria, time.Now(), userId, true, sessionId)
		} else {
			return fmt.Errorf("eventstore does not support investigation updates")
		}
	} else {
		return fmt.Errorf("eventstore is not available")
	}

	// Create a query to match the soc_id
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

	logger.WithFields(log.Fields{
		"socId":          socId,
		"updatedCount":   results.UpdatedCount,
		"unchangedCount": results.UnchangedCount,
	}).Info("Successfully cleared investigation_session_id from alert")

	return nil
}
