// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
)

// ChatInSession loads the session history, appends the new user message,
// dispatches the request to Send, persists the user message and assistant
// responses, and returns the assistant response messages for the handler to
// write back to the requester.
func (ac *AssistantCoordinator) ChatInSession(ctx context.Context, incMsg *model.IncomingMessage, entityType, entityId string) ([]*model.Message, error) {
	logger := log.FromContext(ctx)

	// Detach up front: a browser refresh cancels the request context, which
	// would otherwise abort a billed in-flight turn before it can be saved.
	ctx, cancel := buildDetachedCtx(ctx, CHAT_TURN_TIMEOUT)
	defer cancel()

	messages, isNewSession, err := ac.loadHistory(ctx, incMsg.SessionId)
	if err != nil {
		logger.WithField("sessionId", incMsg.SessionId).WithError(err).Error("unable to load history")
		return nil, err
	}

	newMsg := newUserMessage(incMsg.Msg)
	messages = append(messages, newMsg)

	response, err := ac.Send(ctx, incMsg.Model, messages, model.WithMemories(incMsg.SessionId))
	if err != nil {
		logger.WithFields(log.Fields{
			"sessionId": incMsg.SessionId,
			"model":     incMsg.Model,
			"streaming": false,
		}).WithError(err).Error("unable to send message")

		return nil, err
	}

	// Send already succeeded (and was billed), so bookkeeping failures below must
	// not discard the response before it and its usage are saved.
	if isNewSession {
		if err := ac.createSessionIfNeeded(ctx, incMsg, entityType, entityId); err != nil {
			logger.WithError(err).Error("unable to create session for non-streaming chat")
		}
	}

	if err := ac.srv.Assistantstore.SaveChat(ctx, newMsg.PrepareForStorage(incMsg.SessionId, incMsg.Tags, incMsg.Model)); err != nil {
		logger.WithError(err).Error("unable to save user message for non-streaming chat")
	}

	for _, msg := range response {
		if err := ac.srv.Assistantstore.SaveChat(ctx, msg.PrepareForStorage(incMsg.SessionId, nil, incMsg.Model)); err != nil {
			logger.WithError(err).Error("unable to save assistant response (non-streaming)")
			return nil, err
		}
	}

	return response, nil
}

// ChatStreamInSession is the streaming counterpart to ChatInSession. It loads
// history, persists the user message, dispatches the request to SendStream,
// and returns the upstream response stream alongside a finalize callback the
// handler invokes after streaming completes to parse the buffered response and
// persist the assistant message.
func (ac *AssistantCoordinator) ChatStreamInSession(ctx context.Context, incMsg *model.IncomingMessage, entityType, entityId string) (*http.Response, *model.AuxMessageData, func(rawResponse []byte) error, error) {
	logger := log.FromContext(ctx)

	// Detach up front
	noTimeOutCtx := buildNoTimeoutCtx(ctx)

	messages, isNewSession, err := ac.loadHistory(noTimeOutCtx, incMsg.SessionId)
	if err != nil {
		logger.WithField("sessionId", incMsg.SessionId).WithError(err).Error("unable to load history")
		return nil, nil, nil, err
	}

	newMsg := newUserMessage(incMsg.Msg)
	messages = append(messages, newMsg)

	response, aux, err := ac.SendStream(noTimeOutCtx, incMsg.Model, messages, model.WithMemories(incMsg.SessionId))
	if err != nil {
		logger.WithFields(log.Fields{
			"sessionId": incMsg.SessionId,
			"model":     incMsg.Model,
			"streaming": true,
		}).WithError(err).Error("unable to send message")

		return nil, nil, nil, err
	}

	// SendStream already succeeded (the upstream is live and billing), so
	// bookkeeping failures below must not abandon the stream before finalize can
	// save the turn and its usage.
	if isNewSession {
		if err := ac.createSessionIfNeeded(noTimeOutCtx, incMsg, entityType, entityId); err != nil {
			logger.WithError(err).Error("unable to create session for streaming chat")
		}
	}

	if err := ac.srv.Assistantstore.SaveChat(noTimeOutCtx, newMsg.PrepareForStorage(incMsg.SessionId, incMsg.Tags, incMsg.Model)); err != nil {
		logger.WithError(err).Error("unable to save user message before streaming response")
	}

	finalize := func(rawResponse []byte) error {
		msg, err := server.UnstreamResponse(noTimeOutCtx, string(rawResponse), aux)
		if err != nil {
			logger.WithError(err).Error("error while piecing stream together")
			return err
		}
		if msg == nil {
			return nil
		}

		return ac.srv.Assistantstore.SaveChat(noTimeOutCtx, msg.PrepareForStorage(incMsg.SessionId, nil, incMsg.Model))
	}

	return response, aux, finalize, nil
}

func (ac *AssistantCoordinator) loadHistory(ctx context.Context, sessionId string) ([]*model.Message, bool, error) {
	logger := log.FromContext(ctx)

	history, err := ac.srv.Assistantstore.GetChatHistory(ctx, sessionId)
	if err != nil && !strings.Contains(err.Error(), "not found") {
		logger.WithError(err).Error("unable to get chat history")
		return nil, false, err
	}

	return HistoryToContext(history), len(history) == 0, nil
}

func newUserMessage(text string) *model.Message {
	return &model.Message{
		Role: "user",
		ContentBlocks: []model.ContentBlock{
			{
				Type: "text",
				Text: text,
			},
		},
	}
}

func (ac *AssistantCoordinator) createSessionIfNeeded(ctx context.Context, incMsg *model.IncomingMessage, entityType, entityId string) error {
	session := &model.AssistantSession{
		SessionId: incMsg.SessionId,
		Title:     incMsg.Msg,
		Model:     incMsg.Model,
	}
	if entityType != "" && entityId != "" {
		session.Type = entityType
		session.EntityId = entityId
	}

	return ac.srv.Assistantstore.CreateSession(ctx, session)
}

// buildNoTimeoutCtx returns a context detached from the request's cancellation and
// timeout, carrying over the requestor identity, request id, and request-scoped logger.
func buildNoTimeoutCtx(ctx context.Context) context.Context {
	noTimeOutCtx := context.Background()
	if val := ctx.Value(web.ContextKeyRunAsUsername); val != nil {
		if username, ok := val.(string); ok {
			noTimeOutCtx = context.WithValue(noTimeOutCtx, web.ContextKeyRunAsUsername, username)
		}
	}
	if requestorId, ok := ctx.Value(web.ContextKeyRequestorId).(string); ok {
		noTimeOutCtx = context.WithValue(noTimeOutCtx, web.ContextKeyRequestorId, requestorId)
	}
	// Carried so downstream stores that key work off the request id (e.g. the salt
	// relay's queue filename) still find it on a detached turn.
	if requestId, ok := ctx.Value(web.ContextKeyRequestId).(string); ok {
		noTimeOutCtx = context.WithValue(noTimeOutCtx, web.ContextKeyRequestId, requestId)
	}
	noTimeOutCtx = log.NewContext(noTimeOutCtx, log.FromContext(ctx))
	return noTimeOutCtx
}

// buildDetachedCtx returns a context detached from the request's cancellation —
// so a browser refresh cannot abort a billed in-flight turn before it is saved —
// but bounded by its own timeout, carrying the requestor identity and logger.
func buildDetachedCtx(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(buildNoTimeoutCtx(ctx), timeout)
}
