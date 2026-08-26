// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"fmt"

	"github.com/security-onion-solutions/securityonion-soc/model"

	"github.com/apex/log"
	"github.com/google/uuid"
)

// recordAgentSession persists one background-agent exchange (request and
// response messages, in order) into a new tagged session. Ownership and
// metrics attribution follow the caller's context: the scanner records as
// SYSTEM, the live-chat embedding path as the chatting user.
func (ac *AssistantCoordinator) recordAgentSession(ctx context.Context, tag string, sourceSessionId string, modelSelector string, msgs []*model.Message) {
	if len(msgs) == 0 || sourceSessionId == "" || ac.srv == nil || ac.srv.Assistantstore == nil {
		return
	}

	logger := log.FromContext(ctx).WithFields(log.Fields{
		"memorySessionTag": tag,
		"sourceSessionId":  sourceSessionId,
	})

	session := &model.AssistantSession{
		SessionId: uuid.NewString(),
		Title:     fmt.Sprintf("%s usage for session %s", tag, sourceSessionId),
		EntityId:  sourceSessionId,
		Tags:      []string{tag},
		Model:     modelSelector,
	}

	err := ac.srv.Assistantstore.CreateSession(ctx, session)
	if err != nil {
		logger.WithError(err).Warn("unable to create memory usage session; agent usage not recorded")
		return
	}

	for _, msg := range msgs {
		err = ac.srv.Assistantstore.SaveChat(ctx, msg.PrepareForStorage(session.SessionId, nil, modelSelector))
		if err != nil {
			logger.WithError(err).Warn("unable to save memory agent usage message")
		}
	}
}

// recordEmbedUsage saves the the embedding conversation as a session
func (ac *AssistantCoordinator) recordEmbedUsage(ctx context.Context, sourceSessionId string, modelSelector string, resp *model.EmbeddingResponse, inputs []string) {
	if resp == nil {
		return
	}

	blocks := make([]model.ContentBlock, 0, len(inputs))
	for _, input := range inputs {
		blocks = append(blocks, model.ContentBlock{Type: "text", Text: input})
	}

	request := &model.Message{
		Role:          "user",
		ContentBlocks: blocks,
	}

	response := &model.Message{
		Id:   uuid.NewString(),
		Role: "assistant",
		ContentBlocks: []model.ContentBlock{
			{
				Type: "text",
				Text: fmt.Sprintf("Embedded %d input(s) using %s", len(inputs), resp.Model),
			},
		},
		Usage: resp.Usage,
	}

	ac.recordAgentSession(ctx, model.SessionTagEmbed, sourceSessionId, modelSelector, []*model.Message{request, response})
}
