// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

func (ac *AssistantCoordinator) UpdateSessionTag(ctx context.Context, sessionId string, tag string, present bool) error {
	if err := ac.srv.CheckAuthorized(ctx, "write_authored", "assistant"); err != nil {
		return err
	}

	tag = strings.TrimSpace(tag)
	if tag == "" {
		return server.ErrSessionTagInvalid
	}

	if slices.ContainsFunc(model.ReservedSessionTags, func(reserved string) bool { return strings.EqualFold(reserved, tag) }) {
		return server.ErrSessionTagReserved
	}

	shared := tag == model.SessionTagShared

	// Descendants come back after the root so sharing can cascade to them below.
	sessions, err := ac.srv.Assistantstore.GetSessions(ctx,
		model.GetSessionsWithSessionId(sessionId),
		model.GetSessionsWithAutomationSessions(true),
		model.GetSessionsWithDescendants(shared),
		model.GetSessionsWithMessageMeta(false))
	if err != nil {
		return err
	}
	if len(sessions) == 0 || sessions[0].SessionId != sessionId {
		return server.ErrSessionNotFound
	}

	session := sessions[0]
	if slices.Contains(session.Tags, model.SessionTagAutomation) {
		return server.ErrSessionAutomationTags
	}

	userId, _ := ctx.Value(web.ContextKeyRequestorId).(string)
	if session.UserId != userId {
		return server.ErrSessionAccessDenied
	}

	// Re-adding shared is allowed so descendants that missed the cascade catch up.
	if present && !shared && slices.Contains(session.Tags, tag) {
		return server.ErrSessionTagExists
	}

	if !present {
		err = ac.canRemoveTag(ctx, session, tag)
		if err != nil {
			return err
		}
	}

	// A shared session is readable through its sub-sessions too, so the tag
	// follows every descendant in one write. Other tags stay on the one session.
	ids := []string{sessionId}
	if shared {
		ids = make([]string, len(sessions))
		for i, s := range sessions {
			ids[i] = s.SessionId
		}
	}

	return ac.srv.Assistantstore.ToggleSessionsTag(ctx, ids, tag, present)
}

func (ac *AssistantCoordinator) canRemoveTag(ctx context.Context, session *model.AssistantSession, tag string) error {
	if !slices.Contains(session.Tags, tag) {
		return server.ErrSessionTagMissing
	}

	if ac.srv.Casestore == nil {
		return nil
	}

	cases, err := ac.srv.Casestore.GetCaseIdsWithArtifact(ctx, "assistant_chat", session.SessionId)
	if err != nil {
		return err
	}

	if len(cases) != 0 {
		return fmt.Errorf("%w %d", server.ErrSessionAttachedToCases, len(cases))
	}

	return nil
}
