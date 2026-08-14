// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package statickeyauth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

type StaticKeyAuthImpl struct {
	apiKey string
	server *server.Server
}

func NewStaticKeyAuthImpl(srv *server.Server) *StaticKeyAuthImpl {
	return &StaticKeyAuthImpl{
		server: srv,
	}
}

func (auth *StaticKeyAuthImpl) Init(apiKey string) error {
	auth.apiKey = apiKey
	return nil
}

func (auth *StaticKeyAuthImpl) PreprocessPriority() int {
	return 100
}

func (auth *StaticKeyAuthImpl) Preprocess(ctx context.Context, req *http.Request) (context.Context, int, error) {
	apiKey := req.Header.Get("Authorization")
	if len(apiKey) == 0 {
		return ctx, http.StatusUnauthorized, errors.New("Missing authorization header")
	}

	if !auth.IsAuthorized(ctx, req) {
		return ctx, http.StatusUnauthorized, errors.New("Access denied")
	}

	// Remote agents will assume the role of this server until the implementation
	// is enhanced to support unique agent keys and roles.
	ctx = context.WithValue(ctx, web.ContextKeyRequestorId, auth.server.Agent.Id)
	ctx = context.WithValue(ctx, web.ContextKeyRequestCSRFExempt, true)
	return ctx, 0, nil
}

func (auth *StaticKeyAuthImpl) IsAuthorized(ctx context.Context, request *http.Request) bool {
	apiKey := request.Header.Get("Authorization")
	return auth.validateAuthorization(ctx, apiKey)
}

func (auth *StaticKeyAuthImpl) validateAuthorization(ctx context.Context, key string) bool {
	logger := log.FromContext(ctx)

	if len(key) > 0 && !strings.HasPrefix(key, "Bearer ") {
		isApiKeyAccepted := auth.validateApiKey(key)
		logger.WithFields(log.Fields{
			"isApiKeyAccepted": isApiKeyAccepted,
			"requestId":        ctx.Value(web.ContextKeyRequestId),
		}).Debug("Authorization check via API key")
		return isApiKeyAccepted
	}

	return false
}

func (auth *StaticKeyAuthImpl) validateApiKey(key string) bool {
	pieces := strings.Split(key, " ")
	if len(pieces) > 0 {
		key = pieces[len(pieces)-1]
	}
	return key == auth.apiKey
}
