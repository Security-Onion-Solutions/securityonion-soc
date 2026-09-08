// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package kratos

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

const HeaderKratosAuthenticatedIdentityId = "X-Kratos-Authenticated-Identity-Id"

type KratosPreprocessor struct {
	userstore server.Userstore
}

func NewKratosPreprocessor(impl server.Userstore) *KratosPreprocessor {
	return &KratosPreprocessor{
		userstore: impl,
	}
}

func (proc *KratosPreprocessor) PreprocessPriority() int {
	return 110
}

func (proc *KratosPreprocessor) Preprocess(ctx context.Context, request *http.Request) (context.Context, int, error) {
	var statusCode int
	var err error

	if request.Header.Get("Authorization") != "" {
		// This is an API client request, don't validate the session
		return ctx, http.StatusUnauthorized, errors.New("Unexpected authorization header")
	}

	cookie, cookieErr := request.Cookie("ory_kratos_session")
	if cookieErr != nil || cookie == nil || cookie.Value == "" {
		return ctx, http.StatusUnauthorized, errors.New("Missing ory_kratos_session cookie")
	}

	resp, err := proc.userstore.ValidateSession(ctx, request)
	if err != nil {
		return ctx, http.StatusUnauthorized, err
	}
	if resp == nil || resp.StatusCode != http.StatusOK {
		status := http.StatusUnauthorized
		if resp != nil && resp.StatusCode != 0 {
			status = resp.StatusCode
		}
		return ctx, status, errors.New("Unauthorized session")
	}

	userId := resp.Header.Get(HeaderKratosAuthenticatedIdentityId)
	if userId == "" {
		return ctx, http.StatusUnauthorized, errors.New("Missing identity header in session validation response")
	}

	ctx = context.WithValue(ctx, web.ContextKeyRequestorId, userId)
	ctx = context.WithValue(ctx, web.ContextKeyRequestCSRFExempt, false)
	user, err := proc.userstore.GetUserById(ctx, userId)
	if err == nil && user != nil {
		username := strings.ToLower(user.Email)
		if strings.TrimSpace(user.SearchUsername) != "" {
			username = user.SearchUsername
		}
		ctx = context.WithValue(ctx, web.ContextKeyRunAsUsername, username)
	}

	return ctx, statusCode, nil
}
