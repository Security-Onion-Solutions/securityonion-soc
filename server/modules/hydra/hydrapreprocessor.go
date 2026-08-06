// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package hydra

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

type HydraPreprocessor struct {
	clientstore *HydraClientstore
}

func NewHydraPreprocessor(impl *HydraClientstore) *HydraPreprocessor {
	return &HydraPreprocessor{
		clientstore: impl,
	}
}

func (proc *HydraPreprocessor) PreprocessPriority() int {
	return 120
}

func (proc *HydraPreprocessor) Preprocess(ctx context.Context, request *http.Request) (context.Context, int, error) {
	token := request.Header.Get("Authorization")
	if len(token) == 0 || !strings.HasPrefix(token, "Bearer ") {
		return ctx, 0, nil
	}

	if !licensing.IsEnabled(licensing.FEAT_API) {
		return ctx, http.StatusServiceUnavailable, errors.New("API disabled by license")
	}

	token = strings.TrimPrefix(token, "Bearer ")
	if len(token) == 0 {
		return ctx, http.StatusUnauthorized, errors.New("Invalid bearer token")
	}

	client, err := proc.clientstore.GetClientByToken(ctx, token)
	if err != nil {
		return ctx, http.StatusUnauthorized, err
	}

	ctx = context.WithValue(ctx, web.ContextKeyRequestorId, client.Id)
	ctx = context.WithValue(ctx, web.ContextKeyRequestCSRFExempt, true)
	searchUsername := strings.TrimSpace(client.SearchUsername)
	if searchUsername != "" {
		ctx = context.WithValue(ctx, web.ContextKeyRunAsUsername, searchUsername)
	}

	return ctx, 0, nil
}
