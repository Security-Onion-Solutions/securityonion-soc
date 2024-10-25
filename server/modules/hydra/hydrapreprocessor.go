// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
	if len(token) == 0 || !strings.HasPrefix(token, "Bearer ") || !licensing.IsEnabled(licensing.FEAT_API) {
		return ctx, 0, nil
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

	return ctx, 0, nil
}
