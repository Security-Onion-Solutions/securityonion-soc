// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package kratos

import (
	"context"
	"net/http"

	"github.com/security-onion-solutions/securityonion-soc/web"
)

type KratosPreprocessor struct {
	userstore *KratosUserstore
}

func NewKratosPreprocessor(impl *KratosUserstore) *KratosPreprocessor {
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

	userId := request.Header.Get("x-user-id")
	if userId != "" {
		ctx = context.WithValue(ctx, web.ContextKeyRequestorId, userId)
		user, err := proc.userstore.GetUser(ctx, userId)
		if err == nil {
			ctx = context.WithValue(ctx, web.ContextKeyRequestor, user)
		}
	}

	return ctx, statusCode, err
}
