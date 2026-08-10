// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package web

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

type StaticAssetPreprocessor struct {
}

func NewStaticAssetPreprocessor() *StaticAssetPreprocessor {
	return &StaticAssetPreprocessor{}
}

func (processor *StaticAssetPreprocessor) PreprocessPriority() int {
	return 10
}

func (processor *StaticAssetPreprocessor) Preprocess(ctx context.Context, req *http.Request) (context.Context, int, error) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return ctx, http.StatusUnauthorized, errors.New("Static assets preprocessor only supports GET and HEAD requests")
	}

	path := req.URL.Path

	if strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/ws") {
		return ctx, http.StatusUnauthorized, errors.New("Static assets preprocessor does not handle API or WebSocket requests")
	}

	return ctx, 0, nil
}
