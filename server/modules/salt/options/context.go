// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package options

import "context"

type ContextKey string

const (
	ContextKeySaltExecTimeoutMs ContextKey = "timeoutMs"
)

func WithTimeoutMs(ctx context.Context, timeoutMs int) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}

	return context.WithValue(ctx, ContextKeySaltExecTimeoutMs, timeoutMs)
}

func GetTimeoutMs(ctx context.Context) int {
	if ctx == nil {
		return 0
	}

	if timeoutMs, ok := ctx.Value(ContextKeySaltExecTimeoutMs).(int); ok {
		return timeoutMs
	}

	return 0
}
