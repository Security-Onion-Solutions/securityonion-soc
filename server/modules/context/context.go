// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package context

import (
	"context"
)

type ContextKey string

const (
	ctxKeySkipAudit         ContextKey = "skipAudit"
	ctxKeyOverrideOperation ContextKey = "overrideOperation"
	ctxKeyIsAssistant       ContextKey = "isAssistant"
)

func WriteSkipAudit(ctx context.Context, skipAudit bool) context.Context {
	return context.WithValue(ctx, ctxKeySkipAudit, skipAudit)
}

func ReadSkipAudit(ctx context.Context) bool {
	skipAudit, _ := ctx.Value(ctxKeySkipAudit).(bool)
	return skipAudit
}

func WriteOverrideOperation(ctx context.Context, op string) context.Context {
	return context.WithValue(ctx, ctxKeyOverrideOperation, op)
}

func ReadOverrideOperation(ctx context.Context) *string {
	overrideOp, ok := ctx.Value(ctxKeyOverrideOperation).(string)
	if ok {
		return &overrideOp
	}

	return nil
}

func WriteIsAssistant(ctx context.Context, isAssistant bool) context.Context {
	return context.WithValue(ctx, ctxKeyIsAssistant, isAssistant)
}

func ReadIsAssistant(ctx context.Context) bool {
	isAssistant, _ := ctx.Value(ctxKeyIsAssistant).(bool)
	return isAssistant
}
