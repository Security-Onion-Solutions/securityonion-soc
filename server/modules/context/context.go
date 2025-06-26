package context

import (
	"context"
)

type ContextKey string

const (
	ctxKeySkipAudit         ContextKey = "skipAudit"
	ctxKeyOverrideOperation ContextKey = "overrideOperation"
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
