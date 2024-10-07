package context

import (
	"context"
)

type ContextKey string

const (
	ctxKeySkipAudit ContextKey = "skipAudit"
)

func WriteSkipAudit(ctx context.Context, skipAudit bool) context.Context {
	return context.WithValue(ctx, ctxKeySkipAudit, skipAudit)
}

func ReadSkipAudit(ctx context.Context) bool {
	skipAudit, _ := ctx.Value(ctxKeySkipAudit).(bool)
	return skipAudit
}
