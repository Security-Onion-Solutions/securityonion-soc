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
