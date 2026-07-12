package logger

import (
	"context"
	"log/slog"

	"ShieldAuth-API/internal/middleware"
)

type TraceHandler struct {
	slog.Handler
}

func NewTraceHandler(baseHandler slog.Handler) slog.Handler {
	return &TraceHandler{
		Handler: baseHandler,
	}
}

func (h *TraceHandler) TraceHandle(ctx context.Context, r slog.Record) error {
	if ctx != nil {
		if traceID, ok := ctx.Value(middleware.TraceIDKey).(string); ok {
			r.AddAttrs(slog.String("trace_id", traceID))
		}
	}

	return h.Handler.Handle(ctx, r)
}
