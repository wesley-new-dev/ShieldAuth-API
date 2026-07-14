package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"
)

func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		traceID, _ := r.Context().Value(TraceIDKey).(string)

		defer func() {
			if err := recover(); err != nil {
				stack := string(debug.Stack())
				slog.ErrorContext(r.Context(), "PANIC RECOVERED",
					"trace_id", traceID,
					"method", r.Method,
					"path", r.URL.Path,
					"error", fmt.Sprintf("%v", err),
					"stack", stack,
				)
			}
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}()

		next.ServeHTTP(w, r)
		slog.InfoContext(r.Context(), "Request processed",
			"trace_id", traceID,
			"method", r.Method,
			"path", r.URL.Path,
			"duration", time.Since(start).String())
	})
}
