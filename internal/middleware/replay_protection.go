package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

type ReplayProtection struct {
	redisClient *redis.Client
}

func NewReplayProtection(client *redis.Client) *ReplayProtection {
	return &ReplayProtection{redisClient: client}
}

func (m *ReplayProtection) ReplayProtection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := r.Header.Get("X-Nonce")
		timeStamp := r.Header.Get("X-Timestamp")

		if nonce == "" || timeStamp == "" {
			slog.WarnContext(r.Context(), "missing replay protection headers", "nonce_present", nonce != "", "timestamp_present", timeStamp != "")
			http.Error(w, "missing security headers", http.StatusBadRequest)
			return
		}

		timeStampUnix, err := strconv.ParseInt(timeStamp, 10, 64)
		if err != nil {
			slog.WarnContext(r.Context(), "invalid replay timestamp format", "error", err)
			http.Error(w, "invalid timestamp format", http.StatusBadRequest)
			return
		}

		requestTime := time.Unix(timeStampUnix, 0)
		if time.Since(requestTime) > 5*time.Minute || time.Until(requestTime) > 1*time.Minute {
			slog.WarnContext(r.Context(), "replay protection request expired or skewed", "request_time", requestTime)
			http.Error(w, "request expired or clock skew detected", http.StatusForbidden)
			return
		}

		redisKey := fmt.Sprintf("nonce:%s", nonce)
		success, err := m.redisClient.SetNX(r.Context(), redisKey, "1", 5*time.Minute).Result()
		if err != nil {
			slog.ErrorContext(r.Context(), "failed to store replay nonce", "nonce", nonce, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		if !success {
			slog.WarnContext(r.Context(), "duplicate replay nonce detected", "nonce", nonce)
			http.Error(w, "invalid request: duplicate nonce detected", http.StatusConflict)
			return
		}

		next.ServeHTTP(w, r)
	})
}
