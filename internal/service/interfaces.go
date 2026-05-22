package service

import (
	"context"
	"time"
)

type Security interface {
	GenerateToken() (string, error)
	TokenHash(token string) string
}
type Limiter interface {
	CheckLimit(ctx context.Context, key string, maxAttempts int, window time.Duration) (bool, error)
}
type ResetStore interface {
	Get(ctx context.Context, token string) (string, error)
	Delete(ctx context.Context, token string) error
	Save(ctx context.Context, token string, userID int, ttl time.Duration) error
}