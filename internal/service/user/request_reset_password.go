package user

import (
	"context"
	"crypto/sha256"
	"time"
	"fmt"
	"strings"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/repository"
	"ShieldAuth-API/internal/security"
	"ShieldAuth-API/internal/security/redis"
)

type RequestResetService struct {
	userRepo   *repository.RequestStruct
	tokenizer  security.TokenManager
	resetStore redis.PasswordResetStore
	limiter    *redis.RedisLimiter
}

func NewRequestResetService(userRepo *repository.RequestStruct, resetStore redis.PasswordResetStore, tokenizer security.TokenManager, limiter *redis.RedisLimiter) *RequestResetService {
	return &RequestResetService{
		userRepo:   userRepo,
		resetStore: resetStore,
		tokenizer:  tokenizer,
		limiter:    limiter,
	}
}

func (r *RequestResetService) RequestReset(ctx context.Context, email string) (string, error) {

	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	sum := sha256.Sum256([]byte(normalizedEmail))
	key := fmt.Sprintf("forgot-password:email:%x", sum)

	allowed, err := r.limiter.Allow(ctx, fmt.Sprintf("reset-password:%s", key), 10, time.Minute)
	if err != nil {
		return "", fmt.Errorf("rate limit failed: %w", err)
	}

	if !allowed {
		return "", domain.ErrRateLimitExceeded
	}

	user, err := r.userRepo.GetByEmail(ctx, email)
	if err != nil {
		return "", nil
	}

	token, err := r.tokenizer.GenerateToken()
	if err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}

	r.resetStore.Save(ctx, token, user.Id, 15*time.Minute)

	return token, nil
}