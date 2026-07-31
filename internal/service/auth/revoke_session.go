package auth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"ShieldAuth-API/internal/security/redis"
)

type RevokeSessionService struct {
	repo  RevokeSessionRepository
	redis redis.PasswordResetStore
}

func NewRevokeSessionService(repo RevokeSessionRepository, redis redis.PasswordResetStore) *RevokeSessionService {
	return &RevokeSessionService{
		repo:  repo,
		redis: redis,
	}
}

func (r *RevokeSessionService) RevokeSession(ctx context.Context, refreshTokenString string, accessTokenID string, userID int64) error {
	hash := sha256.Sum256([]byte(refreshTokenString))
	_ = r.repo.Revoke(ctx, hash[:])

	_ = r.redis.Delete(ctx, refreshTokenString)

	if accessTokenID != "" {
		_ = r.redis.Save(ctx, "blacklist:"+accessTokenID, userID, 15*time.Minute)
	}

	return nil
}

func (r *RevokeSessionService) RevokeAllSessions(ctx context.Context, userID int64) error {
	newVersion, err := r.repo.IncrementJWTVersion(ctx, userID)
	if err != nil {
		return err
	}

	err = r.redis.Save(ctx, fmt.Sprintf("user:version:%d", userID), newVersion, 24*time.Hour)
	if err != nil {
		return err
	}

	return nil
}
