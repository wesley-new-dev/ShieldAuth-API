package auth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"ShieldAuth-API/internal/security/redis"
	"ShieldAuth-API/internal/service"
)

type LogOutService struct {
	repo  LogOutRepository
	redis redis.PasswordResetStore
}

func NewLogOutService(repo LogOutRepository, redisStore redis.PasswordResetStore) *LogOutService {
	return &LogOutService{
		repo:  repo,
		redis: redisStore,
	}
}

func (logout *LogOutService) LogOutFunction(ctx context.Context, input service.LogOutInput) error {
	if len(input.RefreshToken) == 0 {
		return fmt.Errorf("refresh token is required")
	}

	if input.UserID <= 0 {
		return fmt.Errorf("user ID is required")
	}

	if input.SessionID == "" {
		return fmt.Errorf("session ID is required")
	}
	
	if input.AccessTokenID == "" {
		return fmt.Errorf("access token ID is required")
	}

	hash := sha256.Sum256([]byte(input.RefreshToken))
	if err := logout.repo.Revoke(ctx, hash[:]); err != nil {
		return err
	}

	sessionKey := fmt.Sprintf("session:%d:%s", input.UserID, input.SessionID)
	if err := logout.redis.Delete(ctx, sessionKey); err != nil {
		return fmt.Errorf("delete session from cache: %w", err)
	}

	blacklistKey := "blacklist:" + input.AccessTokenID
	if err := logout.redis.Save(ctx, blacklistKey, input.UserID, 15*time.Minute); err != nil {
		return fmt.Errorf("blacklist access token: %w", err)
	}

	return nil
}
