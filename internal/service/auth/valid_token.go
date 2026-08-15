package auth

import (
	"context"
	"fmt"
	"time"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/security"
	"ShieldAuth-API/internal/security/redis"
)

type ValidTokenService struct {
	resetStore redis.PasswordResetStore
	tokenManager security.TokenManager
}

func NewValidToken(resetStore redis.PasswordResetStore, tokenManager security.TokenManager) *ValidTokenService {
	return &ValidTokenService{
		resetStore: resetStore,
		tokenManager: tokenManager,
	}
}

func (v *ValidTokenService) ValidToken(ctx context.Context, code string) (string, error) {
	if code == "" {
		return "", domain.ErrInvalidToken
	}

	saveCodeKey := fmt.Sprintf("reset-password-code:%s", code)
	if status, err := v.resetStore.Exists(ctx, saveCodeKey); err != nil {
		return "", domain.ErrInternal
	} else if !status {
		return "", domain.ErrInvalidToken
	}

	if err := v.resetStore.Delete(ctx, saveCodeKey); err != nil {
		return "", domain.ErrInternal
	}

	token, err := v.tokenManager.GenerateToken()
	if err != nil {
		return "", domain.ErrInternal
	}

	tokenHash := v.tokenManager.TokenHash(token)

	key := fmt.Sprintf("reset-password-token:%s", tokenHash)
	if err := v.resetStore.Save(ctx, key, tokenHash, 5*time.Minute); err != nil {
		return "", domain.ErrInternal
	}

	return token, nil
}
