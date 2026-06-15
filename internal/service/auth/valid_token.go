package auth

import (
	"context"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/security/redis"
)


type ValidTokenService struct {
	resetStore redis.PasswordResetStore
}


func NewValidToken(resetStore redis.PasswordResetStore) *ValidTokenService {
	return &ValidTokenService{
		resetStore: resetStore,
	}
}


func (v *ValidTokenService) ValidToken(ctx context.Context, token string) error {
	if token == "" {
		return domain.ErrInvalidToken
	}

	_, err := v.resetStore.Get(ctx, token)
	if err != nil {
		return domain.ErrInvalidToken
	}

	return nil
}