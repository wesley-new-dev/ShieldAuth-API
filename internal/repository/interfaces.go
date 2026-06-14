package repository

import (
	"context"
	
	"ShieldAuth-API/internal/domain"
)

type UserRepository interface {
	Create(ctx context.Context, user *domain.User) (int64, error)

	GetByID(ctx context.Context, id int64) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)

	Update(ctx context.Context, user *domain.User) error
	Delete(ctx context.Context, id int) error
}

type RefreshTokenRepository interface {
	FindByHash(ctx context.Context, hash []byte) (*RefreshTokenRepository, error)

	Revoke(ctx context.Context, token_hash []byte) error
	RevokeSession(ctx context.Context, sessionID string) error
	RevokeAllUserSession(ctx context.Context, userID int64) error

	UpdateLastUsed(ctx context.Context, id int64) error

	Create(ctx context.Context, token *RefreshTokenRepository) error
}