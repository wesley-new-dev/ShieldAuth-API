package auth

import (
	"context"
	"time"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/repository"
)

type RegisterRepository interface {
	Create(ctx context.Context, u *domain.User) (int64, int, error)
}

type LogOutRepository interface {
	Revoke(ctx context.Context, token_hash []byte) error
}

type LoginRepository interface {
	GetByIdentifier(ctx context.Context, identifier string) (*domain.User, error)
	Rehash(ctx context.Context, id int64, hash []byte) error
}

type RefreshTokenRepository interface {
	FindByHash(ctx context.Context, tokenHash []byte) (*domain.RefreshToken, int, error)
	Revoke(ctx context.Context, token_hash []byte) error
	SaveRefreshToken(ctx context.Context, model domain.RefreshToken) error
}

type RevokeSessionRepository interface {
	Revoke(ctx context.Context, token_hash []byte) error
	IncrementJWTVersion(ctx context.Context, userID int64) (int64, error)
}

type UserSessionRepository interface {
	Create(ctx context.Context, session *repository.UserSession) error
	GetActiveByUserID(ctx context.Context, userID int64) ([]*repository.UserSession, error)
	Revoke(ctx context.Context, sessionID string) error
	RevokeAllUserByUserID(ctx context.Context, userID int64) error
}

type ResetTokenRepository interface {
	Create(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time, userAgent string) error
	Consume(ctx context.Context, tokenHas string) (int64, error)
}
