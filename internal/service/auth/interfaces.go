package auth

import (
	"context"

	"ShieldAuth-API/internal/domain"
)

type RegisterRepository interface {
	Create(ctx context.Context, u *domain.User) (int64, error)
	SaveRefreshToken(ctx context.Context, model domain.RefreshToken) error
}

type LogOutRepository interface {
	Revoke(ctx context.Context, token_hash []byte) error
}

type LoginRepository interface {
	GetByIdentifier(ctx context.Context, identifier string) (*domain.User, error)
	Rehash(ctx context.Context, id int64, hash []byte) error
	SaveRefreshToken(ctx context.Context, model domain.RefreshToken) error
}