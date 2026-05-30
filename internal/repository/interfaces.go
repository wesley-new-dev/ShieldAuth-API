package repository

import (
	"context"
	
	"ShieldAuth-API/internal/domain"
)

type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error

	GetByID(ctx context.Context, id int64) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)

	Update(ctx context.Context, user *domain.User) error
	Delete(ctx context.Context, id int64) error
}