package service

import (
	"context"
	"fmt"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/repository"
	"ShieldAuth-API/internal/security"
	"ShieldAuth-API/internal/security/argon2"
	"ShieldAuth-API/internal/security/hibp"
)

type RegisterService struct {
	repo repository.UserRepository
	hasher argon2.Argon2Hasher
	hibp hibp.HIBPChecker
	security security.PasswordLeakChecker
}

func NewRegisterService(repo repository.UserRepository, hibp hibp.HIBPChecker, hasher argon2.Argon2Hasher) *RegisterService {
	return &RegisterService{
		repo: repo,
		hibp: hibp,
		hasher: hasher,
	}
}


func (register *RegisterService) RegisterFunction(ctx context.Context, input RegisterInput) error {
	if err := security.VerifyPassword(register.security, input.Password); err != nil {
		return err
	}

	hash, err := register.hasher.Hash(input.Password)
	if err != nil {
		return err
	}

	defer security.ZeroMemory(input.Password)

	user := &domain.User{
		Name: input.Name,
		Email: input.Email,
		PasswordHash: []byte(hash),
	}

	err = register.repo.Create(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to register user: %w", err)
	}

	return nil
}