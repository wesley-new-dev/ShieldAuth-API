package user

import (
	"context"
	"crypto/subtle"
	"fmt"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/repository"
	"ShieldAuth-API/internal/security"
	"ShieldAuth-API/internal/security/argon2"
	"ShieldAuth-API/internal/security/hibp"
	"ShieldAuth-API/internal/security/redis"
	"ShieldAuth-API/internal/service"
)


type ResetPasswordService struct {
	repo     *repository.ResetPasswordStruct
	security security.PasswordLeakChecker
	hibp     hibp.HIBPChecker
	hasher   argon2.Argon2Hasher
	redis    redis.PasswordResetStore
}


func NewResetPasswordService(repo *repository.ResetPasswordStruct, security security.PasswordLeakChecker, hibp hibp.HIBPChecker, hasher argon2.Argon2Hasher) *ResetPasswordService {
	return &ResetPasswordService{
		repo:     repo,
		security: security,
		hibp:     hibp,
		hasher:   hasher,
	}
}


func (r *ResetPasswordService) ResetPasswordFunction(ctx context.Context, token string, input service.ResetPasswordInput) error {
	if subtle.ConstantTimeCompare(input.NewPassword, input.ConfirmPassword) != 1 {
		return domain.ErrPasswordDoNotMatch
	}

	defer r.redis.Delete(ctx, token)
	defer security.ZeroMemory(input.NewPassword)

	err := security.VerifyPassword(r.security, input.NewPassword)
	if err != nil {
		return err
	}

	userID, err := r.redis.Get(ctx, token)
	if err != nil {
		return fmt.Errorf("invalid or expired token: %w", err)
	}

	hashedPassword, err := r.hasher.Hash(input.NewPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	err = r.repo.UpdatePassword(ctx, userID, hashedPassword)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}