package user

import (
	"bytes"
	"context"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/security"
	"ShieldAuth-API/internal/security/argon2"
	"ShieldAuth-API/internal/security/hibp"
	"ShieldAuth-API/internal/service"
)

type ChangePasswordRepo interface {
	FindById(ctx context.Context, id int) (*domain.User, error)
	UpdatePasswordHash(ctx context.Context, id int, hash []byte) error
}

type ChangePasswordService struct {
	repo   ChangePasswordRepo
	hasher argon2.Hasher
	hibp   hibp.HIBPChecker
}

func NewChangePasswordService(repo ChangePasswordRepo, hasher argon2.Hasher, hibp hibp.HIBPChecker) *ChangePasswordService {
	return &ChangePasswordService{
		repo:   repo,
		hasher: hasher,
		hibp:   hibp,
	}
}

func (changePassword *ChangePasswordService) ChangePassword(ctx context.Context, input service.ChangePasswordInput) error {

	if len(input.NewPassword) < 8 {
		return domain.ErrShortPassword
	}

	if len(input.NewPassword) > 256 {
		return domain.ErrLongPassword
	}

	if !bytes.Equal(input.NewPassword, input.ConfirmPassword) {
		return domain.ErrPasswordDoNotMatch
	}

	user, err := changePassword.repo.FindById(ctx, input.UserID)
	if err != nil {
		return domain.ErrUserNotFound
	}

	if len(user.PasswordHash) == 0 {
		return domain.ErrInvalidCredentials
	}

	if _, err := changePassword.hasher.Compare(input.CurrentPassword, user.PasswordHash); err != nil {
		return domain.ErrInvalidCredentials
	}

	defer security.ZeroMemory(input.CurrentPassword)
	defer security.ZeroMemory(input.NewPassword)
	defer security.ZeroMemory(input.ConfirmPassword)

	newHash, err := changePassword.hasher.Hash(input.NewPassword)
	if err != nil {
		return domain.ErrInternal
	}

	if err := changePassword.repo.UpdatePasswordHash(ctx, input.UserID, newHash); err != nil {
		return domain.ErrInternal
	}

	return nil
}
