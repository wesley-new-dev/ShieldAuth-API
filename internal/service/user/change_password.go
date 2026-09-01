package user

import (
	"bytes"
	"context"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/security"
	"ShieldAuth-API/internal/security/argon2"
	"ShieldAuth-API/internal/service"
)

type ChangePasswordRepo interface {
	FindById(ctx context.Context, id int) (*domain.User, error)
	UpdatePasswordHash(ctx context.Context, id int, hash []byte) error
}

type ChangePasswordService struct {
	repo   ChangePasswordRepo
	hasher argon2.Hasher
}

func NewChangePasswordService(repo ChangePasswordRepo, hasher argon2.Hasher) *ChangePasswordService {
	return &ChangePasswordService{
		repo:   repo,
		hasher: hasher,
	}
}

func (changePassword *ChangePasswordService) ChangePassword(ctx context.Context, input service.ChangePasswordInput) error {
	var (
		newPasswordBytes []byte
		currentPassword  []byte
		confirmPassword  []byte
	)

	if err := input.NewPassword.ExecuteWithDecrypted(func(newPassword []byte) error {
		newPasswordBytes = append([]byte(nil), newPassword...)
		if len(newPasswordBytes) < 8 {
			return domain.ErrShortPassword
		}
		if len(newPasswordBytes) > 256 {
			return domain.ErrLongPassword
		}
		return input.ConfirmPassword.ExecuteWithDecrypted(func(confirm []byte) error {
			confirmPassword = append([]byte(nil), confirm...)
			if !bytes.Equal(newPasswordBytes, confirmPassword) {
				return domain.ErrPasswordDoNotMatch
			}
			return nil
		})
	}); err != nil {
		return err
	}

	user, err := changePassword.repo.FindById(ctx, input.UserID)
	if err != nil {
		return domain.ErrUserNotFound
	}

	if len(user.PasswordHash) == 0 {
		return domain.ErrInvalidCredentials
	}

	if err := input.CurrentPassword.ExecuteWithDecrypted(func(current []byte) error {
		currentPassword = append([]byte(nil), current...)
		if _, err := changePassword.hasher.Compare(currentPassword, user.PasswordHash); err != nil {
			return domain.ErrInvalidCredentials
		}
		return nil
	}); err != nil {
		return err
	}

	defer security.ZeroMemory(currentPassword)
	defer security.ZeroMemory(newPasswordBytes)
	defer security.ZeroMemory(confirmPassword)

	newHash, err := changePassword.hasher.Hash(newPasswordBytes)
	if err != nil {
		return domain.ErrInternal
	}

	if err := changePassword.repo.UpdatePasswordHash(ctx, input.UserID, newHash); err != nil {
		return domain.ErrInternal
	}

	return nil
}
