package user

import (
	"context"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/security/argon2"
	"ShieldAuth-API/internal/service"
)

type DeleteAccountRepo interface {
	GetHashById(ctx context.Context, id int) (*domain.User, error)
	Delete(ctx context.Context, id int) error
}

type DeleteAccountService struct {
	repo   DeleteAccountRepo
	hasher argon2.Hasher
}

func NewDeleteAccountService(repo DeleteAccountRepo, hasher argon2.Hasher) *DeleteAccountService {
	return &DeleteAccountService{
		repo:   repo,
		hasher: hasher,
	}
}

func (delete *DeleteAccountService) DeleteAccountFunction(ctx context.Context, input service.DeleteAccountInput) error {

	user, err := delete.repo.GetHashById(ctx, input.UserID)
	if err != nil {
		return domain.ErrUserNotFound
	}

	var compareError error
	err = input.CurrentPassword.ExecuteWithDecrypted(func(currentPasswordBytes []byte) error {

		if len(currentPasswordBytes) < 8 || len(currentPasswordBytes) > 256 {
			compareError = domain.ErrInvalidData
			return nil
		}

		if _, err := delete.hasher.Compare(currentPasswordBytes, user.PasswordHash); err != nil {
			compareError = domain.ErrInvalidPassword
			return nil
		}
		// defer security.ZeroMemory(currentPasswordBytes)

		return nil
	})

	if err != nil {
		return err
	}

	if compareError != nil {
		return compareError
	}

	if err := delete.repo.Delete(ctx, input.UserID); err != nil {
		return domain.ErrInternal
	}

	return nil
}
