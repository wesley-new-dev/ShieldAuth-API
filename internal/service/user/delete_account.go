package user

import (
	"context"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/repository"
	"ShieldAuth-API/internal/security/argon2"
	"ShieldAuth-API/internal/service"
)

type DeleteAccountService struct {
	repo *repository.DeleteAccountStruct
	hasher argon2.Argon2Hasher
}


func NewDeleteAccountService(repo *repository.DeleteAccountStruct, hasher argon2.Argon2Hasher) *DeleteAccountService {
	return &DeleteAccountService{
		repo: repo,
		hasher: hasher,
	}
}


func (delete *DeleteAccountService) DeleteAccountFunction(ctx context.Context, input service.DeleteAccountInput) error {

	if len(input.CurrentPassword) == 0 {
		return domain.ErrInvalidData
	}

	if len(input.CurrentPassword) > 256 {
		return domain.ErrInvalidData
	}

	user, err := delete.repo.GetHashById(ctx, input.UserID, input.CurrentPassword)
	if err != nil {
		return domain.ErrUserNotFound
	}

	if _, err := delete.hasher.Compare(input.CurrentPassword, user.PasswordHash); err != nil {
		return domain.ErrInvalidPassword
	}

	if err := delete.repo.Delete(ctx, input.UserID); err != nil {
		return domain.ErrInternal
	}

	return nil
}