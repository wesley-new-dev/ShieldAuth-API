package user

import (
	"context"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/repository"
	"ShieldAuth-API/internal/security"
	"ShieldAuth-API/internal/security/argon2"
	"ShieldAuth-API/internal/service"
)


type ChangeEmailService struct {
	repo   *repository.ChangeEmailStruct
	hasher argon2.Argon2Hasher
}


func NewChangeEmailService(repo *repository.ChangeEmailStruct, hasher argon2.Argon2Hasher) *ChangeEmailService {
	return &ChangeEmailService{
		repo:   repo,
		hasher: hasher,
	}
}


func (changeEmail *ChangeEmailService) ChangeEmailFunctionTest(ctx context.Context, input service.ChangeEmailInput) error {

	user, err := changeEmail.repo.GetID(ctx, input.ID)
	if err != nil {
		return domain.ErrUserNotFound
	}

	if _, err := changeEmail.hasher.Compare(input.Password, user.PasswordHash); err != nil {
		return domain.ErrInvalidPassword
	}

	defer security.ZeroMemory(input.Password)

	if err := user.ChangeEmail(input.CurrentEmail, input.NewEmail, input.ConfirmNewEmail); err != nil {
		return domain.ErrInternal
	}

	if err := changeEmail.repo.UpdateEmail(ctx, user); err != nil {
		return domain.ErrInternal
	}

	return nil
}