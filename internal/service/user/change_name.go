package user

import (
	"context"
	"errors"
	"fmt"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/repository"
	"ShieldAuth-API/internal/service"
)


type ChangeNameService struct {
	repo *repository.ChangeNameStruct
}


func NewChangeNameService(repo *repository.ChangeNameStruct) *ChangeNameService {
	return &ChangeNameService{
		repo: repo,
	}
}


func (changeName *ChangeNameService) ChangeNameFunction(ctx context.Context, input service.ChangeNameInput) error {

	user, err := changeName.repo.GetForChangeName(ctx, input.ID)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return fmt.Errorf("fetching user: %w", domain.ErrUserNotFound)
		}
		return fmt.Errorf("database error fetching user: %w", domain.ErrInternal)
	}

	if err := user.ChangeName(input.CurrentName, input.NewName); err != nil {
		return fmt.Errorf("changing user name: %w", err)
	}

	if err := changeName.repo.UpdateName(ctx, user); err != nil {
		return fmt.Errorf("changing user name: %w", domain.ErrInternal)
	}

	return nil
}