package service

import (
	"fmt"
	"context"
	
	"ShieldAuth-API/internal/repository"
)

type ChangeNameService struct {
	repo repository.ChangeNameStruct
}

func NewChangeNameService(repo repository.ChangeNameStruct) *ChangeNameService {
	return &ChangeNameService{
		repo: repo,
	}
}


func (changeName *ChangeNameService) ChangeNameFunction(ctx context.Context, input ChangeNameInput) error {

	user, err := changeName.repo.GetForChangeName(ctx, input.ID)
	if err != nil {
		return fmt.Errorf("getting user by id: %w", err)
	}

	if err := user.ChangeName(input.CurrentName, input.NewName); err != nil {
		return fmt.Errorf("changing user name: %w", err)
	}

	if err := changeName.repo.UpdateName(ctx, user); err != nil {
		return fmt.Errorf("changing user name: %w", err)
	}

	return nil
}