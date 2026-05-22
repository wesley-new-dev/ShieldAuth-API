package service

import "ShieldAuth-API/internal/repository"

type ChangeNameService struct {
	repo repository.ChangeName
}

func NewChangeNameService(repo repository.ChangeName) *ChangeNameService {
	return &ChangeNameService{
		repo: repo,
	}
}