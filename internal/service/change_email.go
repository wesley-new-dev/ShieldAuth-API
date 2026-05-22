package service

import "ShieldAuth-API/internal/repository"


type ChangeEmailService struct {
	repo repository.ChangeEmail
}

func NewChangeEmailService(repo repository.ChangeEmail) *ChangeEmailService {
	return &ChangeEmailService{
		repo: repo,
	}
}