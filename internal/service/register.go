package service

import (
	"ShieldAuth-API/internal/repository"
	"ShieldAuth-API/internal/security"
)

type RegisterService struct {
	repo repository.User
	argon security.Argon2Hasher
}

func NewRegisterService(repo repository.User) *RegisterService {
	return &RegisterService{
		repo: repo,
	}
}