package service

import "ShieldAuth-API/internal/repository"

type LoginService struct {
	repo repository.LoginUser
}

func NewLoginService(repo repository.LoginUser) *LoginService {
	return &LoginService{
		repo: repo,
	}
}