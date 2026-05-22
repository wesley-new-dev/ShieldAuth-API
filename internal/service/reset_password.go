package service

import (
	"ShieldAuth-API/internal/repository"
	"ShieldAuth-API/internal/security"
)


type ResetPasswordService struct {
	repo repository.ResetPassword
	limiter Limiter
	Security   *security.ResetPassword
	resetStore ResetStore
	argon security.Argon2Hasher
}


func NewResetPasswordService(repo repository.ResetPassword, sec *security.ResetPassword) *ResetPasswordService {
	return &ResetPasswordService{
		repo: repo,
		Security:  sec,
	}
}