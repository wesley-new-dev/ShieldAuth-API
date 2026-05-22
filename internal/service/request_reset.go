package service

import (
	"ShieldAuth-API/internal/repository"
	"ShieldAuth-API/internal/security"
)

type RequestResetService struct {
	userRepo repository.UserRepository
	tokenizer security.TokenGenerator
	resetStore ResetStore
	limiter Limiter
}

func NewRequestResetService(userRepo repository.UserRepository, resetStore ResetStore, tokenizer security.TokenGenerator, limiter Limiter) *RequestResetService {
	return &RequestResetService{
		userRepo: userRepo,
		resetStore: resetStore,
		tokenizer: tokenizer,
		limiter: limiter,
	}
}