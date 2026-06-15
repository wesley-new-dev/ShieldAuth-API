package auth

import (
	"context"
	"crypto/sha256"

	"ShieldAuth-API/internal/service"
)


type LogOutService struct {
	repo LogOutRepository
}


func NewLogOutService(repo LogOutRepository) *LogOutService {
	return &LogOutService{
		repo: repo,
	}
}


func (logout *LogOutService) LogOutFunction(ctx context.Context, input service.LogOutInput) error {

	hash := sha256.Sum256([]byte(input.RefreshToken))
	err := logout.repo.Revoke(ctx, hash[:])
	if err != nil {
		return err
	}

	return nil
}