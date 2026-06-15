package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/security"
	"ShieldAuth-API/internal/security/argon2"
	"ShieldAuth-API/internal/security/hibp"
	"ShieldAuth-API/internal/service"
)

type RegisterService struct {
	repo     RegisterRepository
	hasher   argon2.Argon2Hasher
	hibp     hibp.HIBPChecker
	security security.PasswordLeakChecker
}


func NewRegisterService(repo RegisterRepository, hibp hibp.HIBPChecker, hasher argon2.Argon2Hasher) *RegisterService {
	return &RegisterService{
		repo:     repo,
		hibp:     hibp,
		security: &hibp,
		hasher:   hasher,
	}
}


func (register *RegisterService) RegisterFunction(ctx context.Context, input service.RegisterInput) (int64, error) {

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if err := security.VerifyPassword(register.security, input.Password); err != nil {
		return 0, domain.ErrWeakPassword
	}

	hash, err := register.hasher.Hash(input.Password)
	if err != nil {
		return 0, err
	}

	defer security.ZeroMemory(input.Password)

	user := &domain.User{
		Name:         input.Name,
		Email:        input.Email,
		PasswordHash: hash,
	}

	id, err := register.repo.Create(ctx, user)
	if err != nil {
		return 0, fmt.Errorf("failed to register user: %w", err)
	}

	return id, nil
}

func (register *RegisterService) CreateRefreshToken(ctx context.Context, userID int64, duration time.Duration) (string, error)  {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tokenString := hex.EncodeToString(b)
	expiresAt := time.Now().Add(duration)

	tokenModel := domain.RefreshToken{
		UserID:    userID,
		Token:     tokenString,
		ExpiresAt: expiresAt,
	}

	err := register.repo.SaveRefreshToken(ctx, tokenModel)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}