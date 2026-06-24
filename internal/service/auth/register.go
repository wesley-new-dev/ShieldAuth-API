package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/security"
	"ShieldAuth-API/internal/service"
)

type registerHasher interface {
	Hash(password []byte) ([]byte, error)
}

type registerHIBPChecker interface {
	IsLeaked(password []byte) (bool, error)
}

type RegisterService struct {
	repo     RegisterRepository
	hasher   registerHasher
	hibp     registerHIBPChecker
	security security.PasswordLeakChecker
}

func NewRegisterService(repo RegisterRepository, hibp registerHIBPChecker, hasher registerHasher) *RegisterService {
	return &RegisterService{
		repo:     repo,
		hibp:     hibp,
		security: hibp,
		hasher:   hasher,
	}
}

func (register *RegisterService) RegisterFunction(ctx context.Context, input service.RegisterInput) (int64, error) {

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	err := security.VerifyPassword(register.security, input.Password)
	if err != nil {
		if errors.Is(err, domain.ErrPasswordPwned) {
			return 0, domain.ErrPasswordPwned
		}
		if errors.Is(err, domain.ErrShortPassword) || errors.Is(err, domain.ErrLongPassword) {
			return 0, domain.ErrWeakPassword
		}

		return 0, domain.ErrInternal
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

func (register *RegisterService) CreateRefreshToken(ctx context.Context, userID int64, duration time.Duration) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tokenString := hex.EncodeToString(b)
	expiresAt := time.Now().Add(duration)

	hash := sha256.Sum256([]byte(tokenString))

	tokenModel := domain.RefreshToken{
		UserID:    userID,
		Token:     hash[:],
		ExpiresAt: expiresAt,
	}

	err := register.repo.SaveRefreshToken(ctx, tokenModel)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
