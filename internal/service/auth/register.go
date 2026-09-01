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

	"github.com/google/uuid"
)

var sessionIDRegister = uuid.New()

type registerHasher interface {
	Hash(password []byte) ([]byte, error)
}

type RegisterService struct {
	repo   RegisterRepository
	hasher registerHasher
}

func NewRegisterService(repo RegisterRepository, hasher registerHasher) *RegisterService {
	return &RegisterService{
		repo:   repo,
		hasher: hasher,
	}
}

func (register *RegisterService) RegisterFunction(ctx context.Context, input service.RegisterInput) (int64, int, uuid.UUID, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	userInputs := []string{input.Name, input.Email}

	var passwordBytes []byte
	if err := input.Password.ExecuteWithDecrypted(func(password []byte) error {
		passwordBytes = append([]byte(nil), password...)
		if err := security.VerifyPasswordAdvanced(passwordBytes, userInputs); err != nil {
			if errors.Is(err, domain.ErrShortPassword) || errors.Is(err, domain.ErrLongPassword) {
				return domain.ErrWeakPassword
			}
			return err
		}
		return nil
	}); err != nil {
		return 0, 0, uuid.Nil, err
	}

	hash, err := register.hasher.Hash(passwordBytes)
	if err != nil {
		return 0, 0, uuid.Nil, err
	}

	defer security.ZeroMemory(passwordBytes)

	user := &domain.User{
		Name:         input.Name,
		Email:        input.Email,
		JWTVersion:   1,
		PasswordHash: hash,
	}

	id, jwt_version, err := register.repo.Create(ctx, user)
	if err != nil {
		return 0, 0, uuid.Nil, fmt.Errorf("failed to register user: %w", err)
	}

	return id, jwt_version, sessionIDRegister, nil
}

func (register *RegisterService) CreateRefreshToken(ctx context.Context, userID int64, duration time.Duration) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tokenString := hex.EncodeToString(b)
	expiresAt := time.Now().Add(duration)
	sessionID := uuid.New()

	hash := sha256.Sum256([]byte(tokenString))
	tokenModel := domain.RefreshToken{
		UserID:    userID,
		Token:     hex.EncodeToString(hash[:]),
		SessionID: sessionID,
		ExpiresAt: expiresAt,
	}

	err := register.repo.SaveRefreshToken(ctx, tokenModel)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
