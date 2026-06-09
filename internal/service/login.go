package service

import (
	"context"
	"time"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/security"
	"ShieldAuth-API/internal/security/argon2"
)

var dummyArgon2Hash = []byte("DPunA5HgdFJkHrryZptqsQLwmAB4NfaRoM/TiI3Elg01fD2iGX7DuMlQ6B6KATx")

type LoginRepository interface {
	GetByIdentifier(ctx context.Context, identifier string) (*domain.User, error)
	Rehash(ctx context.Context, id int, hash []byte) error
}

type LoginService struct {
	repo LoginRepository
	hasher argon2.Argon2Hasher
}

func NewLoginService(repo LoginRepository, hasher argon2.Argon2Hasher) *LoginService {
	return &LoginService{
		repo: repo,
		hasher: hasher,
	}
}


func (s *LoginService) VerifyLoginFunction(ctx context.Context, input LoginInput) (int, error) {

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	identifier := input.Email
	if identifier == "" {
		identifier = input.Name
	}

	if identifier == "" {
		return 0, domain.ErrInvalidData
	}

	defer security.ZeroMemory(input.Password)

	user, err := s.repo.GetByIdentifier(ctx, identifier)
	if err != nil {
		_, _ = s.hasher.Compare(input.Password, dummyArgon2Hash)
		return 0, domain.ErrInvalidCredentials
	}

	if err := ctx.Err(); err != nil {
		return 0, err
	}

	hashData, err := s.hasher.Compare(input.Password, user.PasswordHash)
	if err != nil {
		return 0, domain.ErrInvalidCredentials
	}

	if s.hasher.NeedsRehash(hashData.Memory, hashData.Iterations, hashData.Parallelism) {

		newHash, err := s.hasher.Hash(input.Password)
		if err != nil {

			updateCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = s.repo.Rehash(updateCtx, user.Id, newHash)
		}
	}

	return user.Id, nil
}