package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/repository"
	"ShieldAuth-API/internal/security/argon2"
	"ShieldAuth-API/internal/security/redis"
	"ShieldAuth-API/internal/service"

	"github.com/google/uuid"
)

var sessionIDLogin = uuid.New()
var dummyArgon2Hash = []byte("DPunA5HgdFJkHrryZptqsQLwmAB4NfaRoM/TiI3Elg01fD2iGX7DuMlQ6B6KATx")

type LoginService struct {
	repo        LoginRepository
	hasher      argon2.Hasher
	redis       redis.PasswordResetStore
	auditRepo   domain.LoginAttemptsAudit
	audit       repository.SessionAndAudit
	sessionRepo UserSessionRepository
	audit_trail repository.AccountAuditRepository
}

func NewLoginService(repo LoginRepository, hasher argon2.Hasher, redis redis.PasswordResetStore, auditRepo domain.LoginAttemptsAudit, audit repository.SessionAndAudit, sessionRepo UserSessionRepository, audit_trail repository.AccountAuditRepository) *LoginService {
	return &LoginService{
		repo:        repo,
		hasher:      hasher,
		redis:       redis,
		auditRepo:   auditRepo,
		audit:       audit,
		sessionRepo: sessionRepo,
		audit_trail: audit_trail,
	}
}

func (s *LoginService) VerifyLoginFunction(ctx context.Context, input service.LoginInput, userAgent string) (int64, int, uuid.UUID, error) {

	audit := &domain.LoginAttemptsAudit{
		Email:     input.Email,
		UserAgent: userAgent,
		Success:   false,
	}

	var loginErr error
	defer func() {
		if loginErr != nil {
			reason := loginErr.Error()
			audit.FailureReason = &reason
		}
		if s.audit.Database != nil {
			_ = s.audit.Create(ctx, audit)
		}
	}()

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	identifier := input.Email
	if identifier == "" {
		identifier = input.Name
	}

	if identifier == "" {
		loginErr = domain.ErrInvalidData
		return 0, 0, uuid.Nil, loginErr
	}

	user, err := s.repo.GetByIdentifier(ctx, identifier)
	if err != nil {
		_ = input.Password.ExecuteWithDecrypted(func(decryptedBytes []byte) error {
			passwordBytes := append([]byte(nil), decryptedBytes...)
			_, _ = s.hasher.Compare(passwordBytes, dummyArgon2Hash)
			return nil
		})
		loginErr = domain.ErrUserNotFound
		return 0, 0, uuid.Nil, loginErr
	}
	audit.UserID = &user.Id

	err = s.redis.Save(ctx, fmt.Sprintf("user:version:%d", user.Id), int64(user.JWTVersion), 24*time.Hour)
	if err != nil {
		loginErr = domain.ErrCacheError
		return 0, 0, uuid.Nil, loginErr
	}

	if err := ctx.Err(); err != nil {
		loginErr = domain.ErrContextTimeout
		return 0, 0, uuid.Nil, loginErr
	}

	var hashData *argon2.HashMetaData
	var wrongPasswordBytes bool
	var newHash []byte

	err = input.Password.ExecuteWithDecrypted(func(decryptedBytes []byte) error {
		passwordBytes := append([]byte(nil), decryptedBytes...)

		data, compareErr := s.hasher.Compare(passwordBytes, user.PasswordHash)
		if compareErr != nil {
			wrongPasswordBytes = true
			return compareErr
		}
		hashData = data

		if s.hasher.NeedsRehash(hashData.Memory, hashData.Iterations, hashData.Parallelism) {
			generatedHash, rehashErr := s.hasher.Hash(passwordBytes)
			if rehashErr == nil {
				newHash = generatedHash
			}
		}
		return nil
	})

	if err != nil && wrongPasswordBytes {
		loginErr = domain.ErrInvalidPassword
		return 0, 0, uuid.Nil, loginErr
	} else if err != nil {
		return 0, 0, uuid.Nil, err
	}

	if len(newHash) > 0 {
		updateCtx, rehashCancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = s.repo.Rehash(updateCtx, user.Id, newHash)
		rehashCancel()
	}

	deviceType := "Desktop"

	lower := strings.ToLower(userAgent)
	if strings.Contains(lower, "mobile") {
		deviceType = "Mobile"
	} else if strings.Contains(lower, "tablet") {
		deviceType = "Tablet"
	}

	sessionIDLoginByte := sessionIDLogin[:]

	session := &repository.UserSession{
		ID:         sessionIDLoginByte,
		UserID:     user.Id,
		UserAgent:  userAgent,
		DeviceType: deviceType,
	}

	if s.sessionRepo != nil {
		if err := s.sessionRepo.Create(ctx, session); err != nil {
			slog.ErrorContext(ctx, "failed to save session to database", "user_id", user.Id, "error", err)
			loginErr = domain.ErrInternal
			return 0, 0, uuid.Nil, loginErr
		}
	}

	if err := s.redis.Save(ctx, fmt.Sprintf("session:%d:%s", user.Id, sessionIDLogin), int64(user.JWTVersion), 24*time.Hour); err != nil {
		slog.ErrorContext(ctx, "failed to save session to cache", "user_id", user.Id, "error", err)
		loginErr = domain.ErrCacheError
		return 0, 0, uuid.Nil, loginErr
	}

	go func(id int64, userAgentString string) {
		auditContext := context.Background()
		auditEvent := repository.AccountEventAudit{
			UserID:    id,
			EventType: "LOGIN_SUCCESS",
			UserAgent: userAgent,
		}
		if s.audit_trail != nil {
			if err := s.audit_trail.CreateEvent(auditContext, auditEvent); err != nil {
				slog.Error("failed to write login success audit", slog.Any("error", err), slog.Int64("user_id", id), slog.String("event_type", "LOGIN_SUCCESS"))
			}
		}

	}(user.Id, userAgent)

	audit.Success = true
	audit.FailureReason = nil
	return user.Id, user.JWTVersion, sessionIDLogin, nil
}

func (s *LoginService) CreateRefreshToken(ctx context.Context, userID int64, duration time.Duration) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tokenString := hex.EncodeToString(b)
	expiresAt := time.Now().Add(duration)

	hash := sha256.Sum256([]byte(tokenString))
	hashString := hex.EncodeToString(hash[:])

	tokenModel := domain.RefreshToken{
		UserID:    userID,
		Token:     hashString,
		SessionID: sessionIDLogin,
		ExpiresAt: expiresAt,
	}

	err := s.repo.SaveRefreshToken(ctx, tokenModel)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
