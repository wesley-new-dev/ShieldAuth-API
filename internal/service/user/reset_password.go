package user

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strconv"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/repository"
	"ShieldAuth-API/internal/security"
	"ShieldAuth-API/internal/security/argon2"
	"ShieldAuth-API/internal/security/redis"
	"ShieldAuth-API/internal/service"
)

type ResetPasswordRepo interface {
	UpdatePassword(ctx context.Context, userID string, passwordHash []byte) error
	GetID(ctx context.Context, id int64) (*domain.User, error)
}

type ResetPasswordService struct {
	repo        ResetPasswordRepo
	security    security.TokenManager
	hasher      argon2.Hasher
	redis       redis.PasswordResetStore
	audit_trail repository.AccountAuditRepository
}

func NewResetPasswordService(repo ResetPasswordRepo, security security.TokenManager, hasher argon2.Hasher, redis redis.PasswordResetStore, audit_trail repository.AccountAuditRepository) *ResetPasswordService {
	return &ResetPasswordService{
		repo:        repo,
		security:    security,
		hasher:      hasher,
		redis:       redis,
		audit_trail: audit_trail,
	}
}

func (r *ResetPasswordService) ResetPasswordFunction(ctx context.Context, token string, input service.ResetPasswordInput, userAgent string) error {

	tokenHash := r.security.TokenHash(token)
	key := fmt.Sprintf("reset-password-token:%s", tokenHash)
	userID, err := r.redis.Get(ctx, key)
	if err != nil {
		return fmt.Errorf("invalid or expired token: %w", err)
	}

	defer r.redis.Delete(ctx, key)
	var hashedPassword []byte

	userIdInt64, _ := strconv.ParseInt(userID, 10, 64)
	user, err := r.repo.GetID(ctx, userIdInt64)
	if err != nil {
		return err
	}

	err = input.NewPassword.ExecuteWithDecrypted(func(newPasswordBytes []byte) error {
		var matchErr error

		_ = input.ConfirmPassword.ExecuteWithDecrypted(func(confirmBytes []byte) error {
			if !bytes.Equal(newPasswordBytes, confirmBytes) {
				matchErr = domain.ErrPasswordDoNotMatch
			}
			// defer security.ZeroMemory(confirmBytes)

			return nil
		})

		if matchErr != nil {
			return matchErr
		}

		userContextInputs := []string{user.Name, user.Email}
		if err := security.VerifyPasswordAdvanced(newPasswordBytes, userContextInputs); err != nil {
			return err
		}

		hash, err := r.hasher.Hash(newPasswordBytes)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}
		hashedPassword = hash
		// defer security.ZeroMemory(newPasswordBytes)

		return nil
	})

	if err != nil {
		return err
	}

	err = r.repo.UpdatePassword(ctx, userID, hashedPassword)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	go func(id int64, userAgentString string) {
		auditContext := context.Background()
		auditEvent := repository.AccountEventAudit{
			UserID:    id,
			EventType: "FORGOT_PASSWORD_SUCCESS",
			UserAgent: userAgentString,
		}
		if err := r.audit_trail.CreateEvent(auditContext, auditEvent); err != nil {
			slog.Error("failed to write forgot password success audit", slog.Any("error", err), slog.Int64("user_id", id), slog.String("event_type", "FORGOT_PASSWORD_SUCCESS"))
		}

	}(user.Id, userAgent)

	return nil
}
