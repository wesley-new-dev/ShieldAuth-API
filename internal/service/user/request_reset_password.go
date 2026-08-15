package user

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/notification"
	"ShieldAuth-API/internal/repository"
	"ShieldAuth-API/internal/security"
	"ShieldAuth-API/internal/security/redis"
)

type RequestResetRepo interface {
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
}

type RequestResetService struct {
	userRepo    RequestResetRepo
	tokenizer   security.TokenManager
	resetStore  redis.PasswordResetStore
	notification notification.SendNotification
	audit_trail repository.AccountAuditRepository
}

func NewRequestResetService(userRepo RequestResetRepo, resetStore redis.PasswordResetStore, tokenizer security.TokenManager, notification notification.SendNotification, audit_trail repository.AccountAuditRepository) *RequestResetService {
	return &RequestResetService{
		userRepo:    userRepo,
		resetStore:  resetStore,
		tokenizer:   tokenizer,
		notification: notification,
		audit_trail: audit_trail,
	}
}

func (r *RequestResetService) RequestReset(ctx context.Context, email string, userAgent string) (string, string, error) {

	user, err := r.userRepo.GetByEmail(ctx, email)
	if err != nil {
		_, _ = r.tokenizer.GenerateToken()
		return "dummy-token", "", nil
	}

	token, err := r.tokenizer.GenerateToken()
	if err != nil {
		return "", "", fmt.Errorf("generate token: %w", err)
	}

	if err := r.resetStore.Save(ctx, token, user.Id, 15*time.Minute); err != nil {
		return "", "", domain.ErrInternal
	}

	code, err := GenerateResetCode()
	if err != nil {
		return "", "", fmt.Errorf("generate reset code: %w", err)
	}

	saveCodeKey := fmt.Sprintf("reset-password-code:%s", code)
	if err := r.resetStore.Save(ctx, saveCodeKey, user.Id, 15*time.Minute); err != nil {
		return "", "", domain.ErrInternal
	}

	go func(id int64, userAgentString string) {
		auditContext := context.Background()
		auditEvent := repository.AccountEventAudit{
			UserID:    id,
			EventType: "FORGOT_PASSWORD_REQUESTED",
			UserAgent: userAgentString,
		}
		if err := r.audit_trail.CreateEvent(auditContext, auditEvent); err != nil {
			slog.Error("failed to write forgot password requested audit", slog.Any("error", err), slog.Int64("user_id", id), slog.String("event_type", "FORGOT_PASSWORD_REQUESTED"))
		}

	}(user.Id, userAgent)

	_ = r.notification.SendPasswordResetCode(ctx, user.Email, code)

	return code, user.Email, nil
}

func GenerateResetCode() (string, error) {
	max := big.NewInt(1000000)

	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%06d", n.Int64()), nil
}	
