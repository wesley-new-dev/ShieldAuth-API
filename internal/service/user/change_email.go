package user

import (
	"context"
	"log/slog"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/repository"
	"ShieldAuth-API/internal/security/argon2"
	"ShieldAuth-API/internal/service"
)

type ChangeEmailRepo interface {
	GetID(ctx context.Context, id int) (*domain.User, error)
	UpdateEmail(ctx context.Context, user *domain.User) error
}

type ChangeEmailService struct {
	repo        ChangeEmailRepo
	hasher      argon2.Hasher
	audit_trail repository.AccountAuditRepository
}

func NewChangeEmailService(repo ChangeEmailRepo, hasher argon2.Hasher, audit_trail repository.AccountAuditRepository) *ChangeEmailService {
	return &ChangeEmailService{
		repo:        repo,
		hasher:      hasher,
		audit_trail: audit_trail,
	}
}

func (changeEmail *ChangeEmailService) ChangeEmailFunction(ctx context.Context, input service.ChangeEmailInput, userAgent string) error {

	user, err := changeEmail.repo.GetID(ctx, input.ID)
	if err != nil {
		return domain.ErrUserNotFound
	}

	err = input.Password.ExecuteWithDecrypted(func(decryptedBytes []byte) error {
		if _, err := changeEmail.hasher.Compare(decryptedBytes, user.PasswordHash); err != nil {
			return domain.ErrInvalidPassword
		}

		return nil
	})

	if err != nil {
		return err
	}

	if err := user.ChangeEmail(input.CurrentEmail, input.NewEmail, input.ConfirmNewEmail); err != nil {
		return domain.ErrInternal
	}

	if err := changeEmail.repo.UpdateEmail(ctx, user); err != nil {
		return domain.ErrInternal
	}

	go func(id int64, userAgentString string) {
		auditContext := context.Background()
		auditEvent := repository.AccountEventAudit{
			UserID:    id,
			EventType: "EMAIL_CHANGE",
			UserAgent: userAgentString,
		}
		if err := changeEmail.audit_trail.CreateEvent(auditContext, auditEvent); err != nil {
			slog.Error("failed to write email change audit", slog.Any("error", err), slog.Int64("user_id", id), slog.String("event_type", "EMAIL_CHANGE"))
		}

	}(user.Id, userAgent)

	return nil
}
