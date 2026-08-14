package notification

import (
	"context"
	"log/slog"
)

type SendNotification interface {
	SendPasswordChangedEmail(ctx context.Context, email string) error
	SendPasswordResetCode(ctx context.Context, email, code string) error
}

type consoleNotificationService struct{}

func NewConsoleNotificationService() SendNotification {
	return &consoleNotificationService{}
}

func (s *consoleNotificationService) SendPasswordChangedEmail(ctx context.Context, email string) error {
	slog.InfoContext(ctx, "[ALERT][SIMULATION] Password changed email simulated",
		"component", "notification_service",
		"target_email", email,
		"status", "dispatched")
	return nil
}

func (s *consoleNotificationService) SendPasswordResetCode(ctx context.Context, email, code string) error {
	slog.InfoContext(ctx, "[ALERT][SIMULATION] Password reset code",
	"component", "notification_service",
	"target_email", email,
	"reset_code", code,
	"status", "dispatched")
	return nil
}
