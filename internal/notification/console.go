package notification

import (
	"context"
	"log/slog"
)

type SendNotification interface {
	SendPasswordChangedEmail(ctx context.Context, email string) error
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
