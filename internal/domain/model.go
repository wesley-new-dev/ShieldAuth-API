package domain

import (
	"time"

	"github.com/google/uuid"
)

type RefreshToken struct {
	ID        int64      `json:"id"`
	UserID    int64      `json:"user_id"`
	Token     string     `json:"token"`
	SessionID uuid.UUID  `json:"session_id,omitempty"`
	ExpiresAt time.Time  `json:"expires_at"`
	CreatedAt time.Time  `json:"created_at,omitempty"`
	Revoked   bool       `json:"revoked"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type LoginAttemptsAudit struct {
	ID            int64      `json:"id,omitempty"`
	UserID        *int64     `json:"user_id,omitempty"`
	Email         string     `json:"email"`
	UserAgent     string     `json:"user_agent,omitempty"`
	Success       bool       `json:"success"`
	FailureReason *string    `json:"failure_reason,omitempty"`
	AttemptedAt   *time.Time `json:"attempted_at,omitempty"`
}

type UserSession struct {
	ID         []byte     `json:"id"`
	UserID     int64      `json:"user_id"`
	UserAgent  string     `json:"user_agent"`
	DeviceType string     `json:"device_type"`
	IsRevoked  bool       `json:"is_revoked"`
	LastActive *time.Time `json:"last_active,omitempty"`
	CreatedAt  *time.Time `json:"created_at,omitempty"`
}

type AccountEventAudit struct {
	UserID    int64  `json:"user_id"`
	EventType string `json:"event_type"`
	UserAgent string `json:"user_agent"`
}

type AccountView struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}
