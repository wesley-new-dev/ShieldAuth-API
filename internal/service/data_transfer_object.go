package service

import "ShieldAuth-API/internal/security"

type RegisterInput struct {
	Name     string
	Email    string
	Password *security.SensitiveData
}

type LoginInput struct {
	Name     string
	Email    string
	Password *security.SensitiveData
}

type ResetPasswordInput struct {
	Token           string
	NewPassword     *security.SensitiveData
	ConfirmPassword *security.SensitiveData
}

type ChangeNameInput struct {
	ID             int
	CurrentName    string
	NewName        string
	ConfirmNewName string
}

type ChangeEmailInput struct {
	ID              int
	CurrentEmail    string
	NewEmail        string
	ConfirmNewEmail string
	Password        *security.SensitiveData
}

type ChangePasswordInput struct {
	UserID          int
	CurrentPassword *security.SensitiveData
	NewPassword     *security.SensitiveData
	ConfirmPassword *security.SensitiveData
}

type DeleteAccountInput struct {
	UserID          int
	CurrentPassword *security.SensitiveData
}

type LogOutInput struct {
	RefreshToken  []byte
	AccessTokenID string
	UserID        int64
	SessionID     string
}

type RefreshSessionInput struct {
	OldRefreshToken string
}
