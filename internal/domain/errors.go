package domain

import "errors"

var (
	ErrInvalidCredentials = errors.New("invalid email, name or password")
	ErrUserNotFound       = errors.New("user not found")
	ErrEmailAlreadyExists = errors.New("email already exists")
	ErrInvalidPassword    = errors.New("invalid password")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrAccountLocked      = errors.New("account is temporarily locked due to too many failed attempts")

	ErrWeakPassword       = errors.New("password does not meet security requirements")
	ErrPasswordDoNotMatch = errors.New("passwords do not match")
	ErrPasswordPwned      = errors.New("password found in data breach")
	ErrShortPassword      = errors.New("password is too short")
	ErrLongPassword       = errors.New("password is too long")

	ErrInvalidData        = errors.New("invalid input")
	ErrInvalidEmailFormat = errors.New("invalid email format")
	ErrNotFound           = errors.New("requested resource was not found")

	ErrNameIsTheSame    = errors.New("the new name is the same as the current one")
	ErrEmailIsTheSame   = errors.New("the new email is the same as the current one")
	ErrEmailMismatch    = errors.New("the provided current email does not match our records")
	ErrEmailsDoNotMatch = errors.New("the new email and its confirmation do not match")

	ErrInternal          = errors.New("an internal error occurred")
	ErrRateLimitExceeded = errors.New("too many requests, please try again later")
	ErrContextTimeout    = errors.New("the operation timed out")
)
