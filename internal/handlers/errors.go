package handlers

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/response"
)

func LogErrorAndMap(w http.ResponseWriter, r *http.Request, message string, err error) {
	slog.ErrorContext(r.Context(), message, "error", err.Error(), "path", r.URL.Path)
	MapServiceError(w, err)
}

func MapServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalidData),
		errors.Is(err, domain.ErrInvalidEmailFormat),
		errors.Is(err, domain.ErrWeakPassword),
		errors.Is(err, domain.ErrShortPassword),
		errors.Is(err, domain.ErrLongPassword),
		errors.Is(err, domain.ErrPasswordDoNotMatch):
		response.Error(w, http.StatusBadRequest, "Invalid input data", "INVALID_INPUT_DATA", err)

	case errors.Is(err, domain.ErrEmailsDoNotMatch):
		response.Error(w, http.StatusBadRequest, "The new email and its confirmation do not match", "EMAILS_DO_NOT_MATCH", err)

	case errors.Is(err, domain.ErrEmailMismatch):
		response.Error(w, http.StatusBadRequest, "The provided current email does not match our records", "EMAIL_MISMATCH", err)

	case errors.Is(err, domain.ErrInvalidCredentials),
		errors.Is(err, domain.ErrInvalidPassword):
		response.Error(w, http.StatusUnauthorized, "Invalid email or password", "INVALID_CREDENTIALS", err)

	case errors.Is(err, domain.ErrInvalidToken):
		response.Error(w, http.StatusUnauthorized, "The provided token is invalid or expired", "INVALID_TOKEN", err)

	case errors.Is(err, domain.ErrAccountLocked):
		response.Error(w, http.StatusForbidden, "Your account has been locked due to too many failed attempts", "ACCOUNT_LOCKED", err)

	case errors.Is(err, domain.ErrPasswordPwned):
		response.Error(w, http.StatusForbidden, "This password was found in a public data leak. Choose a safer one", "PASSWORD_PWNED", err)

	case errors.Is(err, domain.ErrUserNotFound),
		errors.Is(err, domain.ErrNotFound):
		response.Error(w, http.StatusNotFound, "Requested resource not found", "RESOURCE_NOT_FOUND", err)

	case errors.Is(err, domain.ErrCacheError):
		response.Error(w, http.StatusInternalServerError, "A data persistence error occurred", "CACHE_FAILURE", err)

	case errors.Is(err, domain.ErrEmailAlreadyExists):
		response.Error(w, http.StatusConflict, "This email is already in use", "EMAIL_ALREADY_EXISTS", err)

	case errors.Is(err, domain.ErrNameIsTheSame):
		response.Error(w, http.StatusConflict, "The new name is the same as the current one", "NAME_IS_THE_SAME", err)

	case errors.Is(err, domain.ErrEmailIsTheSame):
		response.Error(w, http.StatusConflict, "The new email is the same as the current one", "EMAIL_IS_THE_SAME", err)

	case errors.Is(err, domain.ErrRateLimitExceeded):
		response.Error(w, http.StatusTooManyRequests, "Too many requests. Please try again later", "TOO_MANY_REQUESTS", err)

	case errors.Is(err, domain.ErrContextTimeout),
		errors.Is(err, context.DeadlineExceeded):
		response.Error(w, http.StatusGatewayTimeout, "The request took too long to process", "REQUEST_TIMEOUT", err)

	default:
		response.Error(w, http.StatusInternalServerError, "An unexpected internal server error occurred", "INTERNAL_SERVER_ERROR", err)
	}
}
