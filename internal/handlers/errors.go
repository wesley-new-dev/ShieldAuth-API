package handlers

import (
	"context"
	"errors"
	"net/http"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/response"
)

func MapServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalidData),
		errors.Is(err, domain.ErrInvalidEmailFormat),
		errors.Is(err, domain.ErrWeakPassword),
		errors.Is(err, domain.ErrShortPassword),
		errors.Is(err, domain.ErrLongPassword),
		errors.Is(err, domain.ErrPasswordDoNotMatch):
		response.Error(w, http.StatusBadRequest, "Invalid input data", err)

	case errors.Is(err, domain.ErrEmailsDoNotMatch):
		response.Error(w, http.StatusBadRequest, "The new email and its confirmation do not match", err)

	case errors.Is(err, domain.ErrEmailMismatch):
		response.Error(w, http.StatusBadRequest, "The provided current email does not match our records", err)

	case errors.Is(err, domain.ErrInvalidCredentials),
		errors.Is(err, domain.ErrInvalidPassword),
		errors.Is(err, domain.ErrInvalidToken):
		response.Error(w, http.StatusUnauthorized, "Authentication failed", err)

	case errors.Is(err, domain.ErrAccountLocked),
		errors.Is(err, domain.ErrPasswordPwned):
		response.Error(w, http.StatusForbidden, "Action forbidden due to security policies", err)

	case errors.Is(err, domain.ErrUserNotFound),
		errors.Is(err, domain.ErrNotFound):
		response.Error(w, http.StatusNotFound, "Requested resource not found", err)

	case errors.Is(err, domain.ErrEmailAlreadyExists):
		response.Error(w, http.StatusConflict, "This email is already in use", err)

	case errors.Is(err, domain.ErrNameIsTheSame):
		response.Error(w, http.StatusConflict, "The new name is the same as the current one", err)

	case errors.Is(err, domain.ErrEmailIsTheSame):
		response.Error(w, http.StatusConflict, "The new email is the same as the current one", err)

	case errors.Is(err, domain.ErrRateLimitExceeded):
		response.Error(w, http.StatusTooManyRequests, "Too many requests, slow down", err)

	case errors.Is(err, domain.ErrContextTimeout),
		errors.Is(err, context.DeadlineExceeded):
		response.Error(w, http.StatusGatewayTimeout, "The request took too long to process", err)

	default:
		response.Error(w, http.StatusInternalServerError, "An internal server error occurred", err)
	}
}
