package handlers

import (
	"encoding/json"
	"net/http"

	"ShieldAuth-API/internal/middleware"
	"ShieldAuth-API/internal/response"
	"ShieldAuth-API/internal/security"
	"ShieldAuth-API/internal/service"
	"ShieldAuth-API/internal/service/user"
)

type ChangeNameHandler struct {
	Service *user.ChangeNameService
}
type ChangeEmailHandler struct {
	Service *user.ChangeEmailService
}
type ResetPasswordHandler struct {
	Service *user.ResetPasswordService
}
type DeleteAccountHandler struct {
	Service *user.DeleteAccountService
}
type ChangePasswordHandler struct {
	Service *user.ChangePasswordService
}

func NewChangeNameHandler(service *user.ChangeNameService) *ChangeNameHandler {
	return &ChangeNameHandler{
		Service: service,
	}
}
func NewChangeEmailHandler(service *user.ChangeEmailService) *ChangeEmailHandler {
	return &ChangeEmailHandler{
		Service: service,
	}
}
func NewResetPasswordHandler(service *user.ResetPasswordService) *ResetPasswordHandler {
	return &ResetPasswordHandler{
		Service: service,
	}
}
func NewDeleteAccountHandler(service *user.DeleteAccountService) *DeleteAccountHandler {
	return &DeleteAccountHandler{
		Service: service,
	}
}
func NewChangePasswordHandler(service *user.ChangePasswordService) *ChangePasswordHandler {
	return &ChangePasswordHandler{
		Service: service,
	}
}

type ChangeNameRequest struct {
	CurrentName string `json:"currentName"`
	NewName     string `json:"newName"`
}
type ChangeEmailRequest struct {
	CurrentEmail    string               `json:"currentEmail"`
	NewEmail        string               `json:"newEmail"`
	ConfirmNewEmail string               `json:"confirmNewEmail"`
	Password        security.SecretBytes `json:"password"`
}
type ResetPasswordRequest struct {
	Token              string               `json:"token"`
	NewPassword        security.SecretBytes `json:"newPassword"`
	ConfirmNewPassword security.SecretBytes `json:"confirmPassword"`
}
type DeleteAccountRequest struct {
	Password security.SecretBytes `json:"password"`
}
type ChangePasswordRequest struct {
	CurrentPassword    security.SecretBytes `json:"currentPassword"`
	NewPassword        security.SecretBytes `json:"newPassword"`
	ConfirmNewPassword security.SecretBytes `json:"confirmNewPassword"`
}

func (changeName *ChangeNameHandler) ChangeNameHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req ChangeNameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid request", "INVALID_REQUEST", err)
		return
	}

	auth, ok := r.Context().Value(middleware.Key).(middleware.AuthContext)
	if !ok {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	userID := auth.UserID

	input := service.ChangeNameInput{
		ID:          userID,
		CurrentName: req.CurrentName,
		NewName:     req.NewName,
	}

	if err := changeName.Service.ChangeNameFunction(r.Context(), input); err != nil {
		LogErrorAndMap(w, err)
		return
	}

	response.Json(w, http.StatusOK, map[string]string{"message": "success"})
}

func (changeEmail *ChangeEmailHandler) ChangeEmailHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req ChangeEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid request", "INVALID_REQUEST", err)
		return
	}

	auth, ok := r.Context().Value(middleware.Key).(middleware.AuthContext)
	if !ok {
		response.Error(w, http.StatusInternalServerError, "Internal server error", "INTERNAL_SERVER_ERROR", nil)
		return
	}

	userID := auth.UserID

	password, err := security.NewSensitiveData([]byte(req.Password))
	if err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid password payload", "INVALID_REQUEST", err)
		return
	}

	input := service.ChangeEmailInput{
		ID:              userID,
		CurrentEmail:    req.CurrentEmail,
		NewEmail:        req.NewEmail,
		ConfirmNewEmail: req.ConfirmNewEmail,
		Password:        password,
	}

	userAgent := r.Header.Get("User-Agent")

	if err := changeEmail.Service.ChangeEmailFunction(r.Context(), input, userAgent); err != nil {
		LogErrorAndMap(w, err)
		return
	}

	response.Json(w, http.StatusOK, map[string]string{"message": "success"})
}

func (reset *ResetPasswordHandler) ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid Request", "INVALID_REQUEST", err)
		return
	}

	newPassword, err := security.NewSensitiveData([]byte(req.NewPassword))
	if err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid new password payload", "INVALID_REQUEST", err)
		return
	}

	confirmPassword, err := security.NewSensitiveData([]byte(req.ConfirmNewPassword))
	if err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid confirm password payload", "INVALID_REQUEST", err)
		return
	}

	input := service.ResetPasswordInput{
		NewPassword:     newPassword,
		ConfirmPassword: confirmPassword,
	}

	token := req.Token

	userAgent := r.Header.Get("User-Agent")

	if err := reset.Service.ResetPasswordFunction(r.Context(), token, input, userAgent); err != nil {
		LogErrorAndMap(w, err)
		return
	}

	response.Json(w, http.StatusOK, map[string]string{"message": "success"})
}

func (deleteAccountHandler *DeleteAccountHandler) DeleteAccountHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req DeleteAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid request", "INVALID_REQUEST", err)
		return
	}

	auth, ok := r.Context().Value(middleware.Key).(middleware.AuthContext)
	if !ok {
		response.Error(w, http.StatusInternalServerError, "Internal server error", "INTERNAL_SERVER_ERROR", nil)
		return
	}

	userID := auth.UserID

	password, err := security.NewSensitiveData([]byte(req.Password))
	if err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid password payload", "INVALID_REQUEST", err)
		return
	}

	input := service.DeleteAccountInput{
		ID:       userID,
		Password: password,
	}

	if err := deleteAccountHandler.Service.DeleteAccountFunction(r.Context(), input); err != nil {
		LogErrorAndMap(w, err)
		return
	}

	response.Json(w, http.StatusOK, map[string]string{"message": "success"})
}

func (changePasswordHandler *ChangePasswordHandler) ChangePasswordHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid request", "INVALID_REQUEST", err)
		return
	}

	auth, ok := r.Context().Value(middleware.Key).(middleware.AuthContext)
	if !ok {
		response.Error(w, http.StatusInternalServerError, "Internal server error", "INTERNAL_SERVER_ERROR", nil)
		return
	}

	userID := auth.UserID

	currentPassword, err := security.NewSensitiveData([]byte(req.CurrentPassword))
	if err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid current password payload", "INVALID_REQUEST", err)
		return
	}

	newPassword, err := security.NewSensitiveData([]byte(req.NewPassword))
	if err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid new password payload", "INVALID_REQUEST", err)
		return
	}

	confirmPassword, err := security.NewSensitiveData([]byte(req.ConfirmNewPassword))
	if err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid confirm password payload", "INVALID_REQUEST", err)
		return
	}

	input := service.ChangePasswordInput{
		UserID:          userID,
		CurrentPassword: currentPassword,
		NewPassword:     newPassword,
		ConfirmPassword: confirmPassword,
	}

	if err := changePasswordHandler.Service.ChangePassword(r.Context(), input); err != nil {
		LogErrorAndMap(w, err)
		return
	}

	response.Json(w, http.StatusOK, map[string]string{"message": "success"})
}
