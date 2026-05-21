package handlers

import (
	"log"
	"encoding/json"
	"net/http"

	"ShieldAuth-API/internal/middleware"
	"ShieldAuth-API/internal/response"
	"ShieldAuth-API/internal/service"
)


type ChangeNameHandler struct {
	Service *service.ChangeName
}
type ChangeEmailHandler struct {
	Service *service.ChangeEmail
}
type ResetPasswordHandler struct {
	Service *service.ResetPassword
}
type DeleteAccountHandler struct {
	Service *service.DeleteAccount
}


func NewChangeNameHandler(service *service.ChangeName) *ChangeNameHandler {
	return &ChangeNameHandler{
		Service: service,
	}
}
func NewChangeEmailHandler(service *service.ChangeEmail) *ChangeEmailHandler {
	return &ChangeEmailHandler{
		Service: service,
	}
}
func NewResetPasswordHandler(service *service.ResetPassword) *ResetPasswordHandler {
	return &ResetPasswordHandler{
		Service: service,
	}
}
func NewDeleteAccountHandler(service *service.DeleteAccount) *DeleteAccountHandler {
	return &DeleteAccountHandler{
		Service: service,
	}
}


type ChangeNameRequest struct {
	CurrentName string `json:"currentName"`
	NewName string `json:"newName"`
}
type ChangeEmailRequest struct {
	CurrentEmail string `json:"currentEmail"`
	NewEmail string `json:"newEmail"`
	ConfirmNewEmail string `json:"confirmNewEmail"`
	Password string `json:"password"`
}
type ResetPasswordRequest struct {
	Token string `json:"token"`
	NewPassword string `json:"newPassword"`
	ConfirmNewPassword string `json:"confirmPassword"`
}


func (changeName *ChangeNameHandler) ChangeNameHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req ChangeNameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid request", err)
		return
	}

	auth, ok := r.Context().Value(middleware.Key).(middleware.AuthContext)
	if !ok {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	userID := auth.UserID

	input := service.ChangeNameData{
		ID: userID,
		CurrentName: req.CurrentName,
		NewName: req.NewName,
	}

	if err := changeName.Service.ChangeNameFunction(r.Context(), input); err != nil {
		MapServiceError(w, err)
		return
	}

	response.Json(w, http.StatusOK, map[string]string{"message": "success"})
}


func (changeEmail *ChangeEmailHandler) ChangeEmailHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req ChangeEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid request", err)
		return
	}

	auth, ok := r.Context().Value(middleware.Key).(middleware.AuthContext)
	if !ok {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	userID := auth.UserID

	input := service.ChangeEmailData{
		ID: userID,
		CurrentEmail: req.CurrentEmail,
		NewEmail: req.NewEmail,
		ConfirmNewEmail: req.ConfirmNewEmail,
		Password: req.Password,
	}

	if err := changeEmail.Service.ChangeEmailFunctionTest(r.Context(), input); err != nil {
		MapServiceError(w, err)
		return
	}

	response.Json(w, http.StatusOK, map[string]string{"message": "success"})
}


func (reset *ResetPasswordHandler) ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid Request", err)
		return
	}

	input := service.ResetPasswordData{
		NewPasword: req.NewPassword,
		ConfirmPassword: req.ConfirmNewPassword,
	}

	token := req.Token

	if err := reset.Service.ResetPasswordFunction(r.Context(), token, input); err != nil {
		MapServiceError(w, err)
		return
	}

	response.Json(w, http.StatusOK, map[string]string{"message": "success"})
}


func (deleteAccountHandler *DeleteAccountHandler) DeleteAccountHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	log.SetFlags(log.Lshortfile)

	if r.Method == http.MethodPost {

		email := r.FormValue("emailConfirm")
		password := r.FormValue("passwordConfirm")

		ctx := r.Context()

		err := deleteAccountHandler.Service.DeleteAccountFunction(ctx, email, password)
		if err == nil {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("VALID"))
			log.Println("SUCCESS")

		} else {
			log.Println("ERROR")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

	} else {
		log.Println("ERROR")
		http.Error(w, "ERROR", http.StatusMethodNotAllowed)
	}
}
