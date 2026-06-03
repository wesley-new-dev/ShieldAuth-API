package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"text/template"
	"time"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/response"
	"ShieldAuth-API/internal/security"
	"ShieldAuth-API/internal/service"
	"ShieldAuth-API/internal/ui"
)


type LoginServiceInterface interface {
	VerifyLoginFunction(ctx context.Context, input service.LoginInput) (int, error)
}
type RateLimiter interface {
	CheckLimit(ctx context.Context, key string, maxAttemtps int, window time.Duration) (bool, error)
	ResetLimit(ctx context.Context, key string) error
}


type RegisterHandler struct {
	Service *service.RegisterService
}
type LoginHandler struct {
	Service LoginServiceInterface
	Limiter RateLimiter
}
type RequestHandler struct {
	Service *service.RequestResetService
	Limiter RateLimiter
}
type ValidTokenHandler struct {
	Service *service.ValidTokenService
}


func NewRegisterHanlder(service *service.RegisterService) *RegisterHandler {
	return &RegisterHandler{
		Service: service,
	}
}
func NewLoginHandler(service LoginServiceInterface, limiter RateLimiter) *LoginHandler {
	return &LoginHandler{
		Service: service,
		Limiter: limiter,
	}
}
func NewRequestHandler(s *service.RequestResetService) *RequestHandler {
	return &RequestHandler{
		Service: s,
	}
}
func NewValidTokenHandler(s *service.ValidTokenService) *ValidTokenHandler {
	return &ValidTokenHandler{
		Service: s,
	}
}


type RegisterRequest struct {
	Name 		string `json:"name"`
	Email 		string `json:"email"`
	Password 	security.SecretBytes `json:"password"`
}
type LoginRequest struct {
	NameOrEmail 	string `json:"nameOrEmail"`
	Password 		security.SecretBytes `json:"password"`
}


var tmpl = template.Must(template.ParseFS(ui.Files, "templates/reset.html"))


func (handler *RegisterHandler) RegisterHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1024*4)
	defer r.Body.Close()

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid credentials", err)
		return
	}

	input := service.RegisterInput{
		Name: req.Name,
		Email: req.Email,
		Password: req.Password,
	}

	defer security.ZeroMemory(input.Password)

	err := handler.Service.RegisterFunction(r.Context(), input)
	if err != nil {
		MapServiceError(w, err)
		return
	}

	response.Json(w, http.StatusCreated, map[string]string{"message": "success"})
}


func (h *LoginHandler) HandlerLogin(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1024*4)
	defer r.Body.Close()

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "Malformed JSON request body", err)
		return
	}

	key := "login-attempt:" + req.NameOrEmail
	allowed, err := h.Limiter.CheckLimit(r.Context(), key, 3, 10*time.Minute)
	if err != nil {
		response.Error(w, http.StatusInternalServerError, "Internal server error", err)
		return
	}

	if !allowed {
		response.Error(w, http.StatusTooManyRequests, "Too many attempts. Please again later", err)
		return
	}

	input := service.LoginInput{
		Name: req.NameOrEmail,
		Email: req.NameOrEmail,
		Password: req.Password,
	}

	defer security.ZeroMemory(input.Password)

	id, err := h.Service.VerifyLoginFunction(r.Context(), input)
	if err != nil {
		MapServiceError(w, err)
		return
	}

	tokenJwtString, err := security.TokenJWT(id)
	if err != nil {
		response.Error(w, http.StatusInternalServerError, "Failed to generate authentication session", err)
		return
	}

	_ = h.Limiter.ResetLimit(r.Context(), key)

	response.Json(w, http.StatusOK, map[string]string{"token": tokenJwtString})
}


func (h *RequestHandler) RequestReset(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "invalid request", err)
		return
	}

	key := "request-reset-password-attempt:" + req.Email
	allowed, err := h.Limiter.CheckLimit(r.Context(), key, 5, 12*time.Hour)
	if err != nil {
		response.Error(w, http.StatusInternalServerError, "Internal server error", err)
		return
	}

	if !allowed {
		http.Error(w, "Too many attempts. Please again later", http.StatusTooManyRequests)
		return
	}

	token, err := h.Service.RequestReset(r.Context(), req.Email)
	if err != nil {
		MapServiceError(w, err)
		return
	}

	_ = h.Limiter.ResetLimit(r.Context(), key)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"redirect": "http://127.0.0.1:8000/valid?token=" + url.QueryEscape(token),
	})
}


func (h *ValidTokenHandler) ValidToken(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		MapServiceError(w, domain.ErrInvalidToken)
		return
	}

	err := h.Service.ValidToken(r.Context(), token)
	if err != nil {
		MapServiceError(w, err)
		return
	}

	data := struct {
		Token string
	}{
		Token: token,
	}

	tmpl.Execute(w, data)
}