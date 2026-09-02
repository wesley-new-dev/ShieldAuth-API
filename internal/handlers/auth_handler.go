package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"ShieldAuth-API/internal/request"
	"ShieldAuth-API/internal/response"
	"ShieldAuth-API/internal/security"
	"ShieldAuth-API/internal/service"
	"ShieldAuth-API/internal/service/auth"
	"ShieldAuth-API/internal/service/user"

	"github.com/google/uuid"
)

type RegisterServiceInterface interface {
	RegisterFunction(ctx context.Context, input service.RegisterInput) (int64, int, uuid.UUID, error)
	CreateRefreshToken(ctx context.Context, userID int64, duration time.Duration) (string, error)
}
type LoginServiceInterface interface {
	VerifyLoginFunction(ctx context.Context, input service.LoginInput, userAgent string) (int64, int, uuid.UUID, error)
	CreateRefreshToken(ctx context.Context, userID int64, duration time.Duration) (string, error)
}
type RateLimiter interface {
	CheckLimit(ctx context.Context, key string, maxAttemtps int, window time.Duration) (bool, error)
	ResetLimit(ctx context.Context, key string) error
}

type RegisterHandler struct {
	Service RegisterServiceInterface
}
type LoginHandler struct {
	Service LoginServiceInterface
	Limiter RateLimiter
}
type RequestHandler struct {
	Service *user.RequestResetService
	Limiter RateLimiter
}
type ValidTokenHandler struct {
	Service *auth.ValidTokenService
}
type LogOutHandler struct {
	Service *auth.LogOutService
}

func NewRegisterHanlder(service RegisterServiceInterface) *RegisterHandler {
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
func NewRequestHandler(s *user.RequestResetService, limiter RateLimiter) *RequestHandler {
	return &RequestHandler{
		Service: s,
		Limiter: limiter,
	}
}
func NewValidTokenHandler(s *auth.ValidTokenService) *ValidTokenHandler {
	return &ValidTokenHandler{
		Service: s,
	}
}
func NewLogOutHandler(s *auth.LogOutService) *LogOutHandler {
	return &LogOutHandler{
		Service: s,
	}
}

type RegisterRequest struct {
	Name     string               `json:"name"`
	Email    string               `json:"email"`
	Password security.SecretBytes `json:"password"`
}
type LoginRequest struct {
	NameOrEmail string               `json:"nameOrEmail"`
	Password    security.SecretBytes `json:"password"`
}

func (handler *RegisterHandler) RegisterHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		response.Error(w, http.StatusMethodNotAllowed, "Method not allowed", "METHOD_NOT_ALLOWED", nil)
		return
	}

	var req RegisterRequest
	if err := request.DecodeJSONBody(w, r, &req); err != nil {
		response.Error(w, http.StatusBadRequest, "Malformed JSON request body", "INVALID_REQUEST", err)
		return
	}

	password, err := security.NewSensitiveData([]byte(req.Password))
	if err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid password payload", "INVALID_REQUEST", err)
		return
	}

	input := service.RegisterInput{
		Name:     req.Name,
		Email:    req.Email,
		Password: password,
	}

	id, jwt_version, sessionID, err := handler.Service.RegisterFunction(r.Context(), input)
	if err != nil {
		LogErrorAndMap(w, err)
		return
	}

	tokenJwtString, err := security.TokenJWT(id, jwt_version, sessionID.String()) // exists an error here, if here fails the user is created but the token is not generated, I need to handle this case and delete the user if the token generation fails
	if err != nil {
		response.Error(w, http.StatusInternalServerError, "Failed to generate authentication session", "INTERNAL_SERVER_ERROR", err)
		return
	}

	validDays := 7
	cookieDuration := time.Duration(validDays) * 24 * time.Hour
	refreshTokenString, err := handler.Service.CreateRefreshToken(r.Context(), id, cookieDuration) // probably the same here
	if err != nil {
		response.Error(w, http.StatusInternalServerError, "Failed to generate refresh session", "INTERNAL_SERVER_ERROR", err)
		return
	}

	cookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshTokenString,
		Expires:  time.Now().Add(cookieDuration),
		MaxAge:   validDays * 24 * 60 * 60,
		HttpOnly: true,
		Secure:   false, // Set to true in production
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	}

	http.SetCookie(w, cookie)

	response.Json(w, http.StatusCreated, map[string]string{"token": tokenJwtString})
}

func (h *LoginHandler) HandlerLogin(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		response.Error(w, http.StatusMethodNotAllowed, "Method not allowed", "METHOD_NOT_ALLOWED", nil)
		return
	}

	var req LoginRequest
	if err := request.DecodeJSONBody(w, r, &req); err != nil {
		response.Error(w, http.StatusBadRequest, "Malformed JSON request body", "INVALID_REQUEST", err)
		return
	}

	key := "login-attempt:" + req.NameOrEmail
	allowed, err := h.Limiter.CheckLimit(r.Context(), key, 3, 10*time.Minute)
	if err != nil {
		response.Error(w, http.StatusInternalServerError, "Internal server error", "INTERNAL_SERVER_ERROR", err)
		return
	}

	if !allowed {
		w.Header().Set("Retry-After", "600")
		response.Error(w, http.StatusTooManyRequests, "Too many attempts. Please try again later.", "RATE_LIMIT_EXCEEDED", err)
		return
	}

	password, err := security.NewSensitiveData([]byte(req.Password))
	if err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid password payload", "INVALID_REQUEST", err)
		return
	}

	input := service.LoginInput{
		Name:     req.NameOrEmail,
		Email:    req.NameOrEmail,
		Password: password,
	}

	userAgent := r.Header.Get("User-Agent")
	id, jwtVersion, sessionID, err := h.Service.VerifyLoginFunction(r.Context(), input, userAgent)
	if err != nil {
		LogErrorAndMap(w, err)
		return
	}

	tokenJwtString, err := security.TokenJWT(id, jwtVersion, sessionID.String())
	if err != nil {
		response.Error(w, http.StatusInternalServerError, "Failed to generate authentication session", "INTERNAL_SERVER_ERROR", err)
		return
	}

	validDays := 7
	cookieDuration := time.Duration(validDays) * 24 * time.Hour
	refreshTokenString, err := h.Service.CreateRefreshToken(r.Context(), id, cookieDuration)
	if err != nil {
		response.Error(w, http.StatusInternalServerError, "Failed to generate refresh session", "INTERNAL_SERVER_ERROR", err)
		return
	}

	cookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshTokenString,
		Expires:  time.Now().Add(cookieDuration),
		MaxAge:   validDays * 24 * 60 * 60,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	}

	http.SetCookie(w, cookie)

	_ = h.Limiter.ResetLimit(r.Context(), key)

	response.Json(w, http.StatusOK, map[string]string{"token": tokenJwtString})
}

func (h *RequestHandler) RequestReset(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		response.Error(w, http.StatusMethodNotAllowed, "Method not allowed", "METHOD_NOT_ALLOWED", nil)
		return
	}

	var req struct {
		Email string `json:"email"`
	}

	if err := request.DecodeJSONBody(w, r, &req); err != nil {
		response.Error(w, http.StatusBadRequest, "Malformed JSON request body", "INVALID_REQUEST", err)
		return
	}

	key := "request-reset-password-attempt:" + req.Email
	allowed, err := h.Limiter.CheckLimit(r.Context(), key, 5, 12*time.Hour)
	if err != nil {
		response.Error(w, http.StatusInternalServerError, "Internal server error", "INTERNAL_SERVER_ERROR", err)
		return
	}

	if !allowed {
		w.Header().Set("Retry-After", "43200") // 12 hours in seconds
		response.Error(w, http.StatusTooManyRequests, "Too many attempts. Please try again later", "RATE_LIMIT_EXCEEDED", nil)
		return
	}

	userAgent := r.Header.Get("User-Agent")

	token, code, err := h.Service.RequestReset(r.Context(), req.Email, userAgent)
	if err != nil {
		LogErrorAndMap(w, err)
		return
	}

	_ = h.Limiter.ResetLimit(r.Context(), key)

	w.Header().Set("Content-Type", "application/json")
	response.Json(w, http.StatusOK, map[string]string{"code": code, "token": token})
}

func (h *ValidTokenHandler) ValidToken(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		response.Error(w, http.StatusMethodNotAllowed, "Method not allowed", "METHOD_NOT_ALLOWED", nil)
		return
	}

	var req struct {
		Code string `json:"code"`
	}

	if err := request.DecodeJSONBody(w, r, &req); err != nil {
		response.Error(w, http.StatusBadRequest, "Malformed JSON request body", "INVALID_REQUEST", err)
		return
	}

	token, err := h.Service.ValidToken(r.Context(), req.Code)
	if err != nil {
		LogErrorAndMap(w, err)
		return
	}

	response.Json(w, http.StatusOK, map[string]string{
		"redirect": "http://127.0.0.1:8000/reset/password?token=" + url.QueryEscape(token),
	})
}

func (l *LogOutHandler) LogOutHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		response.Error(w, http.StatusMethodNotAllowed, "Method not allowed", "METHOD_NOT_ALLOWED", nil)
		return
	}

	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			response.Error(w, http.StatusUnauthorized, "cookie was not found", "UNAUTHORIZED_ACCESS", err)
			return
		}
		response.Error(w, http.StatusUnauthorized, "Unauthorized", "UNAUTHORIZED_ACCESS", err)
		return
	}

	err = l.Service.LogOutFunction(r.Context(), service.LogOutInput{RefreshToken: []byte(cookie.Value)})
	if err != nil {
		LogErrorAndMap(w, err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   false,
		Path:     "/",
	})

	response.Json(w, http.StatusNoContent, map[string]string{"message": "success"})
}
