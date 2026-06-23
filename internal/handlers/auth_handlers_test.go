package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/service"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockRateLimiter struct{ mock.Mock }

func (m *MockRateLimiter) CheckLimit(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	args := m.Called(ctx, key, limit, window)
	return args.Bool(0), args.Error(1)
}
func (m *MockRateLimiter) ResetLimit(ctx context.Context, key string) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

type MockRegisterService struct{ mock.Mock }

func (m *MockRegisterService) RegisterFunction(ctx context.Context, input service.RegisterInput) (int64, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(int64), args.Error(1)
}
func (m *MockRegisterService) CreateRefreshToken(ctx context.Context, id int64, ttl time.Duration) (string, error) {
	args := m.Called(ctx, id, ttl)
	return args.String(0), args.Error(1)
}

type MockLoginService struct{ mock.Mock }

func (m *MockLoginService) VerifyLoginFunction(ctx context.Context, input service.LoginInput) (int64, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(int64), args.Error(1)
}
func (m *MockLoginService) CreateRefreshToken(ctx context.Context, id int64, ttl time.Duration) (string, error) {
	args := m.Called(ctx, id, ttl)
	return args.String(0), args.Error(1)
}

type MockRequestService struct{ mock.Mock }

func (m *MockRequestService) RequestReset(ctx context.Context, email string) (string, error) {
	args := m.Called(ctx, email)
	return args.String(0), args.Error(1)
}

type MockValidTokenService struct{ mock.Mock }

func (m *MockValidTokenService) ValidToken(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

type FakeTemplate struct{}

func (t *FakeTemplate) Execute(w http.ResponseWriter, data interface{}) error {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("template rendered successfully"))
	return nil
}

type MockLogOutService struct{ mock.Mock }

func (m *MockLogOutService) LogOutFunction(ctx context.Context, input service.LogOutInput) error {
	args := m.Called(ctx, input)
	return args.Error(0)
}

func TestRegisterHandler(t *testing.T) {
	errRedis := errors.New("redis error")

	tests := []struct {
		name           string
		method         string
		requestBody    interface{}
		setupMocks     func(m *MockRegisterService)
		expectedStatus int
	}{
		{

			name:   "success: account created and cookies set",
			method: http.MethodPost,
			requestBody: RegisterRequest{
				Name:     "test",
				Email:    "test@example.com",
				Password: []byte("test_password"),
			},
			setupMocks: func(m *MockRegisterService) {
				m.On("RegisterFunction", mock.Anything, mock.Anything).Return(int64(123), nil)
				m.On("CreateRefreshToken", mock.Anything, int64(123), time.Duration(7)*24*time.Hour).Return("fake_refresh_token_string", nil)
			},
			expectedStatus: http.StatusCreated,
		},
		{

			name:           "Error: method not allowed",
			method:         http.MethodGet,
			requestBody:    nil,
			setupMocks:     func(m *MockRegisterService) {},
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{

			name:           "Error: malformed JSON",
			method:         http.MethodPost,
			requestBody:    "{invalid-json",
			setupMocks:     func(m *MockRegisterService) {},
			expectedStatus: http.StatusBadRequest,
		},
		{

			name:   "Error: service register failure",
			method: http.MethodPost,
			requestBody: RegisterRequest{
				Name:     "test",
				Email:    "test@example.com",
				Password: []byte("test_password"),
			},
			setupMocks: func(m *MockRegisterService) {
				m.On("RegisterFunction", mock.Anything, mock.Anything).Return(int64(0), domain.ErrInternal)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{

			name:   "Error: refresh token generation failure",
			method: http.MethodPost,
			requestBody: RegisterRequest{
				Name:     "test",
				Email:    "test@example.com",
				Password: []byte("test_password"),
			},
			setupMocks: func(m *MockRegisterService) {
				m.On("RegisterFunction", mock.Anything, mock.Anything).Return(int64(123), nil)
				m.On("CreateRefreshToken", mock.Anything, int64(123), time.Duration(7)*24*time.Hour).Return("", errRedis)
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			mockService := new(MockRegisterService)
			tt.setupMocks(mockService)

			regHandler := &RegisterHandler{
				Service: mockService,
			}

			var bodyReader *bytes.Buffer
			if tt.requestBody != nil {
				if str, ok := tt.requestBody.(string); ok {
					bodyReader = bytes.NewBufferString(str)
				} else {
					jsonBytes, _ := json.Marshal(tt.requestBody)
					bodyReader = bytes.NewBuffer(jsonBytes)
				}
			} else {
				bodyReader = bytes.NewBuffer(nil)
			}

			req := httptest.NewRequest(tt.method, "/v1/register", bodyReader)
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()
			regHandler.RegisterHandler(rec, req)
			assert.Equal(t, tt.expectedStatus, rec.Code)

			if tt.expectedStatus == http.StatusCreated {

				cookies := rec.Result().Cookies()
				assert.Len(t, cookies, 1)
				assert.Equal(t, "refresh_token", cookies[0].Name)
				assert.Equal(t, "fake_refresh_token_string", cookies[0].Value)

				var responseBody map[string]string
				err := json.Unmarshal(rec.Body.Bytes(), &responseBody)
				assert.NoError(t, err)
				assert.Contains(t, responseBody, "token")
			}
			mockService.AssertExpectations(t)

		})
	}

}

func TestHandlerLogin(t *testing.T) {
	targetKey := "login-attempt:test_user@example.com"

	tests := []struct {
		name           string
		method         string
		requestBody    interface{}
		setupMocks     func(mService *MockLoginService, mLimiter *MockRateLimiter)
		expectedStatus int
	}{
		{

			name:   "success: authenticated and limit reset",
			method: http.MethodPost,
			requestBody: LoginRequest{
				NameOrEmail: "test_user@example.com",
				Password:    []byte("test_password"),
			},
			setupMocks: func(mService *MockLoginService, mLimiter *MockRateLimiter) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 3, 10*time.Minute).Return(true, nil)
				mService.On("VerifyLoginFunction", mock.Anything, mock.Anything).Return(int64(123), nil)
				mService.On("CreateRefreshToken", mock.Anything, int64(123), 7*24*time.Hour).Return("valid_refresh_token_string", nil)
				mLimiter.On("ResetLimit", mock.Anything, targetKey).Return(nil)
			},
			expectedStatus: http.StatusOK,

		},
		{

			name:   "Error: create refresh token failure",
			method: http.MethodPost,
			requestBody: LoginRequest{
				NameOrEmail: "test_user@example.com",
				Password:    []byte("test_password"),
			},
			setupMocks: func(mService *MockLoginService, mLimiter *MockRateLimiter) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 3, 10*time.Minute).Return(true, nil)
				mService.On("VerifyLoginFunction", mock.Anything, mock.Anything).Return(int64(123), nil)
				mService.On("CreateRefreshToken", mock.Anything, int64(123), 7*24*time.Hour).Return("", domain.ErrInternal)
			},
			expectedStatus: http.StatusInternalServerError,

		},
		{

			name:   "Error: verify login service failure",
			method: http.MethodPost,
			requestBody: LoginRequest{
				NameOrEmail: "test_user@example.com",
				Password:    []byte("test_password"),
			},
			setupMocks: func(mService *MockLoginService, mLimiter *MockRateLimiter) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 3, 10*time.Minute).Return(true, nil)
				mService.On("VerifyLoginFunction", mock.Anything, mock.Anything).Return(int64(0), domain.ErrInvalidCredentials)
			},
			expectedStatus: http.StatusUnauthorized,

		},
		{

			name:   "Error: too many requests (rate limited)",
			method: http.MethodPost,
			requestBody: LoginRequest{
				NameOrEmail: "test_user@example.com",
				Password:    []byte("test_password"),
			},
			setupMocks: func(mService *MockLoginService, mLimiter *MockRateLimiter) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 3, 10*time.Minute).Return(false, nil)
			},
			expectedStatus: http.StatusTooManyRequests,

		},
		{

			name:   "Error: Rate limiter internal failure",
			method: http.MethodPost,
			requestBody: LoginRequest{
				NameOrEmail: "test_user@example.com",
				Password:    []byte("password123"),
			},
			setupMocks: func(mService *MockLoginService, mLimiter *MockRateLimiter) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 3, 10*time.Minute).Return(false, domain.ErrInternal)
			},
			expectedStatus: http.StatusInternalServerError,

		},
		{

			name:           "Error: Method not allowed",
			method:         http.MethodGet,
			requestBody:    nil,
			setupMocks:     func(mService *MockLoginService, mLimiter *MockRateLimiter) {},
			expectedStatus: http.StatusMethodNotAllowed,

		},
		{

			name:           "Error: Malformed JSON",
			method:         http.MethodPost,
			requestBody:    "{bad-json",
			setupMocks:     func(mService *MockLoginService, mLimiter *MockRateLimiter) {},
			expectedStatus: http.StatusBadRequest,

		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockLoginService)
			mockLimiter := new(MockRateLimiter)
			tt.setupMocks(mockService, mockLimiter)

			loginHandler := &LoginHandler{
				Service: mockService,
				Limiter: mockLimiter,
			}

			var bodyReader *bytes.Buffer
			if tt.requestBody != nil {
				if str, ok := tt.requestBody.(string); ok {
					bodyReader = bytes.NewBufferString(str)
				} else {
					jsonBytes, _ := json.Marshal(tt.requestBody)
					bodyReader = bytes.NewBuffer(jsonBytes)
				}
			} else {
				bodyReader = bytes.NewBuffer(nil)
			}

			req := httptest.NewRequest(tt.method, "/v1/login", bodyReader)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			loginHandler.HandlerLogin(rec, req)
			assert.Equal(t, tt.expectedStatus, rec.Code)

			if tt.expectedStatus == http.StatusOK {
				cookies := rec.Result().Cookies()
				assert.Len(t, cookies, 1)
				assert.Equal(t, "refresh_token", cookies[0].Name)
				assert.Equal(t, "valid_refresh_token_string", cookies[0].Value)

				var responseBody map[string]string
				err := json.Unmarshal(rec.Body.Bytes(), &responseBody)
				assert.NoError(t, err)
				assert.Contains(t, responseBody, "token")
			}

			mockService.AssertExpectations(t)
			mockLimiter.AssertExpectations(t)
		})
	}

}

func TestRequestResetHandler(t *testing.T) {
	targetEmail := "test@example.com"
	targetKey := "request-reset-password-attempt:" + targetEmail

	tests := []struct {
		name           string
		method         string
		requestBody    interface{}
		setupMocks     func(mService *MockRequestService, mLimiter *MockRateLimiter)
		expectedStatus int
	}{
		{

			name:        "success: token generated and response contains redirect URL",
			method:      http.MethodPost,
			requestBody: map[string]string{"email": targetEmail},
			setupMocks: func(mService *MockRequestService, mL *MockRateLimiter) {
				mL.On("CheckLimit", mock.Anything, targetKey, 5, 12*time.Hour).Return(true, nil)
				mService.On("RequestReset", mock.Anything, targetEmail).Return("super-secret-token-123", nil)
				mL.On("ResetLimit", mock.Anything, targetKey).Return(nil)
			},
			expectedStatus: http.StatusOK,

		},
		{

			name:        "Error: Service request reset failure",
			method:      http.MethodPost,
			requestBody: map[string]string{"email": targetEmail},
			setupMocks: func(mService *MockRequestService, mLimiter *MockRateLimiter) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 5, 12*time.Hour).Return(true, nil)
				mService.On("RequestReset", mock.Anything, targetEmail).Return("", domain.ErrUserNotFound)
			},
			expectedStatus: http.StatusNotFound,

		},
		{

			name:        "Error: Rate limit exceeded",
			method:      http.MethodPost,
			requestBody: map[string]string{"email": targetEmail},
			setupMocks: func(mService *MockRequestService, mLimiter *MockRateLimiter) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 5, 12*time.Hour).Return(false, nil)
			},
			expectedStatus: http.StatusTooManyRequests,

		},
		{

			name:        "Error: Rate limiter failed internally",
			method:      http.MethodPost,
			requestBody: map[string]string{"email": targetEmail},
			setupMocks: func(mService *MockRequestService, mLimiter *MockRateLimiter) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 5, 12*time.Hour).Return(false, domain.ErrInternal)
			},
			expectedStatus: http.StatusInternalServerError,

		},
		{

			name:           "Error: Method not allowed",
			method:         http.MethodGet,
			requestBody:    nil,
			setupMocks:     func(mService *MockRequestService, mLimiter *MockRateLimiter) {},
			expectedStatus: http.StatusMethodNotAllowed,

		},
		{

			name:           "Error: Malformed JSON body",
			method:         http.MethodPost,
			requestBody:    "{invalid-json",
			setupMocks:     func(mService *MockRequestService, mLimiter *MockRateLimiter) {},
			expectedStatus: http.StatusBadRequest,

		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockRequestService)
			mockLimiter := new(MockRateLimiter)
			tt.setupMocks(mockService, mockLimiter)

			reqHandler := &RequestHandler{
				Service: mockService,
				Limiter: mockLimiter,
			}

			var bodyReader *bytes.Buffer
			if tt.requestBody != nil {
				if str, ok := tt.requestBody.(string); ok {
					bodyReader = bytes.NewBufferString(str)
				} else {
					jsonBytes, _ := json.Marshal(tt.requestBody)
					bodyReader = bytes.NewBuffer(jsonBytes)
				}
			} else {
				bodyReader = bytes.NewBuffer(nil)
			}

			req := httptest.NewRequest(tt.method, "/v1/request-reset", bodyReader)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			reqHandler.RequestReset(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)

			if tt.expectedStatus == http.StatusOK {
				assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

				var responseBody map[string]string
				err := json.Unmarshal(rec.Body.Bytes(), &responseBody)
				assert.NoError(t, err)

				assert.Contains(t, responseBody, "redirect")
				assert.Equal(t, "http://127.0.0.1:8000/valid?token=super-secret-token-123", responseBody["redirect"])
			}

			mockService.AssertExpectations(t)
			mockLimiter.AssertExpectations(t)
		})
	}

}

func TestValidToken(t *testing.T) {

	tests := []struct {
		name           string
		method         string
		targetURL      string
		setupMocks     func(mService *MockValidTokenService)
		expectedStatus int
	}{
		{

			name:      "success: token is valid and template executes",
			method:    http.MethodGet,
			targetURL: "/v1/validate?token=super_valid_token",
			setupMocks: func(mService *MockValidTokenService) {
				mService.On("ValidToken", mock.Anything, "super_valid_token").Return(nil)
			},
			expectedStatus: http.StatusOK,

		},
		{

			name:      "Error: Service validation failure",
			method:    http.MethodGet,
			targetURL: "/v1/validate?token=expired_token",
			setupMocks: func(mService *MockValidTokenService) {
				mService.On("ValidToken", mock.Anything, "expired_token").Return(domain.ErrInvalidToken)
			},
			expectedStatus: http.StatusUnauthorized,

		},
		{

			name:           "Error: Method not allowed",
			method:         http.MethodPost,
			targetURL:      "/v1/validate?token=valid_token",
			setupMocks:     func(mService *MockValidTokenService) {},
			expectedStatus: http.StatusMethodNotAllowed,

		},
		{

			name:           "Error: Token is empty string",
			method:         http.MethodGet,
			targetURL:      "/v1/validate?token=",
			setupMocks:     func(mService *MockValidTokenService) {},
			expectedStatus: http.StatusUnauthorized,

		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockValidTokenService)
			tt.setupMocks(mockService)

			validHandler := &ValidTokenHandler{
				Service: mockService,
			}

			req := httptest.NewRequest(tt.method, tt.targetURL, nil)
			rec := httptest.NewRecorder()

			validHandler.ValidToken(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)

			if tt.expectedStatus == http.StatusOK {
				assert.NotEmpty(t, rec.Body.String())
			}

			mockService.AssertExpectations(t)
		})
	}

}

func TestLogOutFunction(t *testing.T) {

	tests := []struct {
		name           string
		method         string
		setupCookie    func(req *http.Request)
		setupMocks     func(m *MockLogOutService)
		expectedStatus int
	}{
		{

			name:   "success: logged out and cookie cleared",
			method: http.MethodPost,
			setupCookie: func(req *http.Request) {
				req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "valid_token"})
			},
			setupMocks: func(m *MockLogOutService) {
				m.On("LogOutFunction", mock.Anything, service.LogOutInput{RefreshToken: []byte("valid_token")}).Return(nil)
			},
			expectedStatus: http.StatusNoContent,

		},
		{

			name:   "Error: service failure",
			method: http.MethodPost,
			setupCookie: func(req *http.Request) {
				req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "valid_token"})
			},
			setupMocks: func(m *MockLogOutService) {
				m.On("LogOutFunction", mock.Anything, service.LogOutInput{RefreshToken: []byte("valid_token")}).Return(domain.ErrInvalidToken)
			},
			expectedStatus: http.StatusUnauthorized,

		},
		{

			name:   "Error: Other cookie error",
			method: http.MethodPost,
			setupCookie: func(req *http.Request) {
				req.Header.Set("Cookie", "foo=bar")
			},
			setupMocks:     func(m *MockLogOutService) {},
			expectedStatus: http.StatusUnauthorized,

		},
		{

			name:           "Error: Cookie not found",
			method:         http.MethodPost,
			setupCookie:    func(req *http.Request) {},
			setupMocks:     func(m *MockLogOutService) {},
			expectedStatus: http.StatusUnauthorized,

		},
		{

			name:           "Error: method not allowed",
			method:         http.MethodGet,
			setupCookie:    func(req *http.Request) {},
			setupMocks:     func(m *MockLogOutService) {},
			expectedStatus: http.StatusMethodNotAllowed,
			
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockLogOutService)
			tt.setupMocks(mockService)

			logoutHandler := &LogOutHandler{
				Service: mockService,
			}

			req := httptest.NewRequest(tt.method, "/v1/logout", nil)
			tt.setupCookie(req)

			rec := httptest.NewRecorder()

			logoutHandler.LogOutHandler(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)

			if tt.expectedStatus == http.StatusNoContent {
				cookies := rec.Result().Cookies()
				assert.Len(t, cookies, 1)

				expiredCookie := cookies[0]
				assert.Equal(t, "refresh_token", expiredCookie.Name)
				assert.Equal(t, "", expiredCookie.Value)
				assert.True(t, expiredCookie.MaxAge < 0)
			}

			mockService.AssertExpectations(t)
		})
	}

}
