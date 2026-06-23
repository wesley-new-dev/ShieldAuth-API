package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/middleware"
	"ShieldAuth-API/internal/service"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockRateLimiterUser struct{ mock.Mock }

func (m *MockRateLimiterUser) CheckLimit(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	args := m.Called(ctx, key, limit, window)
	return args.Bool(0), args.Error(1)
}
func (m *MockRateLimiterUser) ResetLimit(ctx context.Context, key string) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

type MockChangeNameService struct{ mock.Mock }

func (m *MockChangeNameService) ChangeNameFunction(ctx context.Context, input service.ChangeNameInput) error {
	args := m.Called(ctx, input)
	return args.Error(0)
}

type MockChangeEmailService struct{ mock.Mock }

func (m *MockChangeEmailService) ChangeEmailFunction(ctx context.Context, input service.ChangeEmailInput) error {
	args := m.Called(ctx, input)
	return args.Error(0)
}

type MockResetPasswordService struct{ mock.Mock }

func (m *MockResetPasswordService) ResetPasswordFunction(ctx context.Context, token string, input service.ResetPasswordInput) error {
	args := m.Called(ctx, token, input)
	return args.Error(0)
}

type MockChangePasswordService struct{ mock.Mock }

func (m *MockChangePasswordService) ChangePassword(ctx context.Context, input service.ChangePasswordInput) error {
	args := m.Called(ctx, input)
	return args.Error(0)
}

type MockDeleteAccountService struct{ mock.Mock }

func (m *MockDeleteAccountService) DeleteAccountFunction(ctx context.Context, input service.DeleteAccountInput) error {
	args := m.Called(ctx, input)
	return args.Error(0)
}

func TestChangeNameHandler(t *testing.T) {
	userID := 42
	targetKey := "change-name-attempt:" + strconv.Itoa(userID)

	validPayload := ChangeNameRequest{
		CurrentName: "test_old_name",
		NewName:     "test_new_name",
	}

	tests := []struct {
		name           string
		method         string
		requestBody    interface{}
		injectContext  bool
		contextValue   interface{}
		setupMocks     func(mService *MockChangeNameService, mLimiter *MockRateLimiterUser)
		expectedStatus int
	}{
		{

			name:          "success: Name changed and limiter reset",
			method:        http.MethodPost,
			requestBody:   validPayload,
			injectContext: true,
			contextValue:  middleware.AuthContext{UserID: userID},
			setupMocks: func(mService *MockChangeNameService, mLimiter *MockRateLimiterUser) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 15, 1*time.Hour).Return(true, nil)
				mService.On("ChangeNameFunction", mock.Anything, mock.Anything).Return(nil)
				mLimiter.On("ResetLimit", mock.Anything, targetKey).Return(nil)
			},
			expectedStatus: http.StatusOK,

		},
		{

			name:           "Error: Method not allowed",
			method:         http.MethodGet,
			requestBody:    validPayload,
			injectContext:  false,
			setupMocks:     func(mService *MockChangeNameService, mLimiter *MockRateLimiterUser) {},
			expectedStatus: http.StatusMethodNotAllowed,

		},
		{

			name:           "Error: Malformed JSON body",
			method:         http.MethodPost,
			requestBody:    "{invalid-json",
			injectContext:  false,
			setupMocks:     func(mService *MockChangeNameService, mLimiter *MockRateLimiterUser) {},
			expectedStatus: http.StatusBadRequest,

		},
		{

			name:           "Error: Context middleware key missing",
			method:         http.MethodPost,
			requestBody:    validPayload,
			injectContext:  false,
			setupMocks:     func(mService *MockChangeNameService, mLimiter *MockRateLimiterUser) {},
			expectedStatus: http.StatusInternalServerError,

		},
		{

			name:           "Error: Unauthorized (UserID <= 0)",
			method:         http.MethodPost,
			requestBody:    validPayload,
			injectContext:  true,
			contextValue:   middleware.AuthContext{UserID: 0},
			setupMocks:     func(mService *MockChangeNameService, mLimiter *MockRateLimiterUser) {},
			expectedStatus: http.StatusUnauthorized,

		},
		{

			name:          "Error: Rate limiter failure",
			method:        http.MethodPost,
			requestBody:   validPayload,
			injectContext: true,
			contextValue:  middleware.AuthContext{UserID: userID},
			setupMocks: func(mService *MockChangeNameService, mLimiter *MockRateLimiterUser) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 15, 1*time.Hour).Return(false, domain.ErrInternal)
			},
			expectedStatus: http.StatusInternalServerError,

		},
		{

			name:          "Error: Too many attempts (Rate limited)",
			method:        http.MethodPost,
			requestBody:   validPayload,
			injectContext: true,
			contextValue:  middleware.AuthContext{UserID: userID},
			setupMocks: func(mService *MockChangeNameService, mLimiter *MockRateLimiterUser) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 15, 1*time.Hour).Return(false, nil)
			},
			expectedStatus: http.StatusTooManyRequests,

		},
		{

			name:          "Error: Service function failure",
			method:        http.MethodPost,
			requestBody:   validPayload,
			injectContext: true,
			contextValue:  middleware.AuthContext{UserID: userID},
			setupMocks: func(mService *MockChangeNameService, mLimiter *MockRateLimiterUser) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 15, 1*time.Hour).Return(true, nil)

				expectedInput := service.ChangeNameInput{
					ID:          userID,
					CurrentName: validPayload.CurrentName,
					NewName:     validPayload.NewName,
				}
				mService.On("ChangeNameFunction", mock.Anything, expectedInput).Return(domain.ErrInternal)
			},
			expectedStatus: http.StatusInternalServerError,

		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockChangeNameService)
			mockLimiter := new(MockRateLimiterUser)
			tt.setupMocks(mockService, mockLimiter)

			changeNameHandler := &ChangeNameHandler{
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

			req := httptest.NewRequest(tt.method, "/v1/change-name", bodyReader)
			req.Header.Set("Content-Type", "application/json")

			if tt.injectContext {
				ctx := context.WithValue(req.Context(), middleware.Key, tt.contextValue)
				req = req.WithContext(ctx)
			}

			rec := httptest.NewRecorder()

			changeNameHandler.ChangeNameHandler(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)

			if tt.expectedStatus == http.StatusOK {
				var responseBody map[string]string
				err := json.Unmarshal(rec.Body.Bytes(), &responseBody)
				assert.NoError(t, err)
				assert.Equal(t, "success", responseBody["message"])
			}

			mockService.AssertExpectations(t)
			mockLimiter.AssertExpectations(t)
		})
	}
}

func TestChangeEmailHandler(t *testing.T) {
	userID := 42
	targetKey := "change-email-attempt:" + strconv.Itoa(userID)

	validPayload := ChangeEmailRequest{
		CurrentEmail:    "test_old_email@example.com",
		NewEmail:        "test_new_email@example.com",
		ConfirmNewEmail: "test_new_email@example.com",
		Password:        []byte("test_password"),
	}

	tests := []struct {
		name           string
		method         string
		requestBody    interface{}
		injectContext  bool
		contextValue   interface{}
		setupMocks     func(mService *MockChangeEmailService, mLimiter *MockRateLimiterUser)
		expectedStatus int
	}{
		{

			name:          "success: Email changed and limiter reset",
			method:        http.MethodPost,
			requestBody:   validPayload,
			injectContext: true,
			contextValue:  middleware.AuthContext{UserID: userID},
			setupMocks: func(mService *MockChangeEmailService, mLimiter *MockRateLimiterUser) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 3, 24*time.Hour).Return(true, nil)
				mService.On("ChangeEmailFunction", mock.Anything, mock.Anything).Return(nil)
				mLimiter.On("ResetLimit", mock.Anything, targetKey).Return(nil)
			},
			expectedStatus: http.StatusOK,

		},
		{

			name:           "Error: Method not allowed",
			method:         http.MethodGet,
			requestBody:    validPayload,
			injectContext:  false,
			setupMocks:     func(mService *MockChangeEmailService, mLimiter *MockRateLimiterUser) {},
			expectedStatus: http.StatusMethodNotAllowed,

		},
		{

			name:           "Error: Malformed JSON body",
			method:         http.MethodPost,
			requestBody:    "{invalid-json",
			injectContext:  false,
			setupMocks:     func(mService *MockChangeEmailService, mLimiter *MockRateLimiterUser) {},
			expectedStatus: http.StatusBadRequest,

		},
		{

			name:           "Error: Context middleware key missing",
			method:         http.MethodPost,
			requestBody:    validPayload,
			injectContext:  false,
			setupMocks:     func(mService *MockChangeEmailService, mLimiter *MockRateLimiterUser) {},
			expectedStatus: http.StatusInternalServerError,

		},
		{

			name:           "Error: Unauthorized (UserID <= 0)",
			method:         http.MethodPost,
			requestBody:    validPayload,
			injectContext:  true,
			contextValue:   middleware.AuthContext{UserID: 0},
			setupMocks:     func(mService *MockChangeEmailService, mLimiter *MockRateLimiterUser) {},
			expectedStatus: http.StatusUnauthorized,

		},
		{

			name:          "Error: Rate limiter failure",
			method:        http.MethodPost,
			requestBody:   validPayload,
			injectContext: true,
			contextValue:  middleware.AuthContext{UserID: userID},
			setupMocks: func(mService *MockChangeEmailService, mLimiter *MockRateLimiterUser) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 3, 24*time.Hour).Return(false, domain.ErrInternal)
			},
			expectedStatus: http.StatusInternalServerError,

		},
		{

			name:          "Error: Too many attempts (Rate limited)",
			method:        http.MethodPost,
			requestBody:   validPayload,
			injectContext: true,
			contextValue:  middleware.AuthContext{UserID: userID},
			setupMocks: func(mService *MockChangeEmailService, mLimiter *MockRateLimiterUser) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 3, 24*time.Hour).Return(false, nil)
			},
			expectedStatus: http.StatusTooManyRequests,

		},
		{

			name:          "Error: Service function failure",
			method:        http.MethodPost,
			requestBody:   validPayload,
			injectContext: true,
			contextValue:  middleware.AuthContext{UserID: userID},
			setupMocks: func(mService *MockChangeEmailService, mLimiter *MockRateLimiterUser) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 3, 24*time.Hour).Return(true, nil)
				mService.On("ChangeEmailFunction", mock.Anything, mock.Anything).Return(domain.ErrEmailAlreadyExists)
			},
			expectedStatus: http.StatusConflict,

		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockChangeEmailService)
			mockLimiter := new(MockRateLimiterUser)
			tt.setupMocks(mockService, mockLimiter)

			changeEmailHandler := &ChangeEmailHandler{
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

			req := httptest.NewRequest(tt.method, "/v1/change-email", bodyReader)
			req.Header.Set("Content-Type", "application/json")

			if tt.injectContext {
				ctx := context.WithValue(req.Context(), middleware.Key, tt.contextValue)
				req = req.WithContext(ctx)
			}

			rec := httptest.NewRecorder()

			changeEmailHandler.ChangeEmailHandler(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)

			if tt.expectedStatus == http.StatusOK {
				var responseBody map[string]string
				err := json.Unmarshal(rec.Body.Bytes(), &responseBody)
				assert.NoError(t, err)
				assert.Equal(t, "success", responseBody["message"])
			}

			mockService.AssertExpectations(t)
			mockLimiter.AssertExpectations(t)
		})
	}
}

func TestResetPasswordHandler(t *testing.T) {
	testToken := "test_token"
	targetKey := "reset-password-attempt:" + testToken

	validPayload := ResetPasswordRequest{
		Token:              testToken,
		NewPassword:        []byte("test_new_password"),
		ConfirmNewPassword: []byte("test_new_password"),
	}

	tests := []struct {
		name           string
		method         string
		requestBody    interface{}
		setupMocks     func(mService *MockResetPasswordService, mLimiter *MockRateLimiterUser)
		expectedStatus int
	}{
		{

			name:        "success: Password reset and limiter reset",
			method:      http.MethodPost,
			requestBody: validPayload,
			setupMocks: func(mService *MockResetPasswordService, mLimiter *MockRateLimiterUser) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 3, 24*time.Hour).Return(true, nil)
				mService.On("ResetPasswordFunction", mock.Anything, testToken, mock.Anything).Return(nil)
				mLimiter.On("ResetLimit", mock.Anything, targetKey).Return(nil)
			},
			expectedStatus: http.StatusOK,

		},
		{

			name:           "Error: Method not allowed",
			method:         http.MethodGet,
			requestBody:    validPayload,
			setupMocks:     func(mService *MockResetPasswordService, mLimiter *MockRateLimiterUser) {},
			expectedStatus: http.StatusMethodNotAllowed,

		},
		{

			name:           "Error: Malformed JSON body",
			method:         http.MethodPost,
			requestBody:    "{invalid-json",
			setupMocks:     func(mService *MockResetPasswordService, mLimiter *MockRateLimiterUser) {},
			expectedStatus: http.StatusBadRequest,

		},
		{

			name:        "Error: Rate limiter failure",
			method:      http.MethodPost,
			requestBody: validPayload,
			setupMocks: func(mService *MockResetPasswordService, mLimiter *MockRateLimiterUser) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 3, 24*time.Hour).Return(false, domain.ErrInternal)
			},
			expectedStatus: http.StatusInternalServerError,

		},
		{

			name:        "Error: Too many requests (Rate limited)",
			method:      http.MethodPost,
			requestBody: validPayload,
			setupMocks: func(mService *MockResetPasswordService, mLimiter *MockRateLimiterUser) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 3, 24*time.Hour).Return(false, nil)
			},
			expectedStatus: http.StatusTooManyRequests,

		},
		{

			name:        "Error: Service function failure",
			method:      http.MethodPost,
			requestBody: validPayload,
			setupMocks: func(mService *MockResetPasswordService, mLimiter *MockRateLimiterUser) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 3, 24*time.Hour).Return(true, nil)
				mService.On("ResetPasswordFunction", mock.Anything, testToken, mock.Anything).Return(domain.ErrInvalidToken)
			},
			expectedStatus: http.StatusUnauthorized,

		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockResetPasswordService)
			mockLimiter := new(MockRateLimiterUser)
			tt.setupMocks(mockService, mockLimiter)

			resetHandler := &ResetPasswordHandler{
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

			req := httptest.NewRequest(tt.method, "/v1/reset-password", bodyReader)
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()

			resetHandler.ResetPasswordHandler(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)

			if tt.expectedStatus == http.StatusOK {
				var responseBody map[string]string
				err := json.Unmarshal(rec.Body.Bytes(), &responseBody)
				assert.NoError(t, err)
				assert.Equal(t, "success", responseBody["message"])
			}

			mockService.AssertExpectations(t)
			mockLimiter.AssertExpectations(t)
		})
	}
}

func TestChangePasswordHandler(t *testing.T) {
	userID := 42
	targetKey := "change-password-attempt:" + strconv.Itoa(userID)

	validPayload := ChangePasswordRequest{
		CurrentPassword:    []byte("test_old_pass123"),
		NewPassword:        []byte("test_new_password"),
		ConfirmNewPassword: []byte("test_new_password"),
	}

	tests := []struct {
		name           string
		method         string
		requestBody    interface{}
		injectContext  bool
		contextValue   interface{}
		setupMocks     func(mService *MockChangePasswordService, mLimiter *MockRateLimiterUser)
		expectedStatus int
	}{
		{

			name:          "success: Password changed and limiter reset",
			method:        http.MethodPost,
			requestBody:   validPayload,
			injectContext: true,
			contextValue:  middleware.AuthContext{UserID: userID},
			setupMocks: func(mService *MockChangePasswordService, mLimiter *MockRateLimiterUser) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 3, 24*time.Hour).Return(true, nil)
				mService.On("ChangePassword", mock.Anything, mock.Anything).Return(nil)
				mLimiter.On("ResetLimit", mock.Anything, targetKey).Return(nil)
			},
			expectedStatus: http.StatusOK,

		},
		{

			name:           "Error: Method not allowed",
			method:         http.MethodGet,
			requestBody:    validPayload,
			injectContext:  false,
			setupMocks:     func(mService *MockChangePasswordService, mLimiter *MockRateLimiterUser) {},
			expectedStatus: http.StatusMethodNotAllowed,

		},
		{

			name:           "Error: Malformed JSON body",
			method:         http.MethodPost,
			requestBody:    "{invalid-json",
			injectContext:  false,
			setupMocks:     func(mService *MockChangePasswordService, mLimiter *MockRateLimiterUser) {},
			expectedStatus: http.StatusBadRequest,

		},
		{

			name:           "Error: Context middleware key missing",
			method:         http.MethodPost,
			requestBody:    validPayload,
			injectContext:  false,
			setupMocks:     func(mService *MockChangePasswordService, mLimiter *MockRateLimiterUser) {},
			expectedStatus: http.StatusInternalServerError,

		},
		{

			name:           "Error: Unauthorized (UserID <= 0)",
			method:         http.MethodPost,
			requestBody:    validPayload,
			injectContext:  true,
			contextValue:   middleware.AuthContext{UserID: 0},
			setupMocks:     func(mService *MockChangePasswordService, mLimiter *MockRateLimiterUser) {},
			expectedStatus: http.StatusUnauthorized,

		},
		{

			name:          "Error: Rate limiter check failure",
			method:        http.MethodPost,
			requestBody:   validPayload,
			injectContext: true,
			contextValue:  middleware.AuthContext{UserID: userID},
			setupMocks: func(mService *MockChangePasswordService, mLimiter *MockRateLimiterUser) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 3, 24*time.Hour).Return(false, domain.ErrInternal)
			},
			expectedStatus: http.StatusInternalServerError,

		},
		{

			name:          "Error: Too many attempts (Rate limited)",
			method:        http.MethodPost,
			requestBody:   validPayload,
			injectContext: true,
			contextValue:  middleware.AuthContext{UserID: userID},
			setupMocks: func(mService *MockChangePasswordService, mLimiter *MockRateLimiterUser) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 3, 24*time.Hour).Return(false, nil)
			},
			expectedStatus: http.StatusTooManyRequests,

		},
		{

			name:          "Error: Service function failure",
			method:        http.MethodPost,
			requestBody:   validPayload,
			injectContext: true,
			contextValue:  middleware.AuthContext{UserID: userID},
			setupMocks: func(mService *MockChangePasswordService, mLimiter *MockRateLimiterUser) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 3, 24*time.Hour).Return(true, nil)
				mService.On("ChangePassword", mock.Anything, mock.Anything).Return(domain.ErrInvalidPassword)
			},
			expectedStatus: http.StatusUnauthorized,

		},
		{

			name:          "Error: Rate limiter reset failure",
			method:        http.MethodPost,
			requestBody:   validPayload,
			injectContext: true,
			contextValue:  middleware.AuthContext{UserID: userID},
			setupMocks: func(mService *MockChangePasswordService, mLimiter *MockRateLimiterUser) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 3, 24*time.Hour).Return(true, nil)
				mService.On("ChangePassword", mock.Anything, mock.Anything).Return(nil)
				mLimiter.On("ResetLimit", mock.Anything, targetKey).Return(domain.ErrInternal).Once()
			},
			expectedStatus: http.StatusInternalServerError,

		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockChangePasswordService)
			mockLimiter := new(MockRateLimiterUser)
			tt.setupMocks(mockService, mockLimiter)

			changePasswordHandler := &ChangePasswordHandler{
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

			req := httptest.NewRequest(tt.method, "/v1/change-password", bodyReader)
			req.Header.Set("Content-Type", "application/json")

			if tt.injectContext {
				ctx := context.WithValue(req.Context(), middleware.Key, tt.contextValue)
				req = req.WithContext(ctx)
			}

			rec := httptest.NewRecorder()

			changePasswordHandler.ChangePasswordHandler(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)

			if tt.expectedStatus == http.StatusOK {
				var responseBody map[string]string
				err := json.Unmarshal(rec.Body.Bytes(), &responseBody)
				assert.NoError(t, err)
				assert.Equal(t, "success", responseBody["message"])
			}

			mockService.AssertExpectations(t)
			mockLimiter.AssertExpectations(t)
		})
	}
}

func TestDeleteAccountHandler(t *testing.T) {
	userID := 42
	targetKey := "delete-account-attempt:" + strconv.Itoa(userID)

	validPayload := DeleteAccountRequest{
		CurrentPassword: []byte("test_password123"),
	}

	tests := []struct {
		name           string
		method         string
		requestBody    interface{}
		injectContext  bool
		contextValue   interface{}
		setupMocks     func(mService *MockDeleteAccountService, mLimiter *MockRateLimiterUser)
		expectedStatus int
	}{
		{

			name:          "Success: Account deleted",
			method:        http.MethodPost,
			requestBody:   validPayload,
			injectContext: true,
			contextValue:  middleware.AuthContext{UserID: userID},
			setupMocks: func(mService *MockDeleteAccountService, mLimiter *MockRateLimiterUser) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 3, 24*time.Hour).Return(true, nil)
				mService.On("DeleteAccountFunction", mock.Anything, mock.Anything).Return(nil)
			},
			expectedStatus: http.StatusOK,

		},
		{

			name:           "Error: Method not allowed",
			method:         http.MethodGet,
			requestBody:    validPayload,
			injectContext:  false,
			setupMocks:     func(mService *MockDeleteAccountService, mLimiter *MockRateLimiterUser) {},
			expectedStatus: http.StatusMethodNotAllowed,

		},
		{

			name:           "Error: Malformed JSON body",
			method:         http.MethodPost,
			requestBody:    "{invalid-json",
			injectContext:  false,
			setupMocks:     func(mService *MockDeleteAccountService, mLimiter *MockRateLimiterUser) {},
			expectedStatus: http.StatusBadRequest,

		},
		{

			name:           "Error: Context middleware key missing",
			method:         http.MethodPost,
			requestBody:    validPayload,
			injectContext:  false,
			setupMocks:     func(mService *MockDeleteAccountService, mLimiter *MockRateLimiterUser) {},
			expectedStatus: http.StatusUnauthorized,

		},
		{

			name:           "Error: Unauthorized (UserID <= 0)",
			method:         http.MethodPost,
			requestBody:    validPayload,
			injectContext:  true,
			contextValue:   middleware.AuthContext{UserID: 0},
			setupMocks:     func(mService *MockDeleteAccountService, mLimiter *MockRateLimiterUser) {},
			expectedStatus: http.StatusUnauthorized,

		},
		{

			name:          "Error: Rate limiter check failure",
			method:        http.MethodPost,
			requestBody:   validPayload,
			injectContext: true,
			contextValue:  middleware.AuthContext{UserID: userID},
			setupMocks: func(mService *MockDeleteAccountService, mLimiter *MockRateLimiterUser) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 3, 24*time.Hour).Return(false, domain.ErrInternal)
			},
			expectedStatus: http.StatusInternalServerError,

		},
		{

			name:          "Error: Too many attempts (Rate limited)",
			method:        http.MethodPost,
			requestBody:   validPayload,
			injectContext: true,
			contextValue:  middleware.AuthContext{UserID: userID},
			setupMocks: func(mService *MockDeleteAccountService, mLimiter *MockRateLimiterUser) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 3, 24*time.Hour).Return(false, nil)
			},
			expectedStatus: http.StatusTooManyRequests,

		},
		{

			name:          "Error: Service function failure",
			method:        http.MethodPost,
			requestBody:   validPayload,
			injectContext: true,
			contextValue:  middleware.AuthContext{UserID: userID},
			setupMocks: func(mService *MockDeleteAccountService, mLimiter *MockRateLimiterUser) {
				mLimiter.On("CheckLimit", mock.Anything, targetKey, 3, 24*time.Hour).Return(true, nil)
				mService.On("DeleteAccountFunction", mock.Anything, mock.Anything).Return(domain.ErrInvalidPassword)
			},
			expectedStatus: http.StatusUnauthorized,
			
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockDeleteAccountService)
			mockLimiter := new(MockRateLimiterUser)
			tt.setupMocks(mockService, mockLimiter)

			deleteAccountHandler := &DeleteAccountHandler{
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

			req := httptest.NewRequest(tt.method, "/v1/delete-account", bodyReader)
			req.Header.Set("Content-Type", "application/json")

			if tt.injectContext {
				ctx := context.WithValue(req.Context(), middleware.Key, tt.contextValue)
				req = req.WithContext(ctx)
			}

			rec := httptest.NewRecorder()

			deleteAccountHandler.DeleteAccountHandler(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)

			if tt.expectedStatus == http.StatusOK {
				var responseBody map[string]string
				err := json.Unmarshal(rec.Body.Bytes(), &responseBody)
				assert.NoError(t, err)
				assert.Equal(t, "success", responseBody["message"])
			}

			mockService.AssertExpectations(t)
			mockLimiter.AssertExpectations(t)
		})
	}
}
