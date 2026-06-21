package auth

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/security/argon2"
	"ShieldAuth-API/internal/service"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockUserRepository struct{ mock.Mock }
func (m *MockUserRepository) Create(ctx context.Context, u *domain.User) (int64, error) {
	args := m.Called(ctx, u)
	return args.Get(0).(int64), args.Error(1)
}
func (m *MockUserRepository) SaveRefreshToken(ctx context.Context, model domain.RefreshToken) error {
	args := m.Called(ctx, model)
	return args.Error(0)
}

type MockHasher struct{ mock.Mock }
func (m *MockHasher) Hash(password []byte) ([]byte, error) {
	args := m.Called(password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}
func (m *MockHasher) Compare(password, passwordHash []byte) error {
	args := m.Called(password, passwordHash)
	return args.Error(0)
}

type MockHIBPChecker struct{ mock.Mock }
func (m *MockHIBPChecker) IsLeaked(password []byte) (bool, error) {
	args := m.Called(password)
	return args.Bool(0), args.Error(1)
}

func TestRegisterFunction(t *testing.T) {

	tests := []struct {
		name          string
		inputPassword []byte
		setupMocks    func(mRepo *MockUserRepository, mHasher *MockHasher, mHIBP *MockHIBPChecker)
		expectedID    int64
		expectedError error
	}{
		{
			name:          "successful registration",
			inputPassword: []byte("test_valid_strong_password_123"),
			setupMocks: func(mRepo *MockUserRepository, mHasher *MockHasher, mHIBP *MockHIBPChecker) {
				mHIBP.On("IsLeaked", []byte("test_valid_strong_password_123")).Return(false, nil)
				mHasher.On("Hash", []byte("test_valid_strong_password_123")).Return([]byte("hashed_password"), nil)
				mRepo.On("Create", mock.Anything, mock.MatchedBy(func(u *domain.User) bool {
					return u.Name == "test_name" && bytes.Equal(u.PasswordHash, []byte("hashed_password"))
				})).Return(int64(42), nil)
			},
			expectedID:    42,
			expectedError: nil,
		},
		{
			name:          "Error: password too short",
			inputPassword: []byte("short"),
			setupMocks:    func(mRepo *MockUserRepository, mHasher *MockHasher, mHIBP *MockHIBPChecker) {},
			expectedID:    0,
			expectedError: domain.ErrWeakPassword,
		},
		{

			name:          "Error: password was leaked (pwned)",
			inputPassword: []byte("test_password_leaked"),
			setupMocks: func(mRepo *MockUserRepository, mHasher *MockHasher, mHIBP *MockHIBPChecker) {
				mHIBP.On("IsLeaked", []byte("test_password_leaked")).Return(true, nil)
			},
			expectedID:    0,
			expectedError: domain.ErrPasswordPwned,
		},
		{

			name:          "Error: password leak checker internal failure",
			inputPassword: []byte("test_valid_strong_password_123"),
			setupMocks: func(mRepo *MockUserRepository, mHasher *MockHasher, mHIBP *MockHIBPChecker) {
				mHIBP.On("IsLeaked", []byte("test_valid_strong_password_123")).Return(false, errors.New("internal error"))
			},
			expectedID:    0,
			expectedError: domain.ErrInternal,
		},
		{

			name:          "Error: failed to generate password hash",
			inputPassword: []byte("test_valid_strong_password_123"),
			setupMocks: func(mRepo *MockUserRepository, mHasher *MockHasher, mHIBP *MockHIBPChecker) {
				mHIBP.On("IsLeaked", []byte("test_valid_strong_password_123")).Return(false, nil)
				mHasher.On("Hash", []byte("test_valid_strong_password_123")).Return(nil, errors.New("hasher internal error"))
			},
			expectedID:    0,
			expectedError: errors.New("hasher internal error"),
		},
		{

			name:          "Error: repository persistence failure",
			inputPassword: []byte("test_valid_strong_password_123"),
			setupMocks: func(mRepo *MockUserRepository, mHasher *MockHasher, mHIBP *MockHIBPChecker) {
				mHIBP.On("IsLeaked", []byte("test_valid_strong_password_123")).Return(false, nil)
				mHasher.On("Hash", []byte("test_valid_strong_password_123")).Return([]byte("hashed_password"), nil)
				mRepo.On("Create", mock.Anything, mock.Anything).Return(int64(0), errors.New("database error"))
			},
			expectedID:    0,
			expectedError: errors.New("failed to register user: database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockUserRepository)
			mockHasher := new(MockHasher)
			mockHIBP := new(MockHIBPChecker)

			tt.setupMocks(mockRepo, mockHasher, mockHIBP)
			registerService := NewRegisterService(mockRepo, mockHIBP, mockHasher)
			input := service.RegisterInput{
				Name:     "test_name",
				Email:    "test_email",
				Password: tt.inputPassword,
			}
			id, err := registerService.RegisterFunction(context.Background(), input)
			assert.Equal(t, tt.expectedID, id)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)
			mockHasher.AssertExpectations(t)
			mockHIBP.AssertExpectations(t)
		})
	}

}

func TestCreateRefreshTokenForRegister(t *testing.T) {

	tests := []struct {
		name          string
		setupMocks    func(mRepo *MockLoginRepository)
		expectedError error
		expectToken   bool
	}{
		{

			name: "token created successfully",
			setupMocks: func(mRepo *MockLoginRepository) {
				mRepo.On("SaveRefreshToken", mock.Anything, mock.MatchedBy(func(model domain.RefreshToken) bool {
					return model.UserID == 123 && model.Token != ""
				})).Return(nil)
			},
			expectedError: nil,
			expectToken:   true,
		},
		{

			name: "Error: database connection failed",
			setupMocks: func(mRepo *MockLoginRepository) {
				mRepo.On("SaveRefreshToken", mock.Anything, mock.Anything).Return(errors.New("database connection failed"))
			},
			expectedError: errors.New("database connection failed"),
			expectToken:   false,
		},
		{

			name: "Error: repository returns domain error",
			setupMocks: func(mRepo *MockLoginRepository) {
				mRepo.On("SaveRefreshToken", mock.Anything, mock.Anything).Return(domain.ErrNotFound)
			},
			expectedError: domain.ErrNotFound,
			expectToken:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockLoginRepository)

			tt.setupMocks(mockRepo)
			service := NewLoginService(mockRepo, &argon2.Argon2Hasher{})
			token, err := service.CreateRefreshToken(context.Background(), 123, 1*time.Hour)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
				assert.Empty(t, token)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, token)
				assert.Len(t, token, 64)
			}

			mockRepo.AssertExpectations(t)
		})
	}

}
