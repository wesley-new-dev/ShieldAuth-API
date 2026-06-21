package user

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/security/argon2"
	"ShieldAuth-API/internal/security/hibp"
	"ShieldAuth-API/internal/service"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockPasswordLeakChecker struct{ mock.Mock }

func (m *MockPasswordLeakChecker) IsLeaked(password []byte) (bool, error) {
	args := m.Called(password)
	return args.Bool(0), args.Error(1)
}

type MockResetPasswordRedis struct{ mock.Mock }

func (m *MockResetPasswordRedis) Get(ctx context.Context, token string) (string, error) {
	args := m.Called(ctx, token)
	return args.String(0), args.Error(1)
}
func (m *MockResetPasswordRedis) Delete(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}
func (m *MockResetPasswordRedis) Save(ctx context.Context, token string, userID int64, ttl time.Duration) error {
	args := m.Called(ctx, token, userID, ttl)
	return args.Error(0)
}

type MockResetPasswordRepository struct{ mock.Mock }

func (m *MockResetPasswordRepository) UpdatePassword(ctx context.Context, userID string, passwordHash []byte) error {
	args := m.Called(ctx, userID, passwordHash)
	return args.Error(0)
}

type MockResetPasswordHasher struct{ mock.Mock }

func (m *MockResetPasswordHasher) Hash(password []byte) ([]byte, error) {
	args := m.Called(password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}
func (m *MockResetPasswordHasher) Compare(password, passwordHash []byte) (*argon2.HashMetaData, error) {
	args := m.Called(password, passwordHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*argon2.HashMetaData), args.Error(1)
}
func (m *MockResetPasswordHasher) NeedsRehash(memory uint32, iterations uint32, parallelism uint8) bool {
	args := m.Called(memory, iterations, parallelism)
	return args.Bool(0)
}

func TestResetPasswordFunction(t *testing.T) {

	errRedis := errors.New("redis error")
	errHash := errors.New("hash error")
	errRepo := errors.New("database error")
	errLeak := errors.New("leak checker down")

	tests := []struct {
		name          string
		input         service.ResetPasswordInput
		setupMocks    func(mRepo *MockResetPasswordRepository, mLeak *MockPasswordLeakChecker, mRedis *MockResetPasswordRedis, mHasher *MockResetPasswordHasher)
		expectedError error
	}{
		{

			name: "success: the password has been reset",
			input: service.ResetPasswordInput{
				Token:           "test_token",
				NewPassword:     []byte("valid_password_12_chars"),
				ConfirmPassword: []byte("valid_password_12_chars"),
			},
			setupMocks: func(mRepo *MockResetPasswordRepository, mLeak *MockPasswordLeakChecker, mRedis *MockResetPasswordRedis, mHasher *MockResetPasswordHasher) {
				mRedis.On("Delete", mock.Anything, "test_token").Return(nil)
				mLeak.On("IsLeaked", []byte("valid_password_12_chars")).Return(false, nil)
				mRedis.On("Get", mock.Anything, "test_token").Return("123", nil)
				mHasher.On("Hash", []byte("valid_password_12_chars")).Return([]byte("hashed_password"), nil)
				mRepo.On("UpdatePassword", mock.Anything, "123", []byte("hashed_password")).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Error: passwords do not match",
			input: service.ResetPasswordInput{
				Token:           "test_token",
				NewPassword:     []byte("valid_password_12_chars"),
				ConfirmPassword: []byte("different_password"),
			},
			setupMocks: func(mRepo *MockResetPasswordRepository, mLeak *MockPasswordLeakChecker, mRedis *MockResetPasswordRedis, mHasher *MockResetPasswordHasher) {
			},
			expectedError: domain.ErrPasswordDoNotMatch,
		},
		{
			name: "Error: password too short",
			input: service.ResetPasswordInput{
				Token:           "test_token",
				NewPassword:     []byte("short"),
				ConfirmPassword: []byte("short"),
			},
			setupMocks: func(mRepo *MockResetPasswordRepository, mLeak *MockPasswordLeakChecker, mRedis *MockResetPasswordRedis, mHasher *MockResetPasswordHasher) {
				mRedis.On("Delete", mock.Anything, "test_token").Return(nil)
			},
			expectedError: domain.ErrShortPassword,
		},
		{
			name: "Error: password too long",
			input: service.ResetPasswordInput{
				Token:           "test_token",
				NewPassword:     bytes.Repeat([]byte("a"), 129),
				ConfirmPassword: bytes.Repeat([]byte("a"), 129),
			},
			setupMocks: func(mRepo *MockResetPasswordRepository, mLeak *MockPasswordLeakChecker, mRedis *MockResetPasswordRedis, mHasher *MockResetPasswordHasher) {
				mRedis.On("Delete", mock.Anything, "test_token").Return(nil)
			},
			expectedError: domain.ErrLongPassword,
		},
		{
			name: "Error: password has leaked (pwned)",
			input: service.ResetPasswordInput{
				Token:           "test_token",
				NewPassword:     []byte("pwned_password_12_chars"),
				ConfirmPassword: []byte("pwned_password_12_chars"),
			},
			setupMocks: func(mRepo *MockResetPasswordRepository, mLeak *MockPasswordLeakChecker, mRedis *MockResetPasswordRedis, mHasher *MockResetPasswordHasher) {
				mRedis.On("Delete", mock.Anything, "test_token").Return(nil)
				mLeak.On("IsLeaked", []byte("pwned_password_12_chars")).Return(true, nil)
			},
			expectedError: domain.ErrPasswordPwned,
		},
		{
			name: "Error: leak checker failed internally",
			input: service.ResetPasswordInput{
				Token:           "test_token",
				NewPassword:     []byte("valid_password_12_chars"),
				ConfirmPassword: []byte("valid_password_12_chars"),
			},
			setupMocks: func(mRepo *MockResetPasswordRepository, mLeak *MockPasswordLeakChecker, mRedis *MockResetPasswordRedis, mHasher *MockResetPasswordHasher) {
				mRedis.On("Delete", mock.Anything, "test_token").Return(nil)
				mLeak.On("IsLeaked", []byte("valid_password_12_chars")).Return(false, errLeak)
			},
			expectedError: errLeak,
		},
		{
			name: "Error: invalid or expired token",
			input: service.ResetPasswordInput{
				Token:           "test_token",
				NewPassword:     []byte("valid_password_12_chars"),
				ConfirmPassword: []byte("valid_password_12_chars"),
			},
			setupMocks: func(mRepo *MockResetPasswordRepository, mLeak *MockPasswordLeakChecker, mRedis *MockResetPasswordRedis, mHasher *MockResetPasswordHasher) {
				mRedis.On("Delete", mock.Anything, "test_token").Return(nil)
				mLeak.On("IsLeaked", []byte("valid_password_12_chars")).Return(false, nil)
				mRedis.On("Get", mock.Anything, "test_token").Return("", errRedis)
			},
			expectedError: errRedis,
		},
		{
			name: "Error: failed to hash password",
			input: service.ResetPasswordInput{
				Token:           "test_token",
				NewPassword:     []byte("valid_password_12_chars"),
				ConfirmPassword: []byte("valid_password_12_chars"),
			},
			setupMocks: func(mRepo *MockResetPasswordRepository, mLeak *MockPasswordLeakChecker, mRedis *MockResetPasswordRedis, mHasher *MockResetPasswordHasher) {
				mRedis.On("Delete", mock.Anything, "test_token").Return(nil)
				mLeak.On("IsLeaked", []byte("valid_password_12_chars")).Return(false, nil)
				mRedis.On("Get", mock.Anything, "test_token").Return("123", nil)
				mHasher.On("Hash", []byte("valid_password_12_chars")).Return(nil, errHash)
			},
			expectedError: errHash,
		},
		{
			name: "Error: failed to hash password",
			input: service.ResetPasswordInput{
				Token:           "test_token",
				NewPassword:     []byte("valid_password_12_chars"),
				ConfirmPassword: []byte("valid_password_12_chars"),
			},
			setupMocks: func(mRepo *MockResetPasswordRepository, mLeak *MockPasswordLeakChecker, mRedis *MockResetPasswordRedis, mHasher *MockResetPasswordHasher) {
				mRedis.On("Delete", mock.Anything, "test_token").Return(nil)
				mLeak.On("IsLeaked", []byte("valid_password_12_chars")).Return(false, nil)
				mRedis.On("Get", mock.Anything, "test_token").Return("123", nil)
				mHasher.On("Hash", []byte("valid_password_12_chars")).Return(nil, errHash)
			},
			expectedError: errHash,
		},
		{
			name: "Error: failed to update password in repository",
			input: service.ResetPasswordInput{
				Token:           "test_token",
				NewPassword:     []byte("valid_password_12_chars"),
				ConfirmPassword: []byte("valid_password_12_chars"),
			},
			setupMocks: func(mRepo *MockResetPasswordRepository, mLeak *MockPasswordLeakChecker, mRedis *MockResetPasswordRedis, mHasher *MockResetPasswordHasher) {
				mRedis.On("Delete", mock.Anything, "test_token").Return(nil)
				mLeak.On("IsLeaked", []byte("valid_password_12_chars")).Return(false, nil)
				mRedis.On("Get", mock.Anything, "test_token").Return("123", nil)
				mHasher.On("Hash", []byte("valid_password_12_chars")).Return([]byte("hashed_password"), nil)
				mRepo.On("UpdatePassword", mock.Anything, "123", []byte("hashed_password")).Return(errRepo)
			},
			expectedError: errRepo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockResetPasswordRepository)
			mockLeak := new(MockPasswordLeakChecker)
			mockRedis := new(MockResetPasswordRedis)
			mockHasher := new(MockResetPasswordHasher)

			tt.setupMocks(mockRepo, mockLeak, mockRedis, mockHasher)

			resetPasswordService := NewResetPasswordService(mockRepo, mockLeak, hibp.HIBPChecker{}, mockHasher)
			resetPasswordService.redis = mockRedis

			err := resetPasswordService.ResetPasswordFunction(context.Background(), tt.input.Token, tt.input)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)
			mockLeak.AssertExpectations(t)
			mockRedis.AssertExpectations(t)
			mockHasher.AssertExpectations(t)
		})
	}

}
