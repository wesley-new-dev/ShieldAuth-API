package user

import (
	"context"
	"errors"
	"testing"
	"time"

	"ShieldAuth-API/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockRequestResetPasswordRepository struct{ mock.Mock }

func (m *MockRequestResetPasswordRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

type MockRequestResetPasswordToken struct{ mock.Mock }

func (m *MockRequestResetPasswordToken) GenerateToken() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}
func (m *MockRequestResetPasswordToken) TokenHash(token string) string {
	args := m.Called(token)
	return args.String(0)
}

type MockRequestResetPasswordSave struct{ mock.Mock }

func (m *MockRequestResetPasswordSave) Save(ctx context.Context, token string, userID int64, ttl time.Duration) error {
	args := m.Called(ctx, token, userID, ttl)
	return args.Error(0)
}
func (m *MockRequestResetPasswordSave) Delete(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}
func (m *MockRequestResetPasswordSave) Get(ctx context.Context, token string) (string, error) {
	args := m.Called(ctx, token)
	return args.String(0), args.Error(1)
}

func TestRequestResetPasswordFunction(t *testing.T) {

	tests := []struct {
		name          string
		email         string
		setupMocks    func(mRepo *MockRequestResetPasswordRepository, mToken *MockRequestResetPasswordToken, mSave *MockRequestResetPasswordSave)
		expectedError error
	}{
		{

			name:  "success: request was send",
			email: "test_email@example.com",
			setupMocks: func(mRepo *MockRequestResetPasswordRepository, mToken *MockRequestResetPasswordToken, mSave *MockRequestResetPasswordSave) {

				fakeUser := domain.RestoreUser(123, "", "test_email@example.com", nil)
				mRepo.On("GetByEmail", mock.Anything, "test_email@example.com").Return(fakeUser, nil)

				mToken.On("GenerateToken").Return("test_token", nil)
				mSave.On("Save", mock.Anything, "test_token", int64(123), 15*time.Minute).Return(nil)
			},
			expectedError: nil,
		},
		{

			name:  "Error: user was not found",
			email: "test_email@example.com",
			setupMocks: func(mRepo *MockRequestResetPasswordRepository, mToken *MockRequestResetPasswordToken, mSave *MockRequestResetPasswordSave) {
				mRepo.On("GetByEmail", mock.Anything, "test_email@example.com").Return(nil, domain.ErrUserNotFound)
			},
			expectedError: domain.ErrUserNotFound,
		},
		{

			name:  "Error: failure on generate token",
			email: "test_email@example.com",
			setupMocks: func(mRepo *MockRequestResetPasswordRepository, mToken *MockRequestResetPasswordToken, mSave *MockRequestResetPasswordSave) {

				fakeUser := domain.RestoreUser(123, "", "test_email@example.com", nil)
				mRepo.On("GetByEmail", mock.Anything, "test_email@example.com").Return(fakeUser, nil)

				mToken.On("GenerateToken").Return("", errors.New("generate token failed"))
			},
			expectedError: errors.New("generate token failed"),
		},
		{

			name:  "Error: failure on save",
			email: "test_email@example.com",
			setupMocks: func(mRepo *MockRequestResetPasswordRepository, mToken *MockRequestResetPasswordToken, mSave *MockRequestResetPasswordSave) {

				fakeUser := domain.RestoreUser(123, "", "test_email@example.com", nil)
				mRepo.On("GetByEmail", mock.Anything, "test_email@example.com").Return(fakeUser, nil)

				mToken.On("GenerateToken").Return("test_token", nil)
				mSave.On("Save", mock.Anything, "test_token", int64(123), 15*time.Minute).Return(domain.ErrInternal)
			},
			expectedError: domain.ErrInternal,
		},
		{

			name:  "Error: database connection is down",
			email: "test_email@example.com",
			setupMocks: func(mRepo *MockRequestResetPasswordRepository, mToken *MockRequestResetPasswordToken, mSave *MockRequestResetPasswordSave) {
				mRepo.On("GetByEmail", mock.Anything, "test_email@example.com").Return(nil, errors.New("database connection is down"))
			},
			expectedError: errors.New("database connection is down"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockRequestResetPasswordRepository)
			mockToken := new(MockRequestResetPasswordToken)
			mockSave := new(MockRequestResetPasswordSave)

			tt.setupMocks(mockRepo, mockToken, mockSave)
			requestResetPasswordService := NewRequestResetService(mockRepo, mockSave, mockToken)
			token, err := requestResetPasswordService.RequestReset(context.Background(), tt.email)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Empty(t, token)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, token)
				assert.Equal(t, "test_token", token)
			}

			mockRepo.AssertExpectations(t)
			mockToken.AssertExpectations(t)
			mockSave.AssertExpectations(t)

		})
	}

}
