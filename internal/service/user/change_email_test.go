package user

import (
	"context"
	"testing"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/security/argon2"
	"ShieldAuth-API/internal/service"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockChangeEmailRepository struct{ mock.Mock }

func (m *MockChangeEmailRepository) GetID(ctx context.Context, id int) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}
func (m *MockChangeEmailRepository) UpdateEmail(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

type MockChangeEmailHasher struct{ mock.Mock }

func (m *MockChangeEmailHasher) Compare(password []byte, passwordHash []byte) (*argon2.HashMetaData, error) {
	args := m.Called(password, passwordHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*argon2.HashMetaData), args.Error(1)
}

func (m *MockChangeEmailHasher) Hash(password []byte) ([]byte, error) {
	args := m.Called(password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockChangeEmailHasher) NeedsRehash(memory uint32, iterations uint32, parallelism uint8) bool {
	args := m.Called(memory, iterations, parallelism)
	return args.Bool(0)
}

func TestChangeEmailFunction(t *testing.T) {

	tests := []struct {
		name          string
		input         service.ChangeEmailInput
		setupMocks    func(mRepo *MockChangeEmailRepository, mHasher *MockChangeEmailHasher)
		expectedError error
	}{
		{

			name: "success: email was exchanged",
			input: service.ChangeEmailInput{
				ID:              123,
				CurrentEmail:    "test_current_email@example.com",
				NewEmail:        "test_new_email@example.com",
				ConfirmNewEmail: "test_new_email@example.com",
				Password:        []byte("test_password"),
			},
			setupMocks: func(mRepo *MockChangeEmailRepository, mHasher *MockChangeEmailHasher) {

				fakeUser := domain.RestoreUser(123, "", "test_current_email@example.com", []byte("test_password"))
				mRepo.On("GetID", mock.Anything, 123).Return(fakeUser, nil)

				fakeMetaData := &argon2.HashMetaData{Version: 2, Memory: 65536, Iterations: 2, Parallelism: 2}
				mHasher.On("Compare", []byte("test_password"), fakeUser.PasswordHash).Return(fakeMetaData, nil)

				mRepo.On("UpdateEmail", mock.Anything, fakeUser).Return(nil)
			},
			expectedError: nil,
		},
		{

			name:  "Error: user was not found",
			input: service.ChangeEmailInput{ID: 123},
			setupMocks: func(mRepo *MockChangeEmailRepository, mHasher *MockChangeEmailHasher) {
				mRepo.On("GetID", mock.Anything, 123).Return(nil, domain.ErrUserNotFound)
			},
			expectedError: domain.ErrUserNotFound,
		},
		{

			name:  "Error: wrong password",
			input: service.ChangeEmailInput{ID: 123, Password: []byte("test_password")},
			setupMocks: func(mRepo *MockChangeEmailRepository, mHasher *MockChangeEmailHasher) {
				fakeUser := domain.RestoreUser(123, "", "test_current_email@example.com", []byte("test_password"))
				mRepo.On("GetID", mock.Anything, 123).Return(fakeUser, nil)

				mHasher.On("Compare", []byte("test_password"), fakeUser.PasswordHash).Return(nil, domain.ErrInvalidPassword)
			},
			expectedError: domain.ErrInvalidPassword,
		},
		{

			name: "Error: domain validation failed (emails mismatch)",
			input: service.ChangeEmailInput{
				ID:              123,
				CurrentEmail:    "test_current_email@example.com",
				NewEmail:        "new_email@example.com",
				ConfirmNewEmail: "test_different_new_email@example.com",
				Password:        []byte("test_password"),
			},
			setupMocks: func(mRepo *MockChangeEmailRepository, mHasher *MockChangeEmailHasher) {
				fakeUser := domain.RestoreUser(123, "", "test_current_email@example.com", []byte("test_password"))
				mRepo.On("GetID", mock.Anything, 123).Return(fakeUser, nil)

				fakeMetaData := &argon2.HashMetaData{Version: 2, Memory: 65536, Iterations: 2, Parallelism: 2}
				mHasher.On("Compare", []byte("test_password"), fakeUser.PasswordHash).Return(fakeMetaData, nil)
			},
			expectedError: domain.ErrInternal,
		},
		{

			name: "Error: database failure on update",
			input: service.ChangeEmailInput{
				ID:              123,
				CurrentEmail:    "test_current_email@example.com",
				NewEmail:        "test_new_email@example.com",
				ConfirmNewEmail: "test_new_email@example.com",
				Password:        []byte("test_password"),
			},
			setupMocks: func(mRepo *MockChangeEmailRepository, mHasher *MockChangeEmailHasher) {
				fakeUser := domain.RestoreUser(123, "", "test_current_email@example.com", []byte("test_password"))
				mRepo.On("GetID", mock.Anything, 123).Return(fakeUser, nil)

				fakeMetaData := &argon2.HashMetaData{Version: 2, Memory: 65536, Iterations: 2, Parallelism: 2}
				mHasher.On("Compare", []byte("test_password"), fakeUser.PasswordHash).Return(fakeMetaData, nil)

				mRepo.On("UpdateEmail", mock.Anything, fakeUser).Return(domain.ErrInternal)
			},
			expectedError: domain.ErrInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockChangeEmailRepository)
			mockHasher := new(MockChangeEmailHasher)

			tt.setupMocks(mockRepo, mockHasher)
			changeEmailService := NewChangeEmailService(mockRepo, mockHasher)
			err := changeEmailService.ChangeEmailFunctionTest(context.Background(), tt.input)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)
			mockHasher.AssertExpectations(t)
		})
	}

}
