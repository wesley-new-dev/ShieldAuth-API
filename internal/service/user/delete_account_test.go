package user

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/security/argon2"
	"ShieldAuth-API/internal/service"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockDeleteAccountRepository struct{ mock.Mock }

func (m *MockDeleteAccountRepository) Delete(ctx context.Context, id int) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockDeleteAccountRepository) GetHashById(ctx context.Context, id int) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

type MockDeleteAccountHasher struct{ mock.Mock }

func (m *MockDeleteAccountHasher) Compare(password []byte, passwordHash []byte) (*argon2.HashMetaData, error) {
	args := m.Called(password, passwordHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*argon2.HashMetaData), args.Error(1)
}

func (m *MockDeleteAccountHasher) Hash(password []byte) ([]byte, error) {
	args := m.Called(password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockDeleteAccountHasher) NeedsRehash(memory uint32, iterations uint32, parallelism uint8) bool {
	args := m.Called(memory, iterations, parallelism)
	return args.Bool(0)
}

func TestDeleteAccount(t *testing.T) {

	tests := []struct {
		name          string
		input         service.DeleteAccountInput
		setupMocks    func(mRepo *MockDeleteAccountRepository, mHasher *MockDeleteAccountHasher)
		expectedError error
	}{
		{

			name: "success: the account was deleted",
			input: service.DeleteAccountInput{
				UserID:          123,
				CurrentPassword: []byte("test_current_password"),
			},
			setupMocks: func(mRepo *MockDeleteAccountRepository, mHasher *MockDeleteAccountHasher) {

				fakeUser := domain.RestoreUser(123, "", "", []byte("test_current_password"))
				mRepo.On("GetHashById", mock.Anything, 123).Return(fakeUser, nil)

				fakeMetaData := &argon2.HashMetaData{Version: 2, Memory: 65536, Iterations: 2, Parallelism: 2}
				mHasher.On("Compare", []byte("test_current_password"), fakeUser.PasswordHash).Return(fakeMetaData, nil)

				mRepo.On("Delete", mock.Anything, 123).Return(nil)
			},
			expectedError: nil,
		},
		{

			name: "Error: password is nil",
			input: service.DeleteAccountInput{
				UserID:          123,
				CurrentPassword: []byte(""),
			},
			setupMocks:    func(mRepo *MockDeleteAccountRepository, mHasher *MockDeleteAccountHasher) {},
			expectedError: domain.ErrInvalidData,
		},
		{

			name: "Error: password is too short",
			input: service.DeleteAccountInput{
				UserID:          123,
				CurrentPassword: []byte("short"),
			},
			setupMocks:    func(mRepo *MockDeleteAccountRepository, mHasher *MockDeleteAccountHasher) {},
			expectedError: domain.ErrInvalidData,
		},
		{

			name: "Error: passwod is too long",
			input: service.DeleteAccountInput{
				UserID:          123,
				CurrentPassword: bytes.Repeat([]byte("a"), 257),
			},
			setupMocks:    func(mRepo *MockDeleteAccountRepository, mHasher *MockDeleteAccountHasher) {},
			expectedError: domain.ErrInvalidData,
		},
		{

			name: "Error: user was not found",
			input: service.DeleteAccountInput{
				UserID:          123,
				CurrentPassword: []byte("test_current_password"),
			},
			setupMocks: func(mRepo *MockDeleteAccountRepository, mHasher *MockDeleteAccountHasher) {
				mRepo.On("GetHashById", mock.Anything, 123).Return(nil, domain.ErrUserNotFound)
			},
			expectedError: domain.ErrUserNotFound,
		},
		{

			name: "Error: wrong password",
			input: service.DeleteAccountInput{
				UserID:          123,
				CurrentPassword: []byte("test_wrong_password"),
			},
			setupMocks: func(mRepo *MockDeleteAccountRepository, mHasher *MockDeleteAccountHasher) {

				fakeUser := domain.RestoreUser(123, "", "", []byte("test_current_password"))
				mRepo.On("GetHashById", mock.Anything, 123).Return(fakeUser, nil)

				mHasher.On("Compare", []byte("test_wrong_password"), fakeUser.PasswordHash).Return(nil, domain.ErrInvalidPassword)
			},
			expectedError: domain.ErrInvalidPassword,
		},
		{

			name: "Error: database internal failure on fetch",
			input: service.DeleteAccountInput{
				UserID:          123,
				CurrentPassword: []byte("test_current_password"),
			},
			setupMocks: func(mRepo *MockDeleteAccountRepository, mHasher *MockDeleteAccountHasher) {
				mRepo.On("GetHashById", mock.Anything, 123).Return(nil, errors.New("databse internal failure on fetch"))
			},
			expectedError: domain.ErrUserNotFound,
		},
		{

			name: "Error: database failure on delete",
			input: service.DeleteAccountInput{
				UserID:          123,
				CurrentPassword: []byte("test_current_password"),
			},
			setupMocks: func(mRepo *MockDeleteAccountRepository, mHasher *MockDeleteAccountHasher) {

				fakeUser := domain.RestoreUser(123, "", "", []byte("test_current_password"))
				mRepo.On("GetHashById", mock.Anything, 123).Return(fakeUser, nil)

				fakeMetaData := &argon2.HashMetaData{Version: 2, Memory: 65536, Iterations: 2, Parallelism: 2}
				mHasher.On("Compare", []byte("test_current_password"), fakeUser.PasswordHash).Return(fakeMetaData, nil)

				mRepo.On("Delete", mock.Anything, 123).Return(domain.ErrInternal)
			},
			expectedError: domain.ErrInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockDeleteAccountRepository)
			mockHasher := new(MockDeleteAccountHasher)

			tt.setupMocks(mockRepo, mockHasher)
			deleteAccountService := NewDeleteAccountService(mockRepo, mockHasher)
			err := deleteAccountService.DeleteAccountFunction(context.Background(), tt.input)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)
			mockHasher.AssertExpectations(t)

		})
	}

}
