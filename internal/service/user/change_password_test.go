package user

import (
	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/security/argon2"
	"ShieldAuth-API/internal/security/hibp"
	"ShieldAuth-API/internal/service"
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockChangePasswordRepository struct{ mock.Mock }

func (m *MockChangePasswordRepository) FindById(ctx context.Context, id int) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}
func (m *MockChangePasswordRepository) UpdatePasswordHash(ctx context.Context, id int, hash []byte) error {
	args := m.Called(ctx, id, hash)
	return args.Error(0)
}

type MockChangePasswordHasher struct{ mock.Mock }

func (m *MockChangePasswordHasher) Hash(password []byte) ([]byte, error) {
	args := m.Called(password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}
func (m *MockChangePasswordHasher) Compare(password []byte, passwordHash []byte) (*argon2.HashMetaData, error) {
	args := m.Called(password, passwordHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*argon2.HashMetaData), args.Error(1)
}

func (m *MockChangePasswordHasher) NeedsRehash(memory uint32, iterations uint32, parallelism uint8) bool {
	args := m.Called(memory, iterations, parallelism)
	return args.Bool(0)
}

func TestChangePassword(t *testing.T) {

	tests := []struct {
		name          string
		input         service.ChangePasswordInput
		setupMocks    func(mRepo *MockChangePasswordRepository, mHasher *MockChangePasswordHasher)
		expectedError error
	}{
		{

			name: "success: password was exchanged",
			input: service.ChangePasswordInput{
				UserID:          123,
				CurrentPassword: []byte("test_current_password"),
				NewPassword:     []byte("test_new_password"),
				ConfirmPassword: []byte("test_new_password"),
			},
			setupMocks: func(mRepo *MockChangePasswordRepository, mHasher *MockChangePasswordHasher) {
				fakeUser := domain.RestoreUser(123, "", "", []byte("test_new_password"))
				mRepo.On("FindById", mock.Anything, 123).Return(fakeUser, nil)

				fakeMetaData := &argon2.HashMetaData{Version: 2, Memory: 65536, Iterations: 2, Parallelism: 2}
				mHasher.On("Compare", []byte("test_current_password"), fakeUser.PasswordHash).Return(fakeMetaData, nil)
				mHasher.On("Hash", []byte("test_new_password")).Return([]byte("hashed_password"), nil)

				mRepo.On("UpdatePasswordHash", mock.Anything, 123, []byte("hashed_password")).Return(nil)
			},
			expectedError: nil,
		},
		{

			name: "Error: password too short",
			input: service.ChangePasswordInput{
				UserID:          123,
				CurrentPassword: []byte("test_current_password"),
				NewPassword:     []byte("short"),
				ConfirmPassword: []byte("short"),
			},
			setupMocks:    func(mRepo *MockChangePasswordRepository, mHasher *MockChangePasswordHasher) {},
			expectedError: domain.ErrShortPassword,
		},
		{

			name: "Error: password too long",
			input: service.ChangePasswordInput{
				UserID:          123,
				CurrentPassword: []byte("test_current_password"),
				NewPassword:     bytes.Repeat([]byte("a"), 257),
				ConfirmPassword: bytes.Repeat([]byte("a"), 257),
			},
			setupMocks:    func(mRepo *MockChangePasswordRepository, mHasher *MockChangePasswordHasher) {},
			expectedError: domain.ErrLongPassword,
		},
		{

			name: "Error: password do not match",
			input: service.ChangePasswordInput{
				UserID:          123,
				CurrentPassword: []byte("test_current_password"),
				NewPassword:     []byte("test_new_password"),
				ConfirmPassword: []byte("test_different_new_password"),
			},
			setupMocks:    func(mRepo *MockChangePasswordRepository, mHasher *MockChangePasswordHasher) {},
			expectedError: domain.ErrPasswordDoNotMatch,
		},
		{

			name: "Error: user not found",
			input: service.ChangePasswordInput{
				UserID:          123,
				CurrentPassword: []byte("test_current_password"),
				NewPassword:     []byte("test_new_password"),
				ConfirmPassword: []byte("test_new_password"),
			},
			setupMocks: func(mRepo *MockChangePasswordRepository, mHasher *MockChangePasswordHasher) {
				mRepo.On("FindById", mock.Anything, 123).Return(nil, domain.ErrUserNotFound)
			},
			expectedError: domain.ErrUserNotFound,
		},
		{

			name: "Error: password hash is nil",
			input: service.ChangePasswordInput{
				UserID:          123,
				CurrentPassword: []byte("test_current_password"),
				NewPassword:     []byte("test_new_password"),
				ConfirmPassword: []byte("test_new_password"),
			},
			setupMocks: func(mRepo *MockChangePasswordRepository, mHasher *MockChangePasswordHasher) {
				fakeUser := domain.RestoreUser(123, "", "", []byte(""))
				mRepo.On("FindById", mock.Anything, 123).Return(fakeUser, nil)
			},
			expectedError: domain.ErrInvalidCredentials,
		},
		{

			name: "Error: wrong password",
			input: service.ChangePasswordInput{
				UserID:          123,
				CurrentPassword: []byte("test_wrong_current_password"),
				NewPassword:     []byte("test_new_password"),
				ConfirmPassword: []byte("test_new_password"),
			},
			setupMocks: func(mRepo *MockChangePasswordRepository, mHasher *MockChangePasswordHasher) {
				fakeUser := domain.RestoreUser(123, "", "", []byte("test_hashed_current_password"))
				mRepo.On("FindById", mock.Anything, 123).Return(fakeUser, nil)

				mHasher.On("Compare", []byte("test_wrong_current_password"), fakeUser.PasswordHash).Return(nil, domain.ErrInvalidCredentials)
			},
			expectedError: domain.ErrInvalidCredentials,
		},
		{

			name: "Error: hash did not happen",
			input: service.ChangePasswordInput{
				UserID:          123,
				CurrentPassword: []byte("test_current_password"),
				NewPassword:     []byte("test_new_password"),
				ConfirmPassword: []byte("test_new_password"),
			},
			setupMocks: func(mRepo *MockChangePasswordRepository, mHasher *MockChangePasswordHasher) {
				fakeUser := domain.RestoreUser(123, "", "", []byte("test_new_password"))
				mRepo.On("FindById", mock.Anything, 123).Return(fakeUser, nil)

				fakeMetaData := &argon2.HashMetaData{Version: 2, Memory: 65536, Iterations: 2, Parallelism: 2}
				mHasher.On("Compare", []byte("test_current_password"), fakeUser.PasswordHash).Return(fakeMetaData, nil)
				mHasher.On("Hash", []byte("test_new_password")).Return(nil, domain.ErrInternal)
			},
			expectedError: domain.ErrInternal,
		},
		{

			name: "database failure on update",
			input: service.ChangePasswordInput{
				UserID:          123,
				CurrentPassword: []byte("test_current_password"),
				NewPassword:     []byte("test_new_password"),
				ConfirmPassword: []byte("test_new_password"),
			},
			setupMocks: func(mRepo *MockChangePasswordRepository, mHasher *MockChangePasswordHasher) {
				fakeUser := domain.RestoreUser(123, "", "", []byte("test_hashed_current_password"))
				mRepo.On("FindById", mock.Anything, 123).Return(fakeUser, nil)

				fakeMetaData := &argon2.HashMetaData{Version: 2, Memory: 65536, Iterations: 2, Parallelism: 2}
				mHasher.On("Compare", []byte("test_current_password"), fakeUser.PasswordHash).Return(fakeMetaData, nil)
				mHasher.On("Hash", []byte("test_new_password")).Return([]byte("hashed_new_password"), nil)

				mRepo.On("UpdatePasswordHash", mock.Anything, 123, []byte("hashed_new_password")).Return(domain.ErrInternal)
			},
			expectedError: domain.ErrInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockChangePasswordRepository)
			mockHasher := new(MockChangePasswordHasher)

			tt.setupMocks(mockRepo, mockHasher)
			changePasswordService := NewChangePasswordService(mockRepo, mockHasher, hibp.HIBPChecker{})
			err := changePasswordService.ChangePassword(context.Background(), tt.input)

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
