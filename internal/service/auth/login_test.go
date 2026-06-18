package auth

import (
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


type MockLoginRepository struct{ mock.Mock }
func (m *MockLoginRepository) GetByIdentifier(ctx context.Context, identifier string) (*domain.User, error) {
	args := m.Called(ctx, identifier)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}
func (m *MockLoginRepository) Rehash(ctx context.Context, id int64, hash []byte) error {
	args := m.Called(ctx, id, hash)
	return args.Error(0)
}
func (m *MockLoginRepository) SaveRefreshToken(ctx context.Context, model domain.RefreshToken) error {
	args := m.Called(ctx, model)
	return args.Error(0)
}


type MockLoginHasher struct{ mock.Mock }
func (m *MockLoginHasher) Compare(password, password_hash []byte) (*argon2.HashMetaData, error) {
	args := m.Called(password, password_hash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*argon2.HashMetaData), args.Error(1)
}
func (m *MockLoginHasher) NeedsRehash(memory uint32, iterations uint32, parallelism uint8) bool {
	args := m.Called(memory, iterations, parallelism)
	return args.Bool(0)
}
func (m *MockLoginHasher) Hash(password []byte) ([]byte, error) {
	args := m.Called(password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}


func TestLoginFunction(t *testing.T) {

	tests := []struct {
		name 				string
		input 				service.LoginInput
		setupMocks 			func(mRepo *MockLoginRepository, mHasher *MockLoginHasher)
		expectedId 			int64
		expectedError 		error

	}{

		{

			name: "successful login",
			setupMocks: func(mRepo *MockLoginRepository, mHasher *MockLoginHasher) {

				fakeUser := &domain.User{Id: 123, Name: "test_name", Email: " test_email@example.com", PasswordHash: []byte("test_password")}
				mRepo.On("GetByIdentifier", mock.Anything, mock.Anything).Return(fakeUser, nil)

				fakeMetaData := &argon2.HashMetaData{
					Version: 		19,
					Memory: 		65536,
					Iterations: 	3,
					Parallelism: 	2,
				}

				mHasher.On("Compare", []byte("test_password"), fakeUser.PasswordHash).Return(fakeMetaData, nil)
				mHasher.On("NeedsRehash", uint32(65536), uint32(3), uint8(2)).Return(false)
			},
			expectedId: 123,
			expectedError: nil,

		},
		{

			name: "successful login using email",
			input: service.LoginInput{
				Name: 		"",
				Email: 		"test_email@example.com",
				Password: 	[]byte("test_password"),
			},
			setupMocks: func(mRepo *MockLoginRepository, mHasher *MockLoginHasher) {
				fakeUser := &domain.User{Id: 123, PasswordHash: []byte("test_hash")}
				mRepo.On("GetByIdentifier", mock.Anything, "test_email@example.com").Return(fakeUser, nil)

				fakeMetaData := &argon2.HashMetaData{
					Version: 		19,
					Memory: 		65536,
					Iterations: 	3,
					Parallelism: 	2,
				}

				mHasher.On("Compare", []byte("test_password"), fakeUser.PasswordHash).Return(fakeMetaData, nil)
				mHasher.On("NeedsRehash", mock.Anything, mock.Anything, mock.Anything).Return(false)
			},
			expectedId: 123,
			expectedError: nil,

		},
		{

			name: "successful login using name",
			input: service.LoginInput{
				Name: 		"test_name",
				Email: 		"",
				Password: 	[]byte("test_password"),
			},
			setupMocks: func(mRepo *MockLoginRepository, mHasher *MockLoginHasher) {
				fakeUser := &domain.User{Id: 123, PasswordHash: []byte("test_hash")}
				mRepo.On("GetByIdentifer", mock.Anything, "test_name").Return(fakeUser, nil)

				fakeMetaData := &argon2.HashMetaData{
					Version: 		19,
					Memory: 		65536,
					Iterations: 	3,
					Parallelism: 	2,
				}

				mHasher.On("Compare", []byte("test_password"), fakeUser.PasswordHash).Return(fakeMetaData, nil)
				mHasher.On("NeedsRehash", mock.Anything, mock.Anything, mock.Anything).Return(false)
			},
			expectedId: 123,
			expectedError: nil,

		},
		{

			name: "Error: invalid credentials",
			setupMocks: func(mRepo *MockLoginRepository, mHasher *MockLoginHasher) {
				mRepo.On("GetByIdentifier", mock.Anything, mock.Anything).Return(nil, domain.ErrInvalidCredentials)
				mHasher.On("Compare", []byte("test_password"), dummyArgon2Hash).Return(nil, domain.ErrInvalidCredentials)
			},
			expectedId: 0,
			expectedError: domain.ErrInvalidCredentials,

		},
		{

			name: "rehash password",
			setupMocks: func(mRepo *MockLoginRepository, mHasher *MockLoginHasher) {

				fakeUser := &domain.User{Id: 123, Name: "test_name", Email: " test_email@example.com", PasswordHash: []byte("test_password")}
				mRepo.On("GetByIdentifier", mock.Anything, mock.Anything).Return(fakeUser, nil)

				fakeMetaData := &argon2.HashMetaData{
					Version: 		19,
					Memory: 		65536,
					Iterations: 	3,
					Parallelism: 	2,
				}

				mHasher.On("Compare", []byte("test_password"), fakeUser.PasswordHash).Return(fakeMetaData, nil)
				mHasher.On("NeedsRehash", uint32(65536), uint32(3), uint8(2)).Return(true)
				mHasher.On("Hash", []byte("test_password")).Return([]byte("new_hash"), nil)
				mRepo.On("Rehash", mock.Anything, int64(123), []byte("new_hash")).Return(nil)
			},
			expectedId: 123,
			expectedError: nil,

		},
		{

			name: "Error: rehash failed",
			setupMocks: func(mRepo *MockLoginRepository, mHasher *MockLoginHasher) {

				fakeUser := &domain.User{Id: 123, Name: "test_name", Email: " test_email@example.com", PasswordHash: []byte("test_password")}
				mRepo.On("GetByIdentifier", mock.Anything, mock.Anything).Return(fakeUser, nil)

				fakeMetaData := &argon2.HashMetaData{
					Version: 		19,
					Memory: 		65536,
					Iterations: 	3,
					Parallelism: 	2,
				}

				mHasher.On("Compare", []byte("test_password"), fakeUser.PasswordHash).Return(fakeMetaData, nil)
				mHasher.On("NeedsRehash", uint32(65536), uint32(3), uint8(2)).Return(true)	
				mHasher.On("Hash", []byte("test_password")).Return(nil, errors.New("hasher internal error"))
			},
			expectedId: 123,
			expectedError: nil,

		},	
		{
			name: "Error: fetching user",
			setupMocks: func(mRepo *MockLoginRepository, mHasher *MockLoginHasher) {

				fakeUser := &domain.User{Id: 123, Name: "test_name", Email: " test_email@example.com", PasswordHash: []byte("test_password")}
				mRepo.On("GetByIdentifier", mock.Anything, mock.Anything).Return(fakeUser, errors.New("database connection down"))

				fakeMetaData := &argon2.HashMetaData{
					Version: 		19,
					Memory: 		65536,
					Iterations: 	3,
					Parallelism: 	2,
				}

				mHasher.On("Compare", []byte("test_password"), dummyArgon2Hash).Return(fakeMetaData, domain.ErrInvalidCredentials)
			},
			expectedId: 0,
			expectedError: domain.ErrInvalidCredentials,

		},
		{

			name: "Error: context cancelled after database fetch",
			setupMocks: func(mRepo *MockLoginRepository, mHasher *MockLoginHasher) {
				fakeUser := &domain.User{Id: 123, PasswordHash: []byte("test_hash")}
				mRepo.On("GetByIdentifier", mock.Anything, mock.Anything).Return(fakeUser, nil)
			},
			expectedId: 0,
			expectedError: context.Canceled,

		},

	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockLoginRepository)
			mockHasher := new(MockLoginHasher)

			tt.setupMocks(mockRepo, mockHasher)
			loginService := NewLoginService(mockRepo, mockHasher)
			id, err := loginService.VerifyLoginFunction(context.Background(), tt.input)

			assert.Equal(t, tt.expectedId, id)
			
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)
			mockHasher.AssertExpectations(t)
		})
	}

}


func TestCreateRefreshToken(t *testing.T) {

	tests := []struct {
		name 			string
		setupMocks 		func(mRepo *MockLoginRepository)
		expectedError 	error
		expectToken 	bool
	}{
		{

			name: "token created successfully",
			setupMocks: func(mRepo *MockLoginRepository) {
				mRepo.On("SaveRefreshToken", mock.Anything, mock.MatchedBy(func(model domain.RefreshToken) bool {
					return model.UserID == 123 && model.Token != ""
				})).Return(nil)
			},
			expectedError: 	nil,
			expectToken: 	true,

		},
		{

			name: "Error: database connection failed",
			setupMocks: func(mRepo *MockLoginRepository) {
				mRepo.On("SaveRefreshToken", mock.Anything, mock.Anything).Return(errors.New("database connection failed"))
			},
			expectedError: 	errors.New("database connection failed"),
			expectToken: 	false,

		},
		{

			name: "Error: repository returns domain error",
			setupMocks: func(mRepo *MockLoginRepository) {
				mRepo.On("SaveRefreshToken", mock.Anything, mock.Anything).Return(domain.ErrNotFound)
			},
			expectedError: 	domain.ErrNotFound,
			expectToken: 	false,

		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockLoginRepository)

			tt.setupMocks(mockRepo)
			service := NewLoginService(mockRepo, nil)
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