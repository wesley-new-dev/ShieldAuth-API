package auth

import (
	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/service"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)


type MockLogOutRepository struct{ mock.Mock }
func (m *MockLogOutRepository) Revoke(ctx context.Context, token_hash []byte) error {
	args := m.Called(ctx, token_hash)
	return args.Error(0)
}


func TestLogOutFunction(t *testing.T) {

	testToken := []byte("test_refresh_token")
	expectedHash := sha256.Sum256(testToken)
	
	tests := []struct {
		name 				string
		setupMocks 			func(mRepo *MockLogOutRepository)
		expectedError 		error
		
	}{
		{

			name: "successful logout",
			setupMocks: func(mRepo *MockLogOutRepository) {
				mRepo.On("Revoke", mock.Anything, expectedHash[:]).Return(nil)
			},
			expectedError: nil,

		},
		{

			name: "Error: repository failure",
			setupMocks: func(mRepo *MockLogOutRepository) {
				mRepo.On("Revoke", mock.Anything, []byte("test_token_hash")).Return(errors.New("database connection failure"))
			},
			expectedError: errors.New("database connection failure"),

		},
		{

			name: "Error: token not found or already revoked",
			setupMocks: func(mRepo *MockLogOutRepository) {
				mRepo.On("Revoke", mock.Anything, expectedHash[:]).Return(domain.ErrNotFound)
			},
			expectedError: domain.ErrNotFound,

		},

	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockLogOutRepository)

			tt.setupMocks(mockRepo)
			logOutService := NewLogOutService(mockRepo)
			input := service.LogOutInput{
				RefreshToken: testToken,
			}
			err := logOutService.LogOutFunction(context.Background(), input)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)
		})
	}

}