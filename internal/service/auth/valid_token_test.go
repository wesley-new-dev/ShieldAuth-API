package auth

import (
	"ShieldAuth-API/internal/domain"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockResetStore struct{ mock.Mock }

func (m *MockResetStore) Get(ctx context.Context, token string) (string, error) {
	args := m.Called(ctx, token)
	return args.String(0), args.Error(1)
}

func (m *MockResetStore) Delete(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockResetStore) Save(ctx context.Context, token string, value int64, expiration time.Duration) error {
	args := m.Called(ctx, token, value, expiration)
	return args.Error(0)
}

func TestValidToken(t *testing.T) {

	tests := []struct {
		name          string
		token         string
		setupMocks    func(mStore *MockResetStore)
		expectedError error
	}{
		{

			name:  "success: token is valid",
			token: "test_valid_token_123",
			setupMocks: func(mStore *MockResetStore) {
				mStore.On("Get", mock.Anything, "test_valid_token_123").Return("42", nil)
			},
			expectedError: nil,
		},
		{

			name:          "Error: token is empty string",
			token:         "",
			setupMocks:    func(mStore *MockResetStore) {},
			expectedError: domain.ErrInvalidToken,
		},
		{

			name:  "Error: token not found in store or store failed",
			token: "test_expired_or_missing_token",
			setupMocks: func(mStore *MockResetStore) {
				mStore.On("Get", mock.Anything, "test_expired_or_missing_token").Return("", errors.New("redis: nil"))
			},
			expectedError: domain.ErrInvalidToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := new(MockResetStore)

			// prepare mocks for this test case
			tt.setupMocks(mockStore)

			validTokenService := NewValidToken(mockStore)
			err := validTokenService.ValidToken(context.Background(), tt.token)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Error(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}

			mockStore.AssertExpectations(t)

		})
	}

}
