package user

import (
	"context"
	"errors"
	"testing"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/service"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)


type MockChangeNameRepository struct{ mock.Mock }
func (m *MockChangeNameRepository) GetForChangeName(ctx context.Context, id int) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}
func (m *MockChangeNameRepository) UpdateName(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}


func TestChangeNameFunction(t *testing.T) {

	tests := []struct{
		name 				string
		input 				service.ChangeNameInput
		setupMocks 			func(mRepo *MockChangeNameRepository)
		expectedError 		error
	}{
		{

			name: "success: name was exchanged",
			input: service.ChangeNameInput{
				ID: 				123,
				CurrentName: 		"test_current_name",
				NewName: 			"test_new_name",
				ConfirmNewName: 	"test_new_name",
			},
			setupMocks: func(mRepo *MockChangeNameRepository) {

				fakeUser := domain.RestoreUser(123, "test_current_name", "", nil)
				mRepo.On("GetForChangeName", mock.Anything, 123).Return(fakeUser, nil)
				mRepo.On("UpdateName", mock.Anything, fakeUser).Return(nil)

			},
			expectedError: nil,

		},
		{

			name: "Error: user was not found",
			input: service.ChangeNameInput{ID: 123},
			setupMocks: func(mRepo *MockChangeNameRepository) {
				mRepo.On("GetForChangeName", mock.Anything, 123).Return(nil, domain.ErrUserNotFound)
			},
			expectedError: domain.ErrUserNotFound,

		},
		{

			name: "Error: domain validation failed (current name does not match record)",
			input: service.ChangeNameInput{
				ID: 				123,
				CurrentName: 		"test_wrong_current_name",
				NewName: 			"test_new_name",
			},
			setupMocks: func(mRepo *MockChangeNameRepository) {
				fakeUser := domain.RestoreUser(123, "test_current_name", "", nil)
				mRepo.On("GetForChangeName", mock.Anything, 123).Return(fakeUser, nil)
			},
			expectedError: domain.ErrInvalidCredentials,
			
		},
		{

			name: "Error: database failure on update",
			input: service.ChangeNameInput{
				ID: 				123,
				CurrentName: 		"test_current_name",
				NewName: 			"test_new_name",
				ConfirmNewName: 	"test_new_name",
			},
			setupMocks: func(mRepo *MockChangeNameRepository) {
				fakeUser := domain.RestoreUser(123, "test_current_name", "", nil)
				mRepo.On("GetForChangeName", mock.Anything, 123).Return(fakeUser, nil)
				mRepo.On("UpdateName", mock.Anything, fakeUser).Return(domain.ErrInternal)
			},
			expectedError: domain.ErrInternal,

		},
		{

			name: "Error: database connection failure on fetch",
			input: service.ChangeNameInput{ID: 123},
			setupMocks: func(mRepo *MockChangeNameRepository) {
				mRepo.On("GetForChangeName", mock.Anything, 123).Return(nil, errors.New("database connection failure on fetch"))
			},
			expectedError: domain.ErrInternal,

		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockChangeNameRepository)

			tt.setupMocks(mockRepo)
			changeNameService := NewChangeNameService(mockRepo)
			err := changeNameService.ChangeNameFunction(context.Background(), tt.input)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)

		})
	}

}