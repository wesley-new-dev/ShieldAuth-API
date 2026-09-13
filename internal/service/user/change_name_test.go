package user

// Coverage summary:
// NewChangeNameService: constructor dependency wiring.
// ChangeNameFunction: repository not-found and generic errors, nil user, successful
// rename with whitespace normalization and zero ID, current-name mismatch, unchanged
// name, empty new name, update errors, wrapped errors, and call tracking.
// No path in change_name.go is intentionally uncovered. ChangeNameRepo was introduced
// because the service previously depended on a concrete database wrapper, which could
// not be replaced by a manual unit-test mock.

import (
	"context"
	"errors"
	"testing"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/service"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type changeNameRepoMock struct {
	getFunc     func(context.Context, int) (*domain.User, error)
	updateFunc  func(context.Context, *domain.User) error
	getCalls    int
	updateCalls int
	requestedID int
	updatedUser *domain.User
}

func (m *changeNameRepoMock) GetForChangeName(ctx context.Context, id int) (*domain.User, error) {
	m.getCalls++
	m.requestedID = id
	return m.getFunc(ctx, id)
}

func (m *changeNameRepoMock) UpdateName(ctx context.Context, user *domain.User) error {
	m.updateCalls++
	m.updatedUser = user
	return m.updateFunc(ctx, user)
}

func defaultChangeNameUser() *domain.User {
	return &domain.User{Id: 10, Name: "user-test", Email: "user-test@example.com"}
}

func newChangeNameInput(id int, currentName, newName string) service.ChangeNameInput {
	return service.ChangeNameInput{ID: id, CurrentName: currentName, NewName: newName}
}

func TestNewChangeNameService_Success(t *testing.T) {
	repo := &changeNameRepoMock{}
	serviceUnderTest := NewChangeNameService(repo)

	require.NotNil(t, serviceUnderTest)
	assert.Same(t, repo, serviceUnderTest.repo)
}

func TestChangeNameFunction_Scenarios(t *testing.T) {
	tests := []struct {
		name           string
		input          service.ChangeNameInput
		user           *domain.User
		getErr         error
		updateErr      error
		wantErr        error
		wantID         int
		wantUpdate     bool
		wantUpdateCall bool
		wantName       string
	}{
		{name: "Success", input: newChangeNameInput(10, "user-test", "user"), user: defaultChangeNameUser(), wantID: 10, wantUpdate: true, wantUpdateCall: true, wantName: "user"},
		{name: "SuccessTrimmedNameZeroID", input: newChangeNameInput(0, " user-test ", " user "), user: &domain.User{Name: "user-test"}, wantID: 0, wantUpdate: true, wantUpdateCall: true, wantName: "user"},
		{name: "RepositoryNotFound", input: newChangeNameInput(10, "user-test", "user"), getErr: domain.ErrUserNotFound, wantErr: domain.ErrUserNotFound},
		{name: "RepositoryError", input: newChangeNameInput(10, "user-test", "user"), getErr: errors.New("database unavailable"), wantErr: domain.ErrInternal},
		{name: "NilUser", input: newChangeNameInput(10, "user-test", "user"), wantErr: domain.ErrUserNotFound},
		{name: "CurrentNameMismatch", input: newChangeNameInput(10, "Other", "user"), user: defaultChangeNameUser(), wantErr: domain.ErrNameIsTheSame},
		{name: "NameUnchanged", input: newChangeNameInput(10, "user-test", "user-test"), user: defaultChangeNameUser(), wantErr: domain.ErrNameIsTheSame},
		{name: "EmptyNewName", input: newChangeNameInput(10, "user-test", ""), user: defaultChangeNameUser(), wantErr: domain.ErrInvalidCredentials},
		{name: "UpdateError", input: newChangeNameInput(10, "user-test", "user"), user: defaultChangeNameUser(), updateErr: errors.New("update failed"), wantErr: domain.ErrInternal, wantUpdateCall: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &changeNameRepoMock{
				getFunc:    func(context.Context, int) (*domain.User, error) { return tt.user, tt.getErr },
				updateFunc: func(context.Context, *domain.User) error { return tt.updateErr },
			}
			serviceUnderTest := NewChangeNameService(repo)

			err := serviceUnderTest.ChangeNameFunction(context.Background(), tt.input)

			if tt.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, 1, repo.getCalls)
			assert.Equal(t, tt.input.ID, repo.requestedID)
			if tt.wantUpdateCall {
				assert.Equal(t, 1, repo.updateCalls)
				if tt.wantUpdate {
					assert.Equal(t, tt.wantName, repo.updatedUser.Name)
				}
			} else {
				assert.Equal(t, 0, repo.updateCalls)
			}
		})
	}
}

var _ ChangeNameRepo = (*changeNameRepoMock)(nil)
