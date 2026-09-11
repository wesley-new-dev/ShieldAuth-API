package user

// Coverage summary:
// NewChangePasswordService: constructor dependency wiring.
// ChangePassword: nil password inputs, short/long passwords, confirmation mismatch,
// malformed sensitive data, repository errors and nil users, empty stored hashes,
// invalid current passwords, hash/update/history dependency errors, success at the
// password length boundaries, zero user ID, and call/argument assertions.
// No path in change_password.go is intentionally uncovered. PasswordHistoryRepo was
// introduced because the service previously depended on a concrete database wrapper.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/security"
	"ShieldAuth-API/internal/security/argon2"
	"ShieldAuth-API/internal/service"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type changePasswordRepoMock struct {
	findFunc    func(context.Context, int) (*domain.User, error)
	updateFunc  func(context.Context, int, []byte) error
	findCalls   int
	updateCalls int
	requestedID int
	updatedID   int
	updatedHash []byte
}

func (m *changePasswordRepoMock) FindById(ctx context.Context, id int) (*domain.User, error) {
	m.findCalls++
	m.requestedID = id
	return m.findFunc(ctx, id)
}

func (m *changePasswordRepoMock) UpdatePasswordHash(ctx context.Context, id int, hash []byte) error {
	m.updateCalls++
	m.updatedID = id
	m.updatedHash = append([]byte(nil), hash...)
	return m.updateFunc(ctx, id, hash)
}

type changePasswordHasherMock struct {
	compareFunc  func([]byte, []byte) (*argon2.HashMetaData, error)
	hashFunc     func([]byte) ([]byte, error)
	compareCalls int
	hashCalls    int
	passwords    [][]byte
	hashes       [][]byte
}

func (m *changePasswordHasherMock) Compare(password, passwordHash []byte) (*argon2.HashMetaData, error) {
	m.compareCalls++
	m.passwords = append(m.passwords, append([]byte(nil), password...))
	m.hashes = append(m.hashes, append([]byte(nil), passwordHash...))
	return m.compareFunc(password, passwordHash)
}

func (m *changePasswordHasherMock) Hash(password []byte) ([]byte, error) {
	m.hashCalls++
	return m.hashFunc(password)
}

func (m *changePasswordHasherMock) NeedsRehash(uint32, uint32, uint8) bool { return false }

type passwordHistoryRepoMock struct {
	createFunc   func(context.Context, int64, []byte) error
	createCalls  int
	userID       int64
	passwordHash []byte
}

func (m *passwordHistoryRepoMock) Create(ctx context.Context, userID int64, passwordHash []byte) error {
	m.createCalls++
	m.userID = userID
	m.passwordHash = append([]byte(nil), passwordHash...)
	return m.createFunc(ctx, userID, passwordHash)
}

func newChangePasswordInput(t *testing.T, userID int, current, next, confirm string) service.ChangePasswordInput {
	t.Helper()
	currentData, err := security.NewSensitiveData([]byte(current))
	require.NoError(t, err)
	newData, err := security.NewSensitiveData([]byte(next))
	require.NoError(t, err)
	confirmData, err := security.NewSensitiveData([]byte(confirm))
	require.NoError(t, err)
	return service.ChangePasswordInput{UserID: userID, CurrentPassword: currentData, NewPassword: newData, ConfirmPassword: confirmData}
}

func defaultChangePasswordUser() *domain.User {
	return &domain.User{Id: 42, PasswordHash: []byte("old-hash")}
}

func TestNewChangePasswordService_Success(t *testing.T) {
	repo := &changePasswordRepoMock{}
	hasher := &changePasswordHasherMock{}
	history := &passwordHistoryRepoMock{}

	serviceUnderTest := NewChangePasswordService(repo, hasher, history)

	require.NotNil(t, serviceUnderTest)
	assert.Same(t, repo, serviceUnderTest.repo)
	assert.Same(t, hasher, serviceUnderTest.hasher)
	assert.Same(t, history, serviceUnderTest.password_history)
}

func TestChangePassword_Scenarios(t *testing.T) {
	tests := []struct {
		name         string
		input        func(*testing.T) service.ChangePasswordInput
		user         *domain.User
		findErr      error
		compareErr   error
		hashResult   []byte
		hashErr      error
		updateErr    error
		historyErr   error
		wantErr      error
		wantEmptyErr bool
		wantCompare  int
		wantHash     int
		wantUpdate   int
		wantHistory  int
	}{
		{name: "Success", input: func(t *testing.T) service.ChangePasswordInput {
			return newChangePasswordInput(t, 42, "current", "newpassword", "newpassword")
		}, user: defaultChangePasswordUser(), hashResult: []byte("new-hash"), wantCompare: 1, wantHash: 1, wantUpdate: 1, wantHistory: 1},
		{name: "SuccessBoundaryLengths", input: func(t *testing.T) service.ChangePasswordInput {
			password := strings.Repeat("n", 256)
			return newChangePasswordInput(t, 0, "current", password, password)
		}, user: &domain.User{Id: 0, PasswordHash: []byte("old")}, hashResult: []byte("boundary-hash"), wantCompare: 1, wantHash: 1, wantUpdate: 1, wantHistory: 1},
		{name: "NilNewPassword", input: func(*testing.T) service.ChangePasswordInput {
			return service.ChangePasswordInput{CurrentPassword: &security.SensitiveData{}, ConfirmPassword: &security.SensitiveData{}}
		}, wantErr: domain.ErrInvalidData},
		{name: "NilConfirmPassword", input: func(t *testing.T) service.ChangePasswordInput {
			input := newChangePasswordInput(t, 42, "current", "newpassword", "newpassword")
			input.ConfirmPassword = nil
			return input
		}, wantErr: domain.ErrInvalidData},
		{name: "NilCurrentPassword", input: func(t *testing.T) service.ChangePasswordInput {
			input := newChangePasswordInput(t, 42, "current", "newpassword", "newpassword")
			input.CurrentPassword = nil
			return input
		}, wantErr: domain.ErrInvalidData},
		{name: "ShortPassword", input: func(t *testing.T) service.ChangePasswordInput {
			return newChangePasswordInput(t, 42, "current", "short", "short")
		}, wantErr: domain.ErrShortPassword},
		{name: "LongPassword", input: func(t *testing.T) service.ChangePasswordInput {
			password := strings.Repeat("l", 257)
			return newChangePasswordInput(t, 42, "current", password, password)
		}, wantErr: domain.ErrLongPassword},
		{name: "ConfirmationMismatch", input: func(t *testing.T) service.ChangePasswordInput {
			return newChangePasswordInput(t, 42, "current", "newpassword", "different")
		}, wantErr: domain.ErrPasswordDoNotMatch},
		{name: "MalformedNewPassword", input: func(t *testing.T) service.ChangePasswordInput {
			input := newChangePasswordInput(t, 42, "current", "newpassword", "newpassword")
			input.NewPassword = &security.SensitiveData{}
			return input
		}, wantEmptyErr: true},
		{name: "MalformedConfirmPassword", input: func(t *testing.T) service.ChangePasswordInput {
			input := newChangePasswordInput(t, 42, "current", "newpassword", "newpassword")
			input.ConfirmPassword = &security.SensitiveData{}
			return input
		}, wantEmptyErr: true},
		{name: "RepositoryError", input: func(t *testing.T) service.ChangePasswordInput {
			return newChangePasswordInput(t, 42, "current", "newpassword", "newpassword")
		}, findErr: errors.New("database unavailable"), wantErr: domain.ErrUserNotFound},
		{name: "NilUser", input: func(t *testing.T) service.ChangePasswordInput {
			return newChangePasswordInput(t, 42, "current", "newpassword", "newpassword")
		}, wantErr: domain.ErrUserNotFound},
		{name: "EmptyStoredHash", input: func(t *testing.T) service.ChangePasswordInput {
			return newChangePasswordInput(t, 42, "current", "newpassword", "newpassword")
		}, user: &domain.User{Id: 42}, wantErr: domain.ErrInvalidCredentials},
		{name: "CurrentPasswordError", input: func(t *testing.T) service.ChangePasswordInput {
			return newChangePasswordInput(t, 42, "wrong", "newpassword", "newpassword")
		}, user: defaultChangePasswordUser(), compareErr: errors.New("invalid current password"), wantErr: domain.ErrInvalidCredentials, wantCompare: 1},
		{name: "MalformedCurrentPassword", input: func(t *testing.T) service.ChangePasswordInput {
			input := newChangePasswordInput(t, 42, "current", "newpassword", "newpassword")
			input.CurrentPassword = &security.SensitiveData{}
			return input
		}, user: defaultChangePasswordUser(), wantEmptyErr: true},
		{name: "HashError", input: func(t *testing.T) service.ChangePasswordInput {
			return newChangePasswordInput(t, 42, "current", "newpassword", "newpassword")
		}, user: defaultChangePasswordUser(), hashErr: errors.New("hash failed"), wantErr: domain.ErrInternal, wantCompare: 1, wantHash: 1},
		{name: "UpdateError", input: func(t *testing.T) service.ChangePasswordInput {
			return newChangePasswordInput(t, 42, "current", "newpassword", "newpassword")
		}, user: defaultChangePasswordUser(), hashResult: []byte("new-hash"), updateErr: errors.New("update failed"), wantErr: domain.ErrInternal, wantCompare: 1, wantHash: 1, wantUpdate: 1},
		{name: "HistoryError", input: func(t *testing.T) service.ChangePasswordInput {
			return newChangePasswordInput(t, 42, "current", "newpassword", "newpassword")
		}, user: defaultChangePasswordUser(), hashResult: []byte("new-hash"), historyErr: errors.New("history failed"), wantErr: domain.ErrInternal, wantCompare: 1, wantHash: 1, wantUpdate: 1, wantHistory: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &changePasswordRepoMock{
				findFunc:   func(context.Context, int) (*domain.User, error) { return tt.user, tt.findErr },
				updateFunc: func(context.Context, int, []byte) error { return tt.updateErr },
			}
			hasher := &changePasswordHasherMock{
				compareFunc: func([]byte, []byte) (*argon2.HashMetaData, error) { return &argon2.HashMetaData{}, tt.compareErr },
				hashFunc:    func([]byte) ([]byte, error) { return tt.hashResult, tt.hashErr },
			}
			history := &passwordHistoryRepoMock{createFunc: func(context.Context, int64, []byte) error { return tt.historyErr }}
			serviceUnderTest := NewChangePasswordService(repo, hasher, history)

			err := serviceUnderTest.ChangePassword(context.Background(), tt.input(t))

			if tt.wantEmptyErr {
				require.Error(t, err)
				assert.Empty(t, err.Error())
			} else if tt.wantErr != nil {
				require.Error(t, err)
				assert.Equal(t, tt.wantErr, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantCompare, hasher.compareCalls)
			assert.Equal(t, tt.wantHash, hasher.hashCalls)
			assert.Equal(t, tt.wantUpdate, repo.updateCalls)
			assert.Equal(t, tt.wantHistory, history.createCalls)
			if tt.wantUpdate > 0 {
				assert.Equal(t, tt.input(t).UserID, repo.updatedID)
				assert.Equal(t, tt.hashResult, repo.updatedHash)
			}
			if tt.wantHistory > 0 {
				assert.Equal(t, tt.user.Id, history.userID)
				assert.Equal(t, tt.hashResult, history.passwordHash)
			}
		})
	}
}

var _ ChangePasswordRepo = (*changePasswordRepoMock)(nil)
var _ PasswordHistoryRepo = (*passwordHistoryRepoMock)(nil)
