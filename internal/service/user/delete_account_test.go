package user

// Coverage summary:
// NewDeleteAccountService: constructor dependency wiring.
// DeleteAccountFunction: repository errors and nil users, nil and malformed passwords,
// password lengths below/at/above the limits, invalid password comparisons, successful
// deletion with zero ID, deletion errors, and dependency call/argument assertions.
// No path in delete_account.go is intentionally uncovered. DeleteAccountRepo and the
// Argon2 hasher already expose interfaces, so no dependency refactoring was required.

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

type deleteAccountRepoMock struct {
	getFunc     func(context.Context, int) (*domain.User, error)
	deleteFunc  func(context.Context, int) error
	getCalls    int
	deleteCalls int
	requestedID int
	deletedID   int
}

func (m *deleteAccountRepoMock) GetHashById(ctx context.Context, id int) (*domain.User, error) {
	m.getCalls++
	m.requestedID = id
	return m.getFunc(ctx, id)
}

func (m *deleteAccountRepoMock) Delete(ctx context.Context, id int) error {
	m.deleteCalls++
	m.deletedID = id
	return m.deleteFunc(ctx, id)
}

type deleteAccountHasherMock struct {
	compareFunc  func([]byte, []byte) (*argon2.HashMetaData, error)
	compareCalls int
	passwords    [][]byte
	hashes       [][]byte
}

func (m *deleteAccountHasherMock) Compare(password, passwordHash []byte) (*argon2.HashMetaData, error) {
	m.compareCalls++
	m.passwords = append(m.passwords, append([]byte(nil), password...))
	m.hashes = append(m.hashes, append([]byte(nil), passwordHash...))
	return m.compareFunc(password, passwordHash)
}

func (m *deleteAccountHasherMock) Hash([]byte) ([]byte, error)            { return nil, nil }
func (m *deleteAccountHasherMock) NeedsRehash(uint32, uint32, uint8) bool { return false }

func newDeleteAccountInput(t *testing.T, id int, password string) service.DeleteAccountInput {
	t.Helper()
	sensitive, err := security.NewSensitiveData([]byte(password))
	require.NoError(t, err)
	return service.DeleteAccountInput{ID: id, Password: sensitive}
}

func defaultDeleteAccountUser() *domain.User {
	return &domain.User{Id: 42, PasswordHash: []byte("stored-password-hash")}
}

func TestNewDeleteAccountService_Success(t *testing.T) {
	repo := &deleteAccountRepoMock{}
	hasher := &deleteAccountHasherMock{}

	serviceUnderTest := NewDeleteAccountService(repo, hasher)

	require.NotNil(t, serviceUnderTest)
	assert.Same(t, repo, serviceUnderTest.repo)
	assert.Same(t, hasher, serviceUnderTest.hasher)
}

func TestDeleteAccountFunction_Scenarios(t *testing.T) {
	tests := []struct {
		name         string
		input        func(*testing.T) service.DeleteAccountInput
		user         *domain.User
		getErr       error
		compareErr   error
		deleteErr    error
		wantErr      error
		wantEmptyErr bool
		wantCompare  int
		wantDelete   int
	}{
		{name: "Success", input: func(t *testing.T) service.DeleteAccountInput { return newDeleteAccountInput(t, 42, "correct-password") }, user: defaultDeleteAccountUser(), wantCompare: 1, wantDelete: 1},
		{name: "SuccessBoundaryLengthEightZeroID", input: func(t *testing.T) service.DeleteAccountInput { return newDeleteAccountInput(t, 0, "12345678") }, user: &domain.User{Id: 0, PasswordHash: []byte("hash")}, wantCompare: 1, wantDelete: 1},
		{name: "SuccessBoundaryLength256", input: func(t *testing.T) service.DeleteAccountInput {
			return newDeleteAccountInput(t, 42, strings.Repeat("p", 256))
		}, user: defaultDeleteAccountUser(), wantCompare: 1, wantDelete: 1},
		{name: "RepositoryError", input: func(t *testing.T) service.DeleteAccountInput { return newDeleteAccountInput(t, 42, "correct-password") }, getErr: errors.New("database unavailable"), wantErr: domain.ErrUserNotFound},
		{name: "NilUser", input: func(t *testing.T) service.DeleteAccountInput { return newDeleteAccountInput(t, 42, "correct-password") }, wantErr: domain.ErrUserNotFound},
		{name: "NilPassword", input: func(*testing.T) service.DeleteAccountInput { return service.DeleteAccountInput{ID: 42} }, user: defaultDeleteAccountUser(), wantErr: domain.ErrInvalidData},
		{name: "MalformedPassword", input: func(*testing.T) service.DeleteAccountInput {
			return service.DeleteAccountInput{ID: 42, Password: &security.SensitiveData{}}
		}, user: defaultDeleteAccountUser(), wantEmptyErr: true},
		{name: "ShortPassword", input: func(t *testing.T) service.DeleteAccountInput { return newDeleteAccountInput(t, 42, "1234567") }, user: defaultDeleteAccountUser(), wantErr: domain.ErrInvalidData},
		{name: "LongPassword", input: func(t *testing.T) service.DeleteAccountInput {
			return newDeleteAccountInput(t, 42, strings.Repeat("l", 257))
		}, user: defaultDeleteAccountUser(), wantErr: domain.ErrInvalidData},
		{name: "InvalidPassword", input: func(t *testing.T) service.DeleteAccountInput { return newDeleteAccountInput(t, 42, "wrong-password") }, user: defaultDeleteAccountUser(), compareErr: errors.New("comparison failed"), wantErr: domain.ErrInvalidPassword, wantCompare: 1},
		{name: "DeleteError", input: func(t *testing.T) service.DeleteAccountInput { return newDeleteAccountInput(t, 42, "correct-password") }, user: defaultDeleteAccountUser(), deleteErr: errors.New("delete failed"), wantErr: domain.ErrInternal, wantCompare: 1, wantDelete: 1},
		{name: "EmptyStoredHash", input: func(t *testing.T) service.DeleteAccountInput { return newDeleteAccountInput(t, 42, "correct-password") }, user: &domain.User{Id: 42}, wantCompare: 1, wantDelete: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &deleteAccountRepoMock{
				getFunc:    func(context.Context, int) (*domain.User, error) { return tt.user, tt.getErr },
				deleteFunc: func(context.Context, int) error { return tt.deleteErr },
			}
			hasher := &deleteAccountHasherMock{compareFunc: func([]byte, []byte) (*argon2.HashMetaData, error) {
				return &argon2.HashMetaData{}, tt.compareErr
			}}
			serviceUnderTest := NewDeleteAccountService(repo, hasher)

			err := serviceUnderTest.DeleteAccountFunction(context.Background(), tt.input(t))

			if tt.wantEmptyErr {
				require.Error(t, err)
				assert.Empty(t, err.Error())
			} else if tt.wantErr != nil {
				require.Error(t, err)
				assert.Equal(t, tt.wantErr, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, 1, repo.getCalls)
			assert.Equal(t, tt.input(t).ID, repo.requestedID)
			assert.Equal(t, tt.wantCompare, hasher.compareCalls)
			assert.Equal(t, tt.wantDelete, repo.deleteCalls)
			if tt.wantDelete > 0 {
				assert.Equal(t, tt.input(t).ID, repo.deletedID)
			}
		})
	}
}

var _ DeleteAccountRepo = (*deleteAccountRepoMock)(nil)
