package user

// Coverage summary:
// NewChangeEmailService: constructor dependency wiring.
// ChangeEmailFunction: repository success/error/nil user, nil and malformed passwords,
// valid and invalid password comparisons, current-email mismatch, confirmation mismatch,
// unchanged email, invalid email, update errors, successful updates with empty user-agent
// and zero user ID, audit success, and audit errors.
// No path in change_email.go is intentionally uncovered. Nil user and nil password guards
// were added so invalid inputs return errors instead of causing a nil-pointer panic.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/repository"
	"ShieldAuth-API/internal/security"
	"ShieldAuth-API/internal/security/argon2"
	"ShieldAuth-API/internal/service"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type changeEmailRepoMock struct {
	getFunc     func(context.Context, int) (*domain.User, error)
	updateFunc  func(context.Context, *domain.User) error
	getCalls    int
	updateCalls int
	requestedID int
	updatedUser *domain.User
}

func (m *changeEmailRepoMock) GetID(ctx context.Context, id int) (*domain.User, error) {
	m.getCalls++
	m.requestedID = id
	return m.getFunc(ctx, id)
}

func (m *changeEmailRepoMock) UpdateEmail(ctx context.Context, user *domain.User) error {
	m.updateCalls++
	m.updatedUser = user
	return m.updateFunc(ctx, user)
}

type changeEmailHasherMock struct {
	compareFunc  func([]byte, []byte) (*argon2.HashMetaData, error)
	compareCalls int
	passwords    [][]byte
	hashes       [][]byte
}

func (m *changeEmailHasherMock) Compare(password, passwordHash []byte) (*argon2.HashMetaData, error) {
	m.compareCalls++
	m.passwords = append(m.passwords, append([]byte(nil), password...))
	m.hashes = append(m.hashes, append([]byte(nil), passwordHash...))
	return m.compareFunc(password, passwordHash)
}

func (m *changeEmailHasherMock) Hash([]byte) ([]byte, error)            { return nil, nil }
func (m *changeEmailHasherMock) NeedsRehash(uint32, uint32, uint8) bool { return false }

type changeEmailAuditMock struct {
	createFunc  func(context.Context, repository.AccountEventAudit) error
	createCalls int
	events      []repository.AccountEventAudit
	done        chan struct{}
	once        sync.Once
}

func (m *changeEmailAuditMock) CreateEvent(ctx context.Context, event repository.AccountEventAudit) error {
	m.createCalls++
	m.events = append(m.events, event)
	if m.done != nil {
		m.once.Do(func() { close(m.done) })
	}
	if m.createFunc != nil {
		return m.createFunc(ctx, event)
	}
	return nil
}

func newChangeEmailInput(t *testing.T, current, next, confirmation, password string) service.ChangeEmailInput {
	t.Helper()
	sensitive, err := security.NewSensitiveData([]byte(password))
	require.NoError(t, err)
	return service.ChangeEmailInput{
		ID:              42,
		CurrentEmail:    current,
		NewEmail:        next,
		ConfirmNewEmail: confirmation,
		Password:        sensitive,
	}
}

func defaultChangeEmailUser() *domain.User {
	return &domain.User{Id: 42, Name: "Alice", Email: "old@example.com", PasswordHash: []byte("password-hash")}
}

func TestNewChangeEmailService_Success(t *testing.T) {
	repo := &changeEmailRepoMock{}
	hasher := &changeEmailHasherMock{}
	audit := &changeEmailAuditMock{}

	serviceUnderTest := NewChangeEmailService(repo, hasher, audit)

	require.NotNil(t, serviceUnderTest)
	assert.Same(t, repo, serviceUnderTest.repo)
	assert.Same(t, hasher, serviceUnderTest.hasher)
	assert.Same(t, audit, serviceUnderTest.audit_trail)
}

func TestChangeEmailFunction_Scenarios(t *testing.T) {
	tests := []struct {
		name           string
		input          func(*testing.T) service.ChangeEmailInput
		user           *domain.User
		repoErr        error
		compareErr     error
		updateErr      error
		auditErr       error
		userAgent      string
		wantErr        error
		wantEmptyErr   bool
		wantUpdate     bool
		wantUpdateCall bool
	}{
		{name: "Success", input: func(t *testing.T) service.ChangeEmailInput {
			return newChangeEmailInput(t, "old@example.com", "new@example.com", "new@example.com", "correct")
		}, user: defaultChangeEmailUser(), userAgent: "browser", wantUpdate: true},
		{name: "SuccessEmptyAgentZeroID", input: func(t *testing.T) service.ChangeEmailInput {
			input := newChangeEmailInput(t, "old@example.com", "new@example.com", "new@example.com", "correct")
			input.ID = 0
			return input
		}, user: &domain.User{Email: "old@example.com", PasswordHash: []byte("hash")}, wantUpdate: true},
		{name: "RepositoryError", input: func(t *testing.T) service.ChangeEmailInput {
			return newChangeEmailInput(t, "old@example.com", "new@example.com", "new@example.com", "correct")
		}, repoErr: errors.New("database unavailable"), wantErr: domain.ErrUserNotFound},
		{name: "NilUser", input: func(t *testing.T) service.ChangeEmailInput {
			return newChangeEmailInput(t, "old@example.com", "new@example.com", "new@example.com", "correct")
		}, wantErr: domain.ErrUserNotFound},
		{name: "NilPassword", input: func(*testing.T) service.ChangeEmailInput {
			return service.ChangeEmailInput{ID: 42, CurrentEmail: "old@example.com", NewEmail: "new@example.com", ConfirmNewEmail: "new@example.com"}
		}, user: defaultChangeEmailUser(), wantErr: domain.ErrInvalidData},
		{name: "MalformedPassword", input: func(*testing.T) service.ChangeEmailInput {
			return service.ChangeEmailInput{ID: 42, CurrentEmail: "old@example.com", NewEmail: "new@example.com", ConfirmNewEmail: "new@example.com", Password: &security.SensitiveData{}}
		}, user: defaultChangeEmailUser(), wantEmptyErr: true},
		{name: "InvalidPassword", input: func(t *testing.T) service.ChangeEmailInput {
			return newChangeEmailInput(t, "old@example.com", "new@example.com", "new@example.com", "wrong")
		}, user: defaultChangeEmailUser(), compareErr: domain.ErrInvalidCredentials, wantErr: domain.ErrInvalidPassword},
		{name: "CurrentEmailMismatch", input: func(t *testing.T) service.ChangeEmailInput {
			return newChangeEmailInput(t, "other@example.com", "new@example.com", "new@example.com", "correct")
		}, user: defaultChangeEmailUser(), wantErr: domain.ErrInternal},
		{name: "ConfirmationMismatch", input: func(t *testing.T) service.ChangeEmailInput {
			return newChangeEmailInput(t, "old@example.com", "new@example.com", "different@example.com", "correct")
		}, user: defaultChangeEmailUser(), wantErr: domain.ErrInternal},
		{name: "EmailUnchanged", input: func(t *testing.T) service.ChangeEmailInput {
			return newChangeEmailInput(t, "old@example.com", "old@example.com", "old@example.com", "correct")
		}, user: defaultChangeEmailUser(), wantErr: domain.ErrInternal},
		{name: "InvalidNewEmail", input: func(t *testing.T) service.ChangeEmailInput {
			return newChangeEmailInput(t, "old@example.com", "not-an-email", "not-an-email", "correct")
		}, user: defaultChangeEmailUser(), wantErr: domain.ErrInternal},
		{name: "UpdateError", input: func(t *testing.T) service.ChangeEmailInput {
			return newChangeEmailInput(t, "old@example.com", "new@example.com", "new@example.com", "correct")
		}, user: defaultChangeEmailUser(), updateErr: errors.New("update failed"), wantErr: domain.ErrInternal, wantUpdateCall: true},
		{name: "AuditError", input: func(t *testing.T) service.ChangeEmailInput {
			return newChangeEmailInput(t, "old@example.com", "new@example.com", "new@example.com", "correct")
		}, user: defaultChangeEmailUser(), auditErr: errors.New("audit failed"), wantUpdate: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &changeEmailRepoMock{
				getFunc:    func(context.Context, int) (*domain.User, error) { return tt.user, tt.repoErr },
				updateFunc: func(context.Context, *domain.User) error { return tt.updateErr },
			}
			hasher := &changeEmailHasherMock{compareFunc: func([]byte, []byte) (*argon2.HashMetaData, error) {
				return &argon2.HashMetaData{}, tt.compareErr
			}}
			audit := &changeEmailAuditMock{done: make(chan struct{}), createFunc: func(context.Context, repository.AccountEventAudit) error { return tt.auditErr }}
			serviceUnderTest := NewChangeEmailService(repo, hasher, audit)

			err := serviceUnderTest.ChangeEmailFunction(context.Background(), tt.input(t), tt.userAgent)

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
			if tt.user != nil && tt.repoErr == nil && tt.input(t).Password != nil && !tt.wantEmptyErr {
				assert.Equal(t, 1, hasher.compareCalls)
			} else {
				assert.Equal(t, 0, hasher.compareCalls)
			}
			if tt.wantUpdate || tt.wantUpdateCall {
				assert.Equal(t, 1, repo.updateCalls)
				assert.Equal(t, "new@example.com", repo.updatedUser.Email)
			}
			if tt.wantUpdate {
				select {
				case <-audit.done:
				case <-time.After(time.Second):
					t.Fatal("timed out waiting for email audit")
				}
				require.Len(t, audit.events, 1)
				assert.Equal(t, int64(tt.user.Id), audit.events[0].UserID)
				assert.Equal(t, "EMAIL_CHANGE", audit.events[0].EventType)
				assert.Equal(t, tt.userAgent, audit.events[0].UserAgent)
			} else {
				assert.Equal(t, tt.wantUpdateCall, repo.updateCalls == 1)
			}
		})
	}
}
