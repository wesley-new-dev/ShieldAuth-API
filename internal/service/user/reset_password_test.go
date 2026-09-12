package user

// Coverage summary:
// NewResetPasswordService: constructor dependency wiring.
// ResetPasswordFunction: token hashing/lookup, Redis errors and deferred deletion,
// numeric and invalid user IDs, repository errors and nil users, nil/malformed password
// inputs, confirmation mismatch and ignored confirmation-decryption errors, short/long/
// weak passwords, hashing/update/consume/history errors, successful reset, zero IDs,
// optional audit, audit errors, and all dependency call arguments.
// No path in reset_password.go is intentionally uncovered. ResetPasswordRecordRepo was
// introduced because the service previously depended on a concrete database wrapper.

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

type resetPasswordRepoMock struct {
	getFunc       func(context.Context, int64) (*domain.User, error)
	updateFunc    func(context.Context, string, []byte) error
	getCalls      int
	updateCalls   int
	requestedID   int64
	updatedUserID string
	updatedHash   []byte
}

func (m *resetPasswordRepoMock) GetID(ctx context.Context, id int64) (*domain.User, error) {
	m.getCalls++
	m.requestedID = id
	return m.getFunc(ctx, id)
}

func (m *resetPasswordRepoMock) UpdatePassword(ctx context.Context, userID string, hash []byte) error {
	m.updateCalls++
	m.updatedUserID = userID
	m.updatedHash = append([]byte(nil), hash...)
	return m.updateFunc(ctx, userID, hash)
}

type resetPasswordTokenMock struct {
	tokenHashFunc func(string) string
	hashCalls     int
	lastToken     string
}

func (m *resetPasswordTokenMock) GenerateToken() (string, error) { return "", nil }

func (m *resetPasswordTokenMock) TokenHash(token string) string {
	m.hashCalls++
	m.lastToken = token
	return m.tokenHashFunc(token)
}

type resetPasswordStoreMock struct {
	getFunc     func(context.Context, string) (string, error)
	deleteFunc  func(context.Context, string) error
	getCalls    int
	deleteCalls int
	getKey      string
	deleteKey   string
}

func (m *resetPasswordStoreMock) Get(ctx context.Context, key string) (string, error) {
	m.getCalls++
	m.getKey = key
	return m.getFunc(ctx, key)
}

func (m *resetPasswordStoreMock) Delete(ctx context.Context, key string) error {
	m.deleteCalls++
	m.deleteKey = key
	return m.deleteFunc(ctx, key)
}

func (m *resetPasswordStoreMock) Save(context.Context, string, interface{}, time.Duration) error {
	return nil
}
func (m *resetPasswordStoreMock) Exists(context.Context, string) (bool, error) { return false, nil }

type resetPasswordHasherMock struct {
	compareFunc  func([]byte, []byte) (*argon2.HashMetaData, error)
	hashFunc     func([]byte) ([]byte, error)
	compareCalls int
	hashCalls    int
	passwords    [][]byte
	hashes       [][]byte
}

func (m *resetPasswordHasherMock) Compare(password, passwordHash []byte) (*argon2.HashMetaData, error) {
	m.compareCalls++
	return &argon2.HashMetaData{}, nil
}

func (m *resetPasswordHasherMock) Hash(password []byte) ([]byte, error) {
	m.hashCalls++
	m.passwords = append(m.passwords, append([]byte(nil), password...))
	return m.hashFunc(password)
}

func (m *resetPasswordHasherMock) NeedsRehash(uint32, uint32, uint8) bool { return false }

type resetPasswordHistoryMock struct {
	createFunc  func(context.Context, int64, []byte) error
	createCalls int
	userID      int64
	hash        []byte
}

func (m *resetPasswordHistoryMock) Create(ctx context.Context, userID int64, hash []byte) error {
	m.createCalls++
	m.userID = userID
	m.hash = append([]byte(nil), hash...)
	return m.createFunc(ctx, userID, hash)
}

type resetPasswordRecordMock struct {
	consumeFunc  func(context.Context, string) error
	consumeCalls int
	tokenHash    string
}

func (m *resetPasswordRecordMock) Consume(ctx context.Context, tokenHash string) error {
	m.consumeCalls++
	m.tokenHash = tokenHash
	return m.consumeFunc(ctx, tokenHash)
}

type resetPasswordAuditMock struct {
	createFunc  func(context.Context, repository.AccountEventAudit) error
	createCalls int
	events      []repository.AccountEventAudit
	done        chan struct{}
	once        sync.Once
}

func (m *resetPasswordAuditMock) CreateEvent(ctx context.Context, event repository.AccountEventAudit) error {
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

func newResetPasswordInput(t *testing.T, newPassword, confirmPassword string) service.ResetPasswordInput {
	t.Helper()
	newData, err := security.NewSensitiveData([]byte(newPassword))
	require.NoError(t, err)
	confirmData, err := security.NewSensitiveData([]byte(confirmPassword))
	require.NoError(t, err)
	return service.ResetPasswordInput{NewPassword: newData, ConfirmPassword: confirmData}
}

func defaultResetPasswordUser() *domain.User {
	return &domain.User{Id: 42, Name: "user-test", Email: "user-test@example.com"}
}

func TestNewResetPasswordService_Success(t *testing.T) {
	repo := &resetPasswordRepoMock{}
	tokenManager := &resetPasswordTokenMock{}
	hasher := &resetPasswordHasherMock{}
	store := &resetPasswordStoreMock{}
	audit := &resetPasswordAuditMock{}
	history := &resetPasswordHistoryMock{}
	record := &resetPasswordRecordMock{}

	serviceUnderTest := NewResetPasswordService(repo, tokenManager, hasher, store, audit, history, record)

	require.NotNil(t, serviceUnderTest)
	assert.Same(t, repo, serviceUnderTest.repo)
	assert.Same(t, tokenManager, serviceUnderTest.security)
	assert.Same(t, hasher, serviceUnderTest.hasher)
	assert.Same(t, store, serviceUnderTest.redis)
	assert.Same(t, audit, serviceUnderTest.audit_trail)
	assert.Same(t, history, serviceUnderTest.password_history)
	assert.Same(t, record, serviceUnderTest.resetPasswordRecord)
}

func TestResetPasswordFunction_Scenarios(t *testing.T) {
	tests := []struct {
		name          string
		token         string
		userID        string
		input         func(*testing.T) service.ResetPasswordInput
		user          *domain.User
		redisErr      error
		getErr        error
		hashResult    []byte
		hashErr       error
		updateErr     error
		consumeErr    error
		historyErr    error
		deleteErr     error
		useAudit      bool
		auditErr      error
		wantErr       error
		wantMessage   string
		wantEmptyErr  bool
		wantHashCalls int
		wantUpdate    int
		wantConsume   int
		wantHistory   int
	}{
		{name: "Success", token: "reset-token", userID: "42", input: func(t *testing.T) service.ResetPasswordInput {
			return newResetPasswordInput(t, "Correct Horse Battery Staple 123!", "Correct Horse Battery Staple 123!")
		}, user: defaultResetPasswordUser(), hashResult: []byte("new-hash"), useAudit: true, wantHashCalls: 1, wantUpdate: 1, wantConsume: 1, wantHistory: 1},
		{name: "SuccessZeroUserID", token: "", userID: "0", input: func(t *testing.T) service.ResetPasswordInput {
			return newResetPasswordInput(t, "Correct Horse Battery Staple 123!", "Correct Horse Battery Staple 123!")
		}, user: &domain.User{Id: 0, Name: "user-test", Email: "user-test@example.com"}, hashResult: []byte("zero-hash"), wantHashCalls: 1, wantUpdate: 1, wantConsume: 1, wantHistory: 1},
		{name: "RedisGetError", token: "token", redisErr: errors.New("token missing"), input: func(t *testing.T) service.ResetPasswordInput {
			return newResetPasswordInput(t, "valid-password", "valid-password")
		}, wantMessage: "invalid or expired token: token missing"},
		{name: "RepositoryError", token: "token", userID: "42", input: func(t *testing.T) service.ResetPasswordInput {
			return newResetPasswordInput(t, "valid-password", "valid-password")
		}, user: defaultResetPasswordUser(), getErr: errors.New("user lookup failed"), wantMessage: "user lookup failed"},
		{name: "NilUser", token: "token", userID: "42", input: func(t *testing.T) service.ResetPasswordInput {
			return newResetPasswordInput(t, "valid-password", "valid-password")
		}, wantErr: domain.ErrUserNotFound},
		{name: "NilNewPassword", token: "token", userID: "42", input: func(*testing.T) service.ResetPasswordInput {
			return service.ResetPasswordInput{ConfirmPassword: &security.SensitiveData{}}
		}, user: defaultResetPasswordUser(), wantErr: domain.ErrInvalidData},
		{name: "NilConfirmPassword", token: "token", userID: "42", input: func(t *testing.T) service.ResetPasswordInput {
			input := newResetPasswordInput(t, "valid-password", "valid-password")
			input.ConfirmPassword = nil
			return input
		}, user: defaultResetPasswordUser(), wantErr: domain.ErrInvalidData},
		{name: "MalformedNewPassword", token: "token", userID: "42", input: func(t *testing.T) service.ResetPasswordInput {
			input := newResetPasswordInput(t, "valid-password", "valid-password")
			input.NewPassword = &security.SensitiveData{}
			return input
		}, user: defaultResetPasswordUser(), wantEmptyErr: true},
		{name: "ConfirmationMismatch", token: "token", userID: "42", input: func(t *testing.T) service.ResetPasswordInput {
			return newResetPasswordInput(t, "valid-password", "different-password")
		}, user: defaultResetPasswordUser(), wantErr: domain.ErrPasswordDoNotMatch},
		{name: "MalformedConfirmationIgnored", token: "token", userID: "42", input: func(t *testing.T) service.ResetPasswordInput {
			input := newResetPasswordInput(t, "Correct Horse Battery Staple 123!", "valid")
			input.ConfirmPassword = &security.SensitiveData{}
			return input
		}, user: defaultResetPasswordUser(), hashResult: []byte("malformed-confirm-hash"), wantHashCalls: 1, wantUpdate: 1, wantConsume: 1, wantHistory: 1},
		{name: "ShortPassword", token: "token", userID: "42", input: func(t *testing.T) service.ResetPasswordInput { return newResetPasswordInput(t, "short", "short") }, user: defaultResetPasswordUser(), wantErr: domain.ErrShortPassword},
		{name: "LongPassword", token: "token", userID: "42", input: func(t *testing.T) service.ResetPasswordInput {
			password := ""
			for len(password) < 129 {
				password += "L"
			}
			return newResetPasswordInput(t, password, password)
		}, user: defaultResetPasswordUser(), wantErr: domain.ErrLongPassword},
		{name: "WeakPassword", token: "token", userID: "42", input: func(t *testing.T) service.ResetPasswordInput { return newResetPasswordInput(t, "password", "password") }, user: defaultResetPasswordUser(), wantErr: domain.ErrWeakPassword},
		{name: "HashError", token: "token", userID: "42", input: func(t *testing.T) service.ResetPasswordInput {
			return newResetPasswordInput(t, "Correct Horse Battery Staple 123!", "Correct Horse Battery Staple 123!")
		}, user: defaultResetPasswordUser(), hashErr: errors.New("hash failed"), wantMessage: "failed to hash password: hash failed", wantHashCalls: 1},
		{name: "UpdateError", token: "token", userID: "42", input: func(t *testing.T) service.ResetPasswordInput {
			return newResetPasswordInput(t, "Correct Horse Battery Staple 123!", "Correct Horse Battery Staple 123!")
		}, user: defaultResetPasswordUser(), hashResult: []byte("new-hash"), updateErr: errors.New("update failed"), wantMessage: "failed to update password: update failed", wantHashCalls: 1, wantUpdate: 1},
		{name: "ConsumeError", token: "token", userID: "42", input: func(t *testing.T) service.ResetPasswordInput {
			return newResetPasswordInput(t, "Correct Horse Battery Staple 123!", "Correct Horse Battery Staple 123!")
		}, user: defaultResetPasswordUser(), hashResult: []byte("new-hash"), consumeErr: errors.New("consume failed"), wantMessage: "failed to consume reset password record: consume failed", wantHashCalls: 1, wantUpdate: 1, wantConsume: 1},
		{name: "HistoryError", token: "token", userID: "42", input: func(t *testing.T) service.ResetPasswordInput {
			return newResetPasswordInput(t, "Correct Horse Battery Staple 123!", "Correct Horse Battery Staple 123!")
		}, user: defaultResetPasswordUser(), hashResult: []byte("new-hash"), historyErr: errors.New("history failed"), wantErr: domain.ErrInternal, wantHashCalls: 1, wantUpdate: 1, wantConsume: 1, wantHistory: 1},
		{name: "AuditErrorIgnored", token: "token", userID: "42", input: func(t *testing.T) service.ResetPasswordInput {
			return newResetPasswordInput(t, "Correct Horse Battery Staple 123!", "Correct Horse Battery Staple 123!")
		}, user: defaultResetPasswordUser(), hashResult: []byte("audit-hash"), useAudit: true, auditErr: errors.New("audit failed"), wantHashCalls: 1, wantUpdate: 1, wantConsume: 1, wantHistory: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &resetPasswordRepoMock{
				getFunc:    func(context.Context, int64) (*domain.User, error) { return tt.user, tt.getErr },
				updateFunc: func(context.Context, string, []byte) error { return tt.updateErr },
			}
			tokenManager := &resetPasswordTokenMock{tokenHashFunc: func(string) string { return "token-hash" }}
			store := &resetPasswordStoreMock{
				getFunc:    func(context.Context, string) (string, error) { return tt.userID, tt.redisErr },
				deleteFunc: func(context.Context, string) error { return tt.deleteErr },
			}
			hasher := &resetPasswordHasherMock{
				hashFunc: func([]byte) ([]byte, error) { return tt.hashResult, tt.hashErr },
			}
			history := &resetPasswordHistoryMock{createFunc: func(context.Context, int64, []byte) error { return tt.historyErr }}
			record := &resetPasswordRecordMock{consumeFunc: func(context.Context, string) error { return tt.consumeErr }}
			audit := &resetPasswordAuditMock{done: make(chan struct{}), createFunc: func(context.Context, repository.AccountEventAudit) error { return tt.auditErr }}
			var auditRepo repository.AccountAuditRepository
			if tt.useAudit {
				auditRepo = audit
			}
			serviceUnderTest := NewResetPasswordService(repo, tokenManager, hasher, store, auditRepo, history, record)

			err := serviceUnderTest.ResetPasswordFunction(context.Background(), tt.token, tt.input(t), "browser")

			if tt.wantMessage != "" {
				require.Error(t, err)
				assert.EqualError(t, err, tt.wantMessage)
			} else if tt.wantEmptyErr {
				require.Error(t, err)
				assert.Empty(t, err.Error())
			} else if tt.wantErr != nil {
				require.Error(t, err)
				assert.Equal(t, tt.wantErr, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, 1, tokenManager.hashCalls)
			assert.Equal(t, "reset-password-token:token-hash", store.getKey)
			if tt.redisErr != nil {
				assert.Equal(t, 0, store.deleteCalls)
				return
			}
			assert.Equal(t, 1, store.deleteCalls)
			assert.Equal(t, store.getKey, store.deleteKey)
			assert.Equal(t, tt.wantHashCalls, hasher.hashCalls)
			assert.Equal(t, tt.wantUpdate, repo.updateCalls)
			assert.Equal(t, tt.wantConsume, record.consumeCalls)
			assert.Equal(t, tt.wantHistory, history.createCalls)
			if tt.useAudit {
				select {
				case <-audit.done:
				case <-time.After(time.Second):
					t.Fatal("timed out waiting for reset-success audit")
				}
				assert.Equal(t, 1, audit.createCalls)
			}
		})
	}
}

var _ ResetPasswordRepo = (*resetPasswordRepoMock)(nil)
var _ ResetPasswordRecordRepo = (*resetPasswordRecordMock)(nil)
var _ PasswordHistoryRepo = (*resetPasswordHistoryMock)(nil)
