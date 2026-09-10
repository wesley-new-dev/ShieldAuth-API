package auth

// Coverage summary:
// NewValidToken: constructor wiring.
// ValidToken: empty code, Exists errors and false status, Get errors, Delete errors,
// token-generation errors, Redis Save errors, reset-record errors, success, empty
// user-agent, empty user ID, exact keys, values, TTLs, and dependency call counts.
// No path in valid_token.go is intentionally uncovered. The service now depends on
// validResetPasswordRecord because the original database wrapper was a concrete type;
// this local interface is the required refactoring for unit-test isolation.

import (
	"context"
	"errors"
	"testing"
	"time"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/security"
	"ShieldAuth-API/internal/security/redis"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type validTokenStoreMock struct {
	existsFunc  func(context.Context, string) (bool, error)
	getFunc     func(context.Context, string) (string, error)
	deleteFunc  func(context.Context, string) error
	saveFunc    func(context.Context, string, interface{}, time.Duration) error
	existsCalls int
	getCalls    int
	deleteCalls int
	saveCalls   int
	existsKey   string
	lastKey     string
	lastValue   interface{}
	lastTTL     time.Duration
}

func (m *validTokenStoreMock) Exists(ctx context.Context, key string) (bool, error) {
	m.existsCalls++
	m.existsKey = key
	m.lastKey = key
	return m.existsFunc(ctx, key)
}

func (m *validTokenStoreMock) Get(ctx context.Context, key string) (string, error) {
	m.getCalls++
	m.lastKey = key
	return m.getFunc(ctx, key)
}

func (m *validTokenStoreMock) Delete(ctx context.Context, key string) error {
	m.deleteCalls++
	m.lastKey = key
	return m.deleteFunc(ctx, key)
}

func (m *validTokenStoreMock) Save(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	m.saveCalls++
	m.lastKey = key
	m.lastValue = value
	m.lastTTL = ttl
	return m.saveFunc(ctx, key, value, ttl)
}

type validTokenManagerMock struct {
	generateFunc  func() (string, error)
	tokenHashFunc func(string) string
	generateCalls int
	hashCalls     int
	lastToken     string
}

func (m *validTokenManagerMock) GenerateToken() (string, error) {
	m.generateCalls++
	return m.generateFunc()
}

func (m *validTokenManagerMock) TokenHash(token string) string {
	m.hashCalls++
	m.lastToken = token
	return m.tokenHashFunc(token)
}

type validResetPasswordRecordMock struct {
	createFunc  func(context.Context, string, string, interface{}, string) error
	createCalls int
	userID      string
	tokenHash   string
	expiresAt   interface{}
	userAgent   string
}

func (m *validResetPasswordRecordMock) Create(ctx context.Context, userID, tokenHash string, expiresAt interface{}, userAgent string) error {
	m.createCalls++
	m.userID = userID
	m.tokenHash = tokenHash
	m.expiresAt = expiresAt
	m.userAgent = userAgent
	return m.createFunc(ctx, userID, tokenHash, expiresAt, userAgent)
}

func newValidTokenDependencies(exists bool, existsErr, getErr, deleteErr, saveErr, generateErr, recordErr error) (*validTokenStoreMock, *validTokenManagerMock, *validResetPasswordRecordMock) {
	store := &validTokenStoreMock{
		existsFunc: func(context.Context, string) (bool, error) { return exists, existsErr },
		getFunc:    func(context.Context, string) (string, error) { return "user-42", getErr },
		deleteFunc: func(context.Context, string) error { return deleteErr },
		saveFunc:   func(context.Context, string, interface{}, time.Duration) error { return saveErr },
	}
	manager := &validTokenManagerMock{
		generateFunc:  func() (string, error) { return "generated-token", generateErr },
		tokenHashFunc: func(string) string { return "hashed-token" },
	}
	record := &validResetPasswordRecordMock{
		createFunc: func(context.Context, string, string, interface{}, string) error { return recordErr },
	}
	return store, manager, record
}

func TestNewValidToken_Success(t *testing.T) {
	store, manager, record := newValidTokenDependencies(true, nil, nil, nil, nil, nil, nil)
	serviceUnderTest := NewValidToken(store, manager, record)

	require.NotNil(t, serviceUnderTest)
	assert.Same(t, store, serviceUnderTest.resetStore)
	assert.Same(t, manager, serviceUnderTest.tokenManager)
	assert.Same(t, record, serviceUnderTest.resetPasswordRecord)
}

func TestValidToken_Scenarios(t *testing.T) {
	tests := []struct {
		name           string
		code           string
		userAgent      string
		exists         bool
		existsErr      error
		getErr         error
		deleteErr      error
		saveErr        error
		generateErr    error
		recordErr      error
		wantToken      string
		wantErr        error
		wantWrappedErr bool
	}{
		{name: "EmptyCode", wantErr: domain.ErrInvalidToken},
		{name: "ExistsError", code: "code-1", existsErr: errors.New("redis exists failed"), wantErr: domain.ErrInternal},
		{name: "CodeNotFound", code: "code-1", exists: false, wantErr: domain.ErrInvalidToken},
		{name: "GetError", code: "code-1", exists: true, getErr: errors.New("redis get failed"), wantErr: domain.ErrInvalidToken},
		{name: "DeleteError", code: "code-1", exists: true, deleteErr: errors.New("redis delete failed"), wantErr: domain.ErrInternal},
		{name: "GenerateTokenError", code: "code-1", exists: true, generateErr: errors.New("token generation failed"), wantErr: domain.ErrInternal},
		{name: "SaveError", code: "code-1", exists: true, saveErr: errors.New("redis save failed"), wantErr: domain.ErrInternal},
		{name: "RecordError", code: "code-1", exists: true, recordErr: errors.New("database insert failed"), wantErr: errors.New("database insert failed"), wantWrappedErr: true},
		{name: "Success", code: "code-1", exists: true, userAgent: "browser", wantToken: "generated-token"},
		{name: "SuccessEmptyValues", code: "zero", exists: true, userAgent: "", wantToken: "generated-token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, manager, record := newValidTokenDependencies(tt.exists, tt.existsErr, tt.getErr, tt.deleteErr, tt.saveErr, tt.generateErr, tt.recordErr)
			serviceUnderTest := NewValidToken(store, manager, record)

			got, err := serviceUnderTest.ValidToken(context.Background(), tt.code, tt.userAgent)

			if tt.wantErr != nil {
				require.Error(t, err)
				if tt.wantWrappedErr {
					assert.EqualError(t, err, "failed to create reset password record: database insert failed")
				} else {
					assert.Equal(t, tt.wantErr, err)
				}
				assert.Empty(t, got)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantToken, got)
			}

			if tt.code == "" {
				assert.Equal(t, 0, store.existsCalls)
				assert.Equal(t, 0, manager.generateCalls)
				assert.Equal(t, 0, record.createCalls)
				return
			}
			assert.Equal(t, 1, store.existsCalls)
			assert.Equal(t, "reset-password-code:"+tt.code, store.existsKey)
			if tt.existsErr != nil || !tt.exists {
				assert.Equal(t, 0, store.getCalls)
				assert.Equal(t, 0, manager.generateCalls)
				return
			}
			assert.Equal(t, 1, store.getCalls)
			if tt.getErr != nil {
				assert.Equal(t, 0, store.deleteCalls)
				return
			}
			assert.Equal(t, 1, store.deleteCalls)
			if tt.deleteErr != nil {
				assert.Equal(t, 0, manager.generateCalls)
				return
			}
			assert.Equal(t, 1, manager.generateCalls)
			if tt.generateErr != nil {
				assert.Equal(t, 0, manager.hashCalls)
				return
			}
			assert.Equal(t, 1, manager.hashCalls)
			if tt.saveErr != nil {
				assert.Equal(t, 0, record.createCalls)
				return
			}
			assert.Equal(t, 1, store.saveCalls)
			assert.Equal(t, "reset-password-token:hashed-token", store.lastKey)
			assert.Equal(t, "user-42", store.lastValue)
			assert.Equal(t, 5*time.Minute, store.lastTTL)
			assert.Equal(t, 1, record.createCalls)
			assert.Equal(t, "user-42", record.userID)
			assert.Equal(t, "hashed-token", record.tokenHash)
			assert.Equal(t, 5*time.Minute, record.expiresAt)
			assert.Equal(t, tt.userAgent, record.userAgent)
		})
	}
}

var _ redis.PasswordResetStore = (*validTokenStoreMock)(nil)
var _ security.TokenManager = (*validTokenManagerMock)(nil)
var _ validResetPasswordRecord = (*validResetPasswordRecordMock)(nil)
