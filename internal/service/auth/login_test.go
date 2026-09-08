package auth

// Coverage summary:
// VerifyLoginFunction: email/name identifier selection, empty and nil inputs, repository
// errors and nil users, cache errors and context cancellation, wrong and malformed
// passwords, successful desktop/mobile/tablet logins, rehash success/error, session
// errors, second cache errors, audit success/error, optional dependencies, and audit data.
// CreateRefreshToken: success, persistence error, random-source error, zero user ID,
// zero duration, hash, expiry, and session ID assertions.
// No login.go path is intentionally uncovered. loginAudit is a local interface because
// repository.SessionAndAudit is a concrete database wrapper and cannot be unit mocked.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/repository"
	"ShieldAuth-API/internal/security"
	"ShieldAuth-API/internal/security/argon2"
	"ShieldAuth-API/internal/security/redis"
	"ShieldAuth-API/internal/service"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type loginRepositoryMock struct {
	getFunc     func(context.Context, string) (*domain.User, error)
	getCalls    int
	identifiers []string
	rehashFunc  func(context.Context, int64, []byte) error
	rehashCalls int
	rehashID    int64
	rehashHash  []byte
}

func (m *loginRepositoryMock) GetByIdentifier(ctx context.Context, identifier string) (*domain.User, error) {
	m.getCalls++
	m.identifiers = append(m.identifiers, identifier)
	return m.getFunc(ctx, identifier)
}

func (m *loginRepositoryMock) Rehash(ctx context.Context, id int64, hash []byte) error {
	m.rehashCalls++
	m.rehashID = id
	m.rehashHash = append([]byte(nil), hash...)
	return m.rehashFunc(ctx, id, hash)
}

type loginHasherMock struct {
	compareFunc      func([]byte, []byte) (*argon2.HashMetaData, error)
	compareCalls     int
	comparePasswords [][]byte
	compareHashes    [][]byte
	needsRehashFunc  func(uint32, uint32, uint8) bool
	needsRehashCalls int
	hashFunc         func([]byte) ([]byte, error)
	hashCalls        int
}

func (m *loginHasherMock) Compare(password, passwordHash []byte) (*argon2.HashMetaData, error) {
	m.compareCalls++
	m.comparePasswords = append(m.comparePasswords, append([]byte(nil), password...))
	m.compareHashes = append(m.compareHashes, append([]byte(nil), passwordHash...))
	return m.compareFunc(password, passwordHash)
}

func (m *loginHasherMock) NeedsRehash(memory uint32, iterations uint32, parallelism uint8) bool {
	m.needsRehashCalls++
	return m.needsRehashFunc(memory, iterations, parallelism)
}

func (m *loginHasherMock) Hash(password []byte) ([]byte, error) {
	m.hashCalls++
	return m.hashFunc(password)
}

type loginRedisMock struct {
	saveFunc  func(context.Context, string, interface{}, time.Duration) error
	saveCalls []loginRedisSaveCall
}

type loginRedisSaveCall struct {
	key   string
	value interface{}
	ttl   time.Duration
}

func (m *loginRedisMock) Get(context.Context, string) (string, error)  { return "", nil }
func (m *loginRedisMock) Delete(context.Context, string) error         { return nil }
func (m *loginRedisMock) Exists(context.Context, string) (bool, error) { return false, nil }
func (m *loginRedisMock) Save(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	m.saveCalls = append(m.saveCalls, loginRedisSaveCall{key: key, value: value, ttl: ttl})
	return m.saveFunc(ctx, key, value, ttl)
}

type loginAuditMock struct {
	createFunc  func(context.Context, domain.LoginAttemptsAudit) error
	createCalls int
	audits      []domain.LoginAttemptsAudit
}

func (m *loginAuditMock) Create(ctx context.Context, audit domain.LoginAttemptsAudit) error {
	m.createCalls++
	m.audits = append(m.audits, audit)
	if m.createFunc != nil {
		return m.createFunc(ctx, audit)
	}
	return nil
}

type loginSessionMock struct {
	createFunc  func(context.Context, *repository.UserSession) error
	createCalls int
	sessions    []*repository.UserSession
}

func (m *loginSessionMock) Create(ctx context.Context, session *repository.UserSession) error {
	m.createCalls++
	m.sessions = append(m.sessions, session)
	return m.createFunc(ctx, session)
}
func (m *loginSessionMock) GetActiveByUserID(context.Context, int64) ([]*repository.UserSession, error) {
	return nil, nil
}
func (m *loginSessionMock) Revoke(context.Context, string) error               { return nil }
func (m *loginSessionMock) RevokeAllUserByUserID(context.Context, int64) error { return nil }

type loginAccountAuditMock struct {
	createFunc  func(context.Context, repository.AccountEventAudit) error
	createCalls int
	events      []repository.AccountEventAudit
	done        chan struct{}
	once        sync.Once
}

func (m *loginAccountAuditMock) CreateEvent(ctx context.Context, event repository.AccountEventAudit) error {
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

type loginRefreshTokenMock struct {
	saveFunc  func(context.Context, domain.RefreshToken) error
	saveCalls int
	saved     domain.RefreshToken
}

func (m *loginRefreshTokenMock) SaveRefreshToken(ctx context.Context, token domain.RefreshToken) error {
	m.saveCalls++
	m.saved = token
	return m.saveFunc(ctx, token)
}

func newLoginInput(t *testing.T, email, name, password string) service.LoginInput {
	t.Helper()
	sensitive, err := security.NewSensitiveData([]byte(password))
	require.NoError(t, err)
	return service.LoginInput{Email: email, Name: name, Password: sensitive}
}

func defaultLoginUser() *domain.User {
	return &domain.User{Id: 7, Name: "test-user", Email: "test-user@example.com", JWTVersion: 3, PasswordHash: []byte("stored-hash")}
}

func newLoginDependencies(user *domain.User, repoErr, firstRedisErr, secondRedisErr, compareErr, hashErr error, rehash bool) (*loginRepositoryMock, *loginHasherMock, *loginRedisMock, *loginAuditMock, *loginSessionMock, *loginAccountAuditMock) {
	repo := &loginRepositoryMock{
		getFunc:    func(context.Context, string) (*domain.User, error) { return user, repoErr },
		rehashFunc: func(context.Context, int64, []byte) error { return nil },
	}
	hasher := &loginHasherMock{
		compareFunc: func([]byte, []byte) (*argon2.HashMetaData, error) {
			return &argon2.HashMetaData{Memory: 1, Iterations: 2, Parallelism: 1}, compareErr
		},
		needsRehashFunc: func(uint32, uint32, uint8) bool { return rehash },
		hashFunc:        func([]byte) ([]byte, error) { return []byte("new-hash"), hashErr },
	}
	var redisMock *loginRedisMock
	redisMock = &loginRedisMock{saveFunc: func(context.Context, string, interface{}, time.Duration) error {
		if len(redisMock.saveCalls) == 1 {
			return firstRedisErr
		}
		return secondRedisErr
	}}
	audit := &loginAuditMock{}
	session := &loginSessionMock{createFunc: func(context.Context, *repository.UserSession) error { return nil }}
	accountAudit := &loginAccountAuditMock{done: make(chan struct{})}
	return repo, hasher, redisMock, audit, session, accountAudit
}

func TestVerifyLoginFunction_Scenarios(t *testing.T) {
	tests := []struct {
		name            string
		input           func(*testing.T) service.LoginInput
		userAgent       string
		user            *domain.User
		repoErr         error
		firstRedisErr   error
		secondRedisErr  error
		compareErr      error
		hashErr         error
		rehash          bool
		useSession      bool
		sessionErr      error
		useAuditTrail   bool
		auditTrailErr   error
		cancelContext   bool
		wantErr         error
		wantDevice      string
		wantIdentifier  string
		wantCompareCall int
		wantRehashCalls int
	}{
		{name: "SuccessDesktopEmail", input: func(t *testing.T) service.LoginInput {
			return newLoginInput(t, "test-user@example.com", "test-user", "secret")
		}, user: defaultLoginUser(), userAgent: "Mozilla", useSession: true, useAuditTrail: true, wantDevice: "Desktop", wantIdentifier: "test-user@example.com", wantCompareCall: 1},
		{name: "SuccessMobile", input: func(t *testing.T) service.LoginInput {
			return newLoginInput(t, "test-user@example.com", "test-user", "secret")
		}, user: defaultLoginUser(), userAgent: "My MOBILE browser", wantDevice: "Mobile", wantIdentifier: "test-user@example.com", wantCompareCall: 1},
		{name: "SuccessTabletNameAndRehash", input: func(t *testing.T) service.LoginInput { return newLoginInput(t, "", "test-user", "secret") }, user: defaultLoginUser(), userAgent: "Tablet browser", rehash: true, wantDevice: "Tablet", wantIdentifier: "test-user", wantCompareCall: 1, wantRehashCalls: 1},
		{name: "InvalidIdentifier", input: func(*testing.T) service.LoginInput { return service.LoginInput{} }, wantErr: domain.ErrInvalidData},
		{name: "NilPassword", input: func(*testing.T) service.LoginInput { return service.LoginInput{Email: "test-user@example.com"} }, wantErr: domain.ErrInvalidData},
		{name: "RepositoryError", input: func(t *testing.T) service.LoginInput { return newLoginInput(t, "test-user@example.com", "", "secret") }, user: defaultLoginUser(), repoErr: errors.New("database unavailable"), wantErr: domain.ErrUserNotFound, wantIdentifier: "test-user@example.com", wantCompareCall: 1},
		{name: "NilUser", input: func(t *testing.T) service.LoginInput { return newLoginInput(t, "test-user@example.com", "", "secret") }, wantIdentifier: "test-user@example.com", wantErr: domain.ErrUserNotFound},
		{name: "CacheError", input: func(t *testing.T) service.LoginInput { return newLoginInput(t, "test-user@example.com", "", "secret") }, user: defaultLoginUser(), firstRedisErr: errors.New("redis down"), wantErr: domain.ErrCacheError, wantCompareCall: 0},
		{name: "ContextTimeout", input: func(t *testing.T) service.LoginInput { return newLoginInput(t, "test-user@example.com", "", "secret") }, user: defaultLoginUser(), cancelContext: true, wantErr: domain.ErrContextTimeout, wantCompareCall: 0},
		{name: "WrongPassword", input: func(t *testing.T) service.LoginInput { return newLoginInput(t, "test-user@example.com", "", "secret") }, user: defaultLoginUser(), compareErr: domain.ErrInvalidCredentials, wantErr: domain.ErrInvalidPassword, wantCompareCall: 1},
		{name: "MalformedSensitiveData", input: func(*testing.T) service.LoginInput {
			return service.LoginInput{Email: "test-user@example.com", Password: &security.SensitiveData{}}
		}, user: defaultLoginUser(), wantErr: errors.New(""), wantCompareCall: 0},
		{name: "RehashErrorIgnored", input: func(t *testing.T) service.LoginInput { return newLoginInput(t, "test-user@example.com", "", "secret") }, user: defaultLoginUser(), rehash: true, hashErr: errors.New("rehash failed"), wantDevice: "Desktop", wantRehashCalls: 0, wantCompareCall: 1},
		{name: "SessionError", input: func(t *testing.T) service.LoginInput { return newLoginInput(t, "test-user@example.com", "", "secret") }, user: defaultLoginUser(), useSession: true, sessionErr: errors.New("session failed"), wantErr: domain.ErrInternal, wantCompareCall: 1},
		{name: "SecondCacheError", input: func(t *testing.T) service.LoginInput { return newLoginInput(t, "test-user@example.com", "", "secret") }, user: defaultLoginUser(), secondRedisErr: errors.New("session cache down"), wantErr: domain.ErrCacheError, wantCompareCall: 1},
		{name: "AuditTrailError", input: func(t *testing.T) service.LoginInput { return newLoginInput(t, "test-user@example.com", "", "secret") }, user: defaultLoginUser(), useAuditTrail: true, auditTrailErr: errors.New("audit failed"), wantDevice: "Desktop", wantCompareCall: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, hasher, cache, audit, session, accountAudit := newLoginDependencies(tt.user, tt.repoErr, tt.firstRedisErr, tt.secondRedisErr, tt.compareErr, tt.hashErr, tt.rehash)
			if tt.sessionErr != nil {
				session.createFunc = func(context.Context, *repository.UserSession) error { return tt.sessionErr }
			}
			var auditTrail repository.AccountAuditRepository
			if tt.useAuditTrail {
				accountAudit.createFunc = func(context.Context, repository.AccountEventAudit) error { return tt.auditTrailErr }
				auditTrail = accountAudit
			}
			var sessionRepo UserSessionRepository
			if tt.useSession || tt.sessionErr != nil || tt.wantDevice != "" {
				sessionRepo = session
			}
			loginService := NewLoginService(repo, hasher, cache, domain.LoginAttemptsAudit{}, audit, sessionRepo, auditTrail, &loginRefreshTokenMock{})
			ctx := context.Background()
			if tt.cancelContext {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			id, version, gotSession, err := loginService.VerifyLoginFunction(ctx, tt.input(t), tt.userAgent)

			if tt.wantErr != nil {
				require.Error(t, err)
				assert.Equal(t, tt.wantErr.Error(), err.Error())
				assert.Equal(t, int64(0), id)
				assert.Equal(t, 0, version)
				assert.Equal(t, uuid.Nil, gotSession)
			} else {
				require.NoError(t, err)
				assert.Equal(t, int64(7), id)
				assert.Equal(t, 3, version)
				assert.Equal(t, sessionIDLogin, gotSession)
			}
			if tt.wantIdentifier != "" {
				require.Len(t, repo.identifiers, 1)
				assert.Equal(t, tt.wantIdentifier, repo.identifiers[0])
			}
			assert.Equal(t, tt.wantCompareCall, hasher.compareCalls)
			assert.Equal(t, tt.wantRehashCalls, repo.rehashCalls)
			if tt.wantDevice != "" {
				require.Len(t, session.sessions, 1)
				assert.Equal(t, tt.wantDevice, session.sessions[0].DeviceType)
			}
			if tt.useAuditTrail {
				select {
				case <-accountAudit.done:
				case <-time.After(time.Second):
					t.Fatal("timed out waiting for account audit")
				}
				require.Len(t, accountAudit.events, 1)
				assert.Equal(t, "LOGIN_SUCCESS", accountAudit.events[0].EventType)
			}
		})
	}
}

func TestVerifyLoginFunction_AuditIsRecorded(t *testing.T) {
	repo, hasher, cache, audit, _, _ := newLoginDependencies(defaultLoginUser(), nil, nil, nil, nil, nil, false)
	serviceUnderTest := NewLoginService(repo, hasher, cache, domain.LoginAttemptsAudit{}, audit, nil, nil, &loginRefreshTokenMock{})
	_, _, _, err := serviceUnderTest.VerifyLoginFunction(context.Background(), newLoginInput(t, "test-user@example.com", "", "secret"), "Desktop")
	require.NoError(t, err)
	require.Len(t, audit.audits, 1)
	assert.True(t, audit.audits[0].Success)
	assert.Nil(t, audit.audits[0].FailureReason)
	assert.Equal(t, int64(7), *audit.audits[0].UserID)
}

func TestLoginCreateRefreshToken_Scenarios(t *testing.T) {
	originalRandomRead, originalNow := loginRandomRead, loginNow
	t.Cleanup(func() { loginRandomRead, loginNow = originalRandomRead, originalNow })
	fixedNow := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	loginNow = func() time.Time { return fixedNow }

	tests := []struct {
		name        string
		userID      int64
		duration    time.Duration
		randomError error
		saveError   error
		wantError   error
	}{
		{name: "Success", userID: 42, duration: time.Hour},
		{name: "ZeroValues", duration: 0},
		{name: "RandomError", randomError: errors.New("random failed"), wantError: errors.New("random failed")},
		{name: "SaveError", userID: 42, duration: time.Minute, saveError: errors.New("save failed"), wantError: errors.New("save failed")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loginRandomRead = func(buffer []byte) (int, error) {
				if tt.randomError != nil {
					return 0, tt.randomError
				}
				for index := range buffer {
					buffer[index] = byte(index + 1)
				}
				return len(buffer), nil
			}
			store := &loginRefreshTokenMock{saveFunc: func(context.Context, domain.RefreshToken) error { return tt.saveError }}
			serviceUnderTest := NewLoginService(&loginRepositoryMock{}, &loginHasherMock{}, &loginRedisMock{}, domain.LoginAttemptsAudit{}, nil, nil, nil, store)
			got, err := serviceUnderTest.CreateRefreshToken(context.Background(), tt.userID, tt.duration)
			if tt.wantError != nil {
				require.Error(t, err)
				assert.Equal(t, tt.wantError.Error(), err.Error())
				assert.Empty(t, got)
				wantCalls := 1
				if tt.randomError != nil {
					wantCalls = 0
				}
				assert.Equal(t, wantCalls, store.saveCalls)
				return
			}
			require.NoError(t, err)
			assert.Len(t, got, 64)
			assert.Equal(t, tt.userID, store.saved.UserID)
			hash := sha256.Sum256([]byte(got))
			assert.Equal(t, hex.EncodeToString(hash[:]), store.saved.Token)
			assert.Equal(t, fixedNow.Add(tt.duration), store.saved.ExpiresAt)
			assert.Equal(t, sessionIDLogin, store.saved.SessionID)
			assert.Equal(t, 1, store.saveCalls)
		})
	}
}

var _ redis.PasswordResetStore = (*loginRedisMock)(nil)
