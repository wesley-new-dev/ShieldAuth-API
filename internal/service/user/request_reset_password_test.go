package user

// Coverage summary:
// NewRequestResetService: constructor dependency wiring.
// RequestReset: repository errors and nil users with dummy responses, reset-code
// generation errors, Redis save errors, successful persistence, notification success
// and ignored errors, optional audit, audit success/error, empty email, zero user ID,
// exact Redis key/value/TTL, and asynchronous audit event assertions.
// GenerateResetCode: successful six-digit generation, leading zero behavior, and
// random-reader errors. No path in request_reset_password.go is intentionally uncovered.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/notification"
	"ShieldAuth-API/internal/repository"
	"ShieldAuth-API/internal/security/redis"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type requestResetRepoMock struct {
	getFunc        func(context.Context, string) (*domain.User, error)
	getCalls       int
	requestedEmail string
}

func (m *requestResetRepoMock) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	m.getCalls++
	m.requestedEmail = email
	return m.getFunc(ctx, email)
}

type requestResetStoreMock struct {
	saveFunc  func(context.Context, string, interface{}, time.Duration) error
	saveCalls int
	key       string
	value     interface{}
	ttl       time.Duration
}

func (m *requestResetStoreMock) Save(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	m.saveCalls++
	m.key = key
	m.value = value
	m.ttl = ttl
	return m.saveFunc(ctx, key, value, ttl)
}

func (m *requestResetStoreMock) Get(context.Context, string) (string, error)  { return "", nil }
func (m *requestResetStoreMock) Delete(context.Context, string) error         { return nil }
func (m *requestResetStoreMock) Exists(context.Context, string) (bool, error) { return false, nil }

type requestNotificationMock struct {
	sendFunc  func(context.Context, string, string) error
	sendCalls int
	email     string
	code      string
}

func (m *requestNotificationMock) SendPasswordChangedEmail(context.Context, string) error { return nil }

func (m *requestNotificationMock) SendPasswordResetCode(ctx context.Context, email, code string) error {
	m.sendCalls++
	m.email = email
	m.code = code
	return m.sendFunc(ctx, email, code)
}

type requestAuditMock struct {
	createFunc  func(context.Context, repository.AccountEventAudit) error
	createCalls int
	events      []repository.AccountEventAudit
	done        chan struct{}
	once        sync.Once
}

func (m *requestAuditMock) CreateEvent(ctx context.Context, event repository.AccountEventAudit) error {
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

type fixedResetReader struct {
	value byte
	err   error
}

func (r fixedResetReader) Read(buffer []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	for index := range buffer {
		buffer[index] = r.value
	}
	return len(buffer), nil
}

func defaultRequestResetUser() *domain.User {
	return &domain.User{Id: 42, Email: "user-test@example.com"}
}

func TestNewRequestResetService_Success(t *testing.T) {
	repo := &requestResetRepoMock{}
	store := &requestResetStoreMock{}
	notifier := &requestNotificationMock{}
	audit := &requestAuditMock{}

	serviceUnderTest := NewRequestResetService(repo, store, notifier, audit)

	require.NotNil(t, serviceUnderTest)
	assert.Same(t, repo, serviceUnderTest.userRepo)
	assert.Same(t, store, serviceUnderTest.resetStore)
	assert.Same(t, notifier, serviceUnderTest.notification)
	assert.Same(t, audit, serviceUnderTest.audit_trail)
}

func TestRequestReset_Scenarios(t *testing.T) {
	originalReader := resetCodeReader
	t.Cleanup(func() { resetCodeReader = originalReader })

	tests := []struct {
		name        string
		email       string
		user        *domain.User
		getErr      error
		randomErr   error
		saveErr     error
		notifyErr   error
		auditErr    error
		useAudit    bool
		wantCode    string
		wantErr     error
		wantWrapped bool
	}{
		{name: "Success", email: "user-test@example.com", user: defaultRequestResetUser(), useAudit: true, wantCode: "000000"},
		{name: "SuccessEmptyEmailZeroUserID", email: "", user: &domain.User{Id: 0, Email: ""}, wantCode: "000000"},
		{name: "RepositoryErrorReturnsDummy", email: "unknown@example.com", getErr: errors.New("not found"), wantCode: "dummy-code"},
		{name: "RepositoryErrorAndRandomErrorStillDummy", email: "unknown@example.com", getErr: errors.New("not found"), randomErr: errors.New("random unavailable"), wantCode: "dummy-code"},
		{name: "NilUserReturnsDummy", email: "unknown@example.com", wantCode: "dummy-code"},
		{name: "GenerateError", email: "user-test@example.com", user: defaultRequestResetUser(), randomErr: errors.New("random unavailable"), wantErr: errors.New("random unavailable"), wantWrapped: true},
		{name: "SaveError", email: "user-test@example.com", user: defaultRequestResetUser(), saveErr: errors.New("redis unavailable"), wantErr: domain.ErrInternal},
		{name: "NotificationErrorIgnored", email: "user-test@example.com", user: defaultRequestResetUser(), notifyErr: errors.New("notification unavailable"), wantCode: "000000"},
		{name: "AuditErrorIgnored", email: "user-test@example.com", user: defaultRequestResetUser(), auditErr: errors.New("audit unavailable"), useAudit: true, wantCode: "000000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCodeReader = fixedResetReader{value: 0, err: tt.randomErr}
			repo := &requestResetRepoMock{getFunc: func(context.Context, string) (*domain.User, error) { return tt.user, tt.getErr }}
			store := &requestResetStoreMock{saveFunc: func(context.Context, string, interface{}, time.Duration) error { return tt.saveErr }}
			notifier := &requestNotificationMock{sendFunc: func(context.Context, string, string) error { return tt.notifyErr }}
			audit := &requestAuditMock{done: make(chan struct{}), createFunc: func(context.Context, repository.AccountEventAudit) error { return tt.auditErr }}
			var auditRepo repository.AccountAuditRepository
			if tt.useAudit {
				auditRepo = audit
			}
			serviceUnderTest := NewRequestResetService(repo, store, notifier, auditRepo)

			got, err := serviceUnderTest.RequestReset(context.Background(), tt.email, "browser")

			if tt.wantErr != nil {
				require.Error(t, err)
				if tt.wantWrapped {
					assert.EqualError(t, err, "generate reset code: random unavailable")
				} else {
					assert.Equal(t, tt.wantErr, err)
				}
				assert.Empty(t, got)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantCode, got)
			}
			assert.Equal(t, 1, repo.getCalls)
			assert.Equal(t, tt.email, repo.requestedEmail)

			if tt.getErr != nil || tt.user == nil {
				assert.Equal(t, 0, store.saveCalls)
				assert.Equal(t, 0, notifier.sendCalls)
				assert.Equal(t, 0, audit.createCalls)
				return
			}
			if tt.randomErr != nil {
				assert.Equal(t, 0, store.saveCalls)
				assert.Equal(t, 0, notifier.sendCalls)
				assert.Equal(t, 0, audit.createCalls)
				return
			}
			assert.Equal(t, 1, store.saveCalls)
			assert.Equal(t, "reset-password-code:000000", store.key)
			assert.Equal(t, tt.user.Id, store.value)
			assert.Equal(t, 15*time.Minute, store.ttl)
			if tt.saveErr != nil {
				assert.Equal(t, 0, notifier.sendCalls)
				assert.Equal(t, 0, audit.createCalls)
				return
			}
			assert.Equal(t, 1, notifier.sendCalls)
			assert.Equal(t, tt.user.Email, notifier.email)
			assert.Equal(t, "000000", notifier.code)
			if tt.useAudit {
				select {
				case <-audit.done:
				case <-time.After(time.Second):
					t.Fatal("timed out waiting for reset audit")
				}
				require.Len(t, audit.events, 1)
				assert.Equal(t, tt.user.Id, audit.events[0].UserID)
				assert.Equal(t, "FORGOT_PASSWORD_REQUESTED", audit.events[0].EventType)
				assert.Equal(t, "browser", audit.events[0].UserAgent)
			}
		})
	}
}

func TestGenerateResetCode_Scenarios(t *testing.T) {
	originalReader := resetCodeReader
	t.Cleanup(func() { resetCodeReader = originalReader })

	tests := []struct {
		name      string
		reader    fixedResetReader
		wantCode  string
		wantError error
	}{
		{name: "SuccessLeadingZeros", reader: fixedResetReader{value: 0}, wantCode: "000000"},
		{name: "SuccessNonZero", reader: fixedResetReader{value: 1}, wantCode: "065793"},
		{name: "ReaderError", reader: fixedResetReader{err: errors.New("reader failed")}, wantError: errors.New("reader failed")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCodeReader = tt.reader
			code, err := GenerateResetCode()
			if tt.wantError != nil {
				require.Error(t, err)
				assert.Equal(t, tt.wantError.Error(), err.Error())
				assert.Empty(t, code)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantCode, code)
			assert.Len(t, code, 6)
		})
	}
}

var _ RequestResetRepo = (*requestResetRepoMock)(nil)
var _ redis.PasswordResetStore = (*requestResetStoreMock)(nil)
var _ notification.SendNotification = (*requestNotificationMock)(nil)
var _ repository.AccountAuditRepository = (*requestAuditMock)(nil)
