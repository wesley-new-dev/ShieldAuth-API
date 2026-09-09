package auth

// Coverage summary:
// RegisterFunction: successful registration, nil/short/long/weak passwords,
// hasher error, repository error, and repository success with user-field assertions.
// CreateRefreshToken: successful persistence, persistence error, random-source error,
// zero user ID, zero duration, token hashing, expiry, and generated session ID.
// No service path is intentionally uncovered. The random reader and clock are injected
// through package variables in register.go solely to make error and edge paths deterministic.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/security"
	"ShieldAuth-API/internal/service"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type registerRepositoryMock struct {
	createFunc  func(context.Context, *domain.User) (int64, int, error)
	createCalls int
	createdUser *domain.User
}

func (m *registerRepositoryMock) Create(ctx context.Context, user *domain.User) (int64, int, error) {
	m.createCalls++
	m.createdUser = user
	return m.createFunc(ctx, user)
}

type registerHasherMock struct {
	hashFunc  func([]byte) ([]byte, error)
	hashCalls int
}

func (m *registerHasherMock) Hash(password []byte) ([]byte, error) {
	m.hashCalls++
	return m.hashFunc(password)
}

type registerRefreshTokenMock struct {
	saveFunc  func(context.Context, domain.RefreshToken) error
	saveCalls int
	saved     domain.RefreshToken
}

func (m *registerRefreshTokenMock) SaveRefreshToken(ctx context.Context, token domain.RefreshToken) error {
	m.saveCalls++
	m.saved = token
	return m.saveFunc(ctx, token)
}

func newRegisterInput(t *testing.T, password string) service.RegisterInput {
	t.Helper()
	sensitive, err := security.NewSensitiveData([]byte(password))
	require.NoError(t, err)
	return service.RegisterInput{Name: "test_user", Email: "test_user@example.com", Password: sensitive}
}

func TestRegisterFunction_Scenarios(t *testing.T) {
	tests := []struct {
		name          string
		password      string
		nilPassword   bool
		hashError     error
		repoError     error
		wantError     error
		wantID        int64
		wantVersion   int
		wantHash      []byte
		wantHashCalls int
		wantRepoCalls int
	}{
		{name: "Success", password: "Correct Horse Battery Staple 123!", wantID: 42, wantVersion: 1, wantHash: []byte("hashed"), wantHashCalls: 1, wantRepoCalls: 1},
		{name: "NilPassword", nilPassword: true, wantError: domain.ErrInvalidData},
		{name: "ShortPassword", password: "short", wantError: domain.ErrWeakPassword},
		{name: "LongPassword", password: strings.Repeat("A", 129), wantError: domain.ErrWeakPassword},
		{name: "WeakPassword", password: "password", wantError: domain.ErrWeakPassword},
		{name: "HasherError", password: "Correct Horse Battery Staple 123!", hashError: errors.New("hash failed"), wantError: errors.New("hash failed"), wantHashCalls: 1},
		{name: "RepositoryError", password: "Correct Horse Battery Staple 123!", repoError: errors.New("database failed"), wantError: errors.New("failed to register user: database failed"), wantHash: []byte("hashed"), wantHashCalls: 1, wantRepoCalls: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &registerRepositoryMock{createFunc: func(context.Context, *domain.User) (int64, int, error) {
				if tt.repoError != nil {
					return 0, 0, tt.repoError
				}
				return 42, 1, nil
			}}
			hasher := &registerHasherMock{hashFunc: func([]byte) ([]byte, error) {
				return tt.wantHash, tt.hashError
			}}
			input := service.RegisterInput{}
			if tt.nilPassword {
				input.Name = "test_user"
				input.Email = "test_user@example.com"
			} else {
				input = newRegisterInput(t, tt.password)
			}

			gotID, gotVersion, gotSession, err := NewRegisterService(repo, hasher, &registerRefreshTokenMock{}).RegisterFunction(context.Background(), input)

			if tt.wantError != nil {
				require.Error(t, err)
				assert.Equal(t, tt.wantError.Error(), err.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantID, gotID)
				assert.Equal(t, tt.wantVersion, gotVersion)
				assert.Equal(t, sessionIDRegister, gotSession)
				assert.Equal(t, "test_user", repo.createdUser.Name)
				assert.Equal(t, "test_user@example.com", repo.createdUser.Email)
				assert.Equal(t, 1, repo.createdUser.JWTVersion)
				assert.Equal(t, tt.wantHash, repo.createdUser.PasswordHash)
			}
			assert.Equal(t, tt.wantHashCalls, hasher.hashCalls)
			assert.Equal(t, tt.wantRepoCalls, repo.createCalls)
		})
	}
}

func TestCreateRefreshToken_Scenarios(t *testing.T) {
	originalRandomRead, originalNow := registerRandomRead, registerNow
	t.Cleanup(func() { registerRandomRead, registerNow = originalRandomRead, originalNow })

	fixedNow := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	registerNow = func() time.Time { return fixedNow }

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
			registerRandomRead = func(buffer []byte) (int, error) {
				if tt.randomError != nil {
					return 0, tt.randomError
				}
				for index := range buffer {
					buffer[index] = byte(index + 1)
				}
				return len(buffer), nil
			}
			store := &registerRefreshTokenMock{saveFunc: func(context.Context, domain.RefreshToken) error { return tt.saveError }}
			serviceUnderTest := NewRegisterService(&registerRepositoryMock{}, &registerHasherMock{}, store)

			got, err := serviceUnderTest.CreateRefreshToken(context.Background(), tt.userID, tt.duration)

			if tt.wantError != nil {
				require.Error(t, err)
				assert.Equal(t, tt.wantError.Error(), err.Error())
				assert.Empty(t, got)
				wantSaveCalls := 1
				if tt.randomError != nil {
					wantSaveCalls = 0
				}
				assert.Equal(t, wantSaveCalls, store.saveCalls)
				return
			}

			require.NoError(t, err)
			assert.Len(t, got, 64)
			assert.Equal(t, tt.userID, store.saved.UserID)
			assert.Equal(t, hex.EncodeToString(sha256Bytes([]byte(got))), store.saved.Token)
			assert.Equal(t, fixedNow.Add(tt.duration), store.saved.ExpiresAt)
			assert.NotEqual(t, uuid.Nil, store.saved.SessionID)
			assert.Equal(t, 1, store.saveCalls)
		})
	}
}

func sha256Bytes(value []byte) []byte {
	hash := sha256.Sum256(value)
	return hash[:]
}
