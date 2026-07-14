package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"ShieldAuth-API/internal/security/redis"

	"github.com/golang-jwt/jwt/v5"
)

type ContextKey string

const Key ContextKey = "userID"
const SessionIDKey ContextKey = "sessionID"

type Claims struct {
	Version   int    `json:"version"`
	SessionID string `json:"session_id"`
	jwt.RegisteredClaims
}
type AuthContext struct {
	UserID    int
	TokenHash string
	SessionID string
}

func AuthMiddleware(secretKey string, redis redis.PasswordResetStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")

			if tokenString == "" || tokenString == "null" {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
				if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method")
				}

				return []byte(secretKey), nil
			})

			if err != nil || !token.Valid {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			claims, ok := token.Claims.(*Claims)
			if !ok {
				http.Error(w, "invalid claims", http.StatusUnauthorized)
				return
			}

			isBlackListed, err := redis.Exists(r.Context(), "blacklist:"+claims.ID)
			if err == nil && isBlackListed {
				http.Error(w, "token revoked", http.StatusUnauthorized)
				return
			}

			if claims.Subject == "" {
				http.Error(w, "missing subject", http.StatusUnauthorized)
				return
			}

			userID, err := strconv.Atoi(claims.Subject)
			if err != nil {
				http.Error(w, "invalid user id", http.StatusUnauthorized)
				return
			}

			sessionIDKey := fmt.Sprintf("session:%d:%s", userID, claims.SessionID)
			isSessionActive, err := redis.Exists(r.Context(), sessionIDKey)
			if err != nil || !isSessionActive {
				http.Error(w, "session expired ot logged out", http.StatusUnauthorized)
				return
			}

			currentVersion, err := redis.Get(r.Context(), fmt.Sprintf("user:version:%d", userID))
			if err != nil {
				http.Error(w, "Unathorized session", http.StatusUnauthorized)
				return
			}

			newCurrentVersion, _ := strconv.Atoi(currentVersion)
			if claims.Version < newCurrentVersion {
				http.Error(w, "Token version expired. Please log in again", http.StatusUnauthorized)
				return
			}

			auth := AuthContext{
				UserID:    userID,
				TokenHash: claims.ID,
				SessionID: claims.SessionID,
			}

			ctx := context.WithValue(r.Context(), Key, auth)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

}
