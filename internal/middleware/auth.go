package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type ContextKey string
const Key ContextKey = "userID"

type Claims struct {
	jwt.RegisteredClaims
}
type AuthContext struct {
	UserID 		int
	TokenHash 	string
}

func AuthMiddleware(secretKey string) func(http.Handler) http.Handler {
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
				if t.Method != jwt.SigningMethodHS256{
					return nil, fmt.Errorf("unexpected signing method")
				}

				return []byte(secretKey), nil
			},)
	
			if err != nil || !token.Valid {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			claims, ok := token.Claims.(*Claims)
			if !ok {
				http.Error(w, "invalid claims", http.StatusUnauthorized)
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

			auth := AuthContext{
				UserID: userID,
				TokenHash: claims.ID,
			}
	
			ctx := context.WithValue(r.Context(), Key, auth)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}