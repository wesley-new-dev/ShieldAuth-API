package security

import (
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)


func TokenJWT(userID int64) (string, error) {
	claims := jwt.RegisteredClaims{
		Subject: strconv.FormatInt(userID, 10),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
		ID: uuid.NewString(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	secretKey := os.Getenv("JWT_KEY")
	return token.SignedString([]byte(secretKey))
}