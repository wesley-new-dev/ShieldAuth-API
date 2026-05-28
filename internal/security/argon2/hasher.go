package argon2

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/security"

	"golang.org/x/crypto/argon2"
)

type Argon2Hasher struct {
	memory uint32
	iterations uint32
	parallelism uint8
	keyLength uint32
	saltLenth uint32
}

func NewArgon2Hasher() *Argon2Hasher {
	return &Argon2Hasher{
		memory: 64 * 1024,
		iterations: 3,
		parallelism: 4,
		keyLength: 32,
		saltLenth: 16,
	}
}


func (h *Argon2Hasher) Hash(password []byte) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return base64.RawStdEncoding.EncodeToString(append(salt, hash...)), nil
}


func (h *Argon2Hasher) Compare(password []byte, passwordHash []byte) error {
	dbBuf := make([]byte, base64.RawStdEncoding.DecodedLen(len(passwordHash)))

	n, err := base64.RawStdEncoding.Decode(dbBuf, passwordHash)
	if err != nil {
		security.ZeroMemory(dbBuf)
		return err
	}

	data := dbBuf[:n]
	defer security.ZeroMemory(dbBuf)

	if len(data) < 16 {
		return domain.ErrInvalidPassword
	}

	salt := data[:16]
	hash := data[16:]

	newHash := argon2.IDKey(password, salt, 3, 64*1024, 4, 32)
	defer security.ZeroMemory(newHash)

	if subtle.ConstantTimeCompare(hash, newHash) == 1 {
		return nil
	}

	return domain.ErrInvalidPassword
}