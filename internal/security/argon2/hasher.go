package argon2

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/security"

	"golang.org/x/crypto/argon2"
)

type Argon2Hasher struct {
	memory 			uint32
	iterations 		uint32
	parallelism 	uint8
	keyLength 		uint32
	saltLength		uint32
}
type HashMetaData struct {
	Version 		int
	Memory 			uint32
	Iterations 		uint32
	Parallelism 	uint8
}


func NewArgon2Hasher() *Argon2Hasher {
	return &Argon2Hasher{
		memory: 		64 * 1024,
		iterations: 	3,
		parallelism: 	4,
		keyLength: 		32,
		saltLength: 	16,
	}
}


func (h *Argon2Hasher) Hash(password []byte) ([]byte, error) {
	salt := make([]byte, h.saltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	defer security.ZeroMemory(salt)

	hash := argon2.IDKey(password, salt, h.iterations, h.memory, h.parallelism, h.keyLength)
	defer security.ZeroMemory(hash)

	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, h.memory, h.iterations, h.parallelism, saltB64, hashB64)

	return []byte(encoded), nil
}


func (h *Argon2Hasher) Compare(password []byte, passwordHash []byte) (*HashMetaData, error) {

	const (
		maxMemory 		= 1024 * 1024
		maxIterations 	= 20
		maxParallelism 	= 16
	)

	const (
		minMemory 		= 8 * 1024
		minIterations 	= 2
		minParallelism 	= 1
	)

	parts := strings.Split(string(passwordHash), "$")

	if len(parts) != 6 {
		return nil, domain.ErrInvalidCredentials
	}

	if parts[1] != "argon2id" {
		return nil, domain.ErrInvalidCredentials
	}

	var version int
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	if version != argon2.Version {
		return nil, domain.ErrInvalidCredentials
	}

	var memory 		uint32
	var iterations 	uint32
	var parallelism uint8

	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	storedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	if memory < minMemory || memory > maxMemory {
		return nil, domain.ErrInvalidCredentials
	}

	if iterations < minIterations || iterations > maxIterations {
		return nil, domain.ErrInvalidCredentials
	}

	if parallelism < minParallelism || parallelism > maxParallelism {
		return nil, domain.ErrInvalidCredentials
	}

	newHash := argon2.IDKey(password,salt,iterations,memory,parallelism,uint32(len(storedHash)))

	if subtle.ConstantTimeCompare(storedHash, newHash) != 1 {
		return nil, domain.ErrInvalidCredentials
	}

	return &HashMetaData{Version: version, Memory: memory, Iterations: iterations, Parallelism: parallelism}, nil
}


func (h *Argon2Hasher) NeedsRehash(memory uint32, iterations uint32, parallelism uint8) bool {
	return memory != h.memory || iterations != h.iterations || parallelism != h.parallelism
}