package security

import (
	"context"
	"time"

	// "ShieldAuth-API/internal/repository"
	"github.com/redis/go-redis/v9"
)

type PasswordResetStore interface {
	Get(ctx context.Context, token string) (string, error)
	Delete(ctx context.Context, token string) error
	Save(ctx context.Context, token string, userID int64, ttl time.Duration) error
}

type ResetPassword struct {
	rdb *redis.Client
}

func NewResetPassword(rdb *redis.Client) *ResetPassword {
	return &ResetPassword{rdb: rdb}
}


func (r *ResetPassword) Get(ctx context.Context, token string) (string , error) {
	key := "reset:" + token
	return r.rdb.Get(ctx, key).Result()
}

func (r *ResetPassword) Delete(ctx context.Context, token string) error {
	key := "reset:" + token
	return r.rdb.Del(ctx, key).Err()
}

func (r *ResetPassword) Save(ctx context.Context, token string, userID int, ttl time.Duration) error {
	key := "reset:" + token
	return r.rdb.Set(ctx, key, userID, ttl).Err()
}