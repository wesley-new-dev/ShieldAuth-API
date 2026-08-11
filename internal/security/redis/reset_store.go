package redis

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type PasswordResetStore interface {
	Get(ctx context.Context, key string) (string, error)
	Delete(ctx context.Context, key string) error
	Save(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	Exists(ctx context.Context, key string) (bool, error)
}

type ResetPassword struct {
	rdb *redis.Client
}

func NewResetPassword(rdb *redis.Client) *ResetPassword {
	return &ResetPassword{rdb: rdb}
}

func (r *ResetPassword) Get(ctx context.Context, key string) (string, error) {
	return r.rdb.Get(ctx, key).Result()
}

func (r *ResetPassword) Delete(ctx context.Context, key string) error {
	return r.rdb.Del(ctx, key).Err()
}

func (r *ResetPassword) Save(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	return r.rdb.Set(ctx, key, value, ttl).Err()
}

func (r *ResetPassword) Exists(ctx context.Context, key string) (bool, error) {
	count, err := r.rdb.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
