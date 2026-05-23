package security

import (
	"context"
	"fmt"
	"time"
	
	"github.com/redis/go-redis/v9"
)

type RateLimiter interface {
	Allow(ctx context.Context, key string, maxAttempts int, window time.Duration) (bool, error)
}

type RedisLimiter struct {
	client *redis.Client
	scriptSha string
}

func NewRedisLimiter(addr string) (*RedisLimiter, error) {
	client := redis.NewClient(&redis.Options{
		Addr: addr,
	})

	script := `
		local current = redis.call("INCR", KEYS[1])
		if current == 1 then
			redis.call("PEXPIRE", KEYS[1], ARGV[1])
		end
		return current`

	sha, err := client.ScriptLoad(context.Background(), script).Result()
	if err != nil {
		return nil, err
	}

	return &RedisLimiter{
		client: client,
		scriptSha: sha,
	}, nil
}

func (rl *RedisLimiter) CheckLimit(ctx context.Context, key string, maxAttempts int, window time.Duration) (bool, error) {
	fullKey := fmt.Sprintf("rl:%s", key)

	result, err := rl.client.EvalSha(ctx, rl.scriptSha, []string{fullKey}, window.Milliseconds()).Int64()
	if err != nil {
		return false, err
	}

	return int(result) <= maxAttempts, nil
}

func (rl *RedisLimiter) ResetLimit(ctx context.Context, key string) error {
	fullKey := fmt.Sprintf("rl:%s", key)
	return rl.client.Del(ctx, fullKey).Err()
}