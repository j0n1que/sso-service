package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/j0n1que/sso-service/internal/storage"
)

type TokenStorage struct {
	db *redis.Client
}

func New(addr, password string) *TokenStorage {
	return &TokenStorage{
		db: redis.NewClient(&redis.Options{
			Addr:     addr,
			Password: password,
			DB:       0,
		}),
	}
}

func (db *TokenStorage) Close() {
	db.db.Close()
}

func (db *TokenStorage) JWT(ctx context.Context, userID int64) (string, error) {
	const op = "storage.redis.JWT"

	key := fmt.Sprintf("user:%d", userID)

	token, err := db.db.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", fmt.Errorf("%s: %w", op, storage.ErrTokenNotFound)
		}
		return "", fmt.Errorf("%s: failed to get JWT for user %d: %w", op, userID, err)
	}

	return token, nil
}

func (db *TokenStorage) SaveJWT(ctx context.Context, token string, userID int64, ttl time.Duration) error {
	const op = "storage.redis.SaveJWT"

	key := fmt.Sprintf("user:%d", userID)

	wasSet, err := db.db.SetNX(ctx, key, token, ttl).Result()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if !wasSet {
		return fmt.Errorf("%s %w", op, storage.ErrTokenExists)
	}

	return nil
}

func (db *TokenStorage) DeleteJWT(ctx context.Context, userID int64) error {
	const op = "storage.redis.DeleteJWT"

	key := fmt.Sprintf("user:%d", userID)

	err := db.db.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}
