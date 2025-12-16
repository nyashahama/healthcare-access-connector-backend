// Package cache implements Redis caching with in-memory fallback
package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
)

type cacheEntry struct {
	value      interface{}
	expiration time.Time
}

type redisCache struct {
	redis       *redis.Client
	fallback    sync.Map
	logger      *zerolog.Logger
	defaultTTL  time.Duration
	useRedis    bool
	cleanupOnce sync.Once
}

// NewRedisCache creates a new Redis cache service with in-memory fallback
func NewRedisCache(redisURL string, logger *zerolog.Logger, defaultTTL time.Duration) Service {
	cache := &redisCache{
		logger:     logger,
		defaultTTL: defaultTTL,
		useRedis:   false,
	}

	if redisURL != "" {
		opts, err := redis.ParseURL(redisURL)
		if err != nil {
			logger.Warn().Err(err).Msg("Invalid Redis URL, using in-memory cache")
			return cache
		}

		rdb := redis.NewClient(opts)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := rdb.Ping(ctx).Err(); err != nil {
			logger.Warn().Err(err).Msg("Redis unavailable, using in-memory cache")
			return cache
		}

		cache.redis = rdb
		cache.useRedis = true
		logger.Info().Msg("Redis cache initialized")
	}

	// Start cleanup goroutine for in-memory cache
	cache.startCleanup()

	return cache
}

func (c *redisCache) Get(ctx context.Context, key string, dest interface{}) error {
	if c.useRedis {
		return c.getFromRedis(ctx, key, dest)
	}
	return c.getFromMemory(key, dest)
}

func (c *redisCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	if ttl == 0 {
		ttl = c.defaultTTL
	}

	if c.useRedis {
		return c.setToRedis(ctx, key, value, ttl)
	}
	return c.setToMemory(key, value, ttl)
}

func (c *redisCache) Delete(ctx context.Context, key string) error {
	if c.useRedis {
		return c.redis.Del(ctx, key).Err()
	}
	c.fallback.Delete(key)
	return nil
}

func (c *redisCache) Exists(ctx context.Context, key string) (bool, error) {
	if c.useRedis {
		result, err := c.redis.Exists(ctx, key).Result()
		return result > 0, err
	}

	_, ok := c.fallback.Load(key)
	return ok, nil
}

func (c *redisCache) Ping(ctx context.Context) error {
	if c.useRedis {
		return c.redis.Ping(ctx).Err()
	}
	return nil
}

// getFromRedis retrieves value from Redis
func (c *redisCache) getFromRedis(ctx context.Context, key string, dest interface{}) error {
	val, err := c.redis.Get(ctx, key).Result()
	if err == redis.Nil {
		return ErrCacheMiss
	}
	if err != nil {
		c.logger.Error().Err(err).Str("key", key).Msg("Redis get failed")
		return fmt.Errorf("redis get: %w", err)
	}

	if err := json.Unmarshal([]byte(val), dest); err != nil {
		return fmt.Errorf("unmarshal cache value: %w", err)
	}

	return nil
}

// setToRedis stores value in Redis
func (c *redisCache) setToRedis(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal cache value: %w", err)
	}

	if err := c.redis.Set(ctx, key, data, ttl).Err(); err != nil {
		c.logger.Error().Err(err).Str("key", key).Msg("Redis set failed")
		return fmt.Errorf("redis set: %w", err)
	}

	return nil
}

// getFromMemory retrieves value from in-memory cache
func (c *redisCache) getFromMemory(key string, dest interface{}) error {
	val, ok := c.fallback.Load(key)
	if !ok {
		return ErrCacheMiss
	}

	entry, ok := val.(cacheEntry)
	if !ok {
		c.fallback.Delete(key)
		return ErrCacheMiss
	}

	// Check expiration
	if time.Now().After(entry.expiration) {
		c.fallback.Delete(key)
		return ErrCacheMiss
	}

	// Copy value using JSON marshaling/unmarshaling
	data, err := json.Marshal(entry.value)
	if err != nil {
		return fmt.Errorf("marshal cached value: %w", err)
	}

	if err := json.Unmarshal(data, dest); err != nil {
		return fmt.Errorf("unmarshal cached value: %w", err)
	}

	return nil
}

// setToMemory stores value in in-memory cache
func (c *redisCache) setToMemory(key string, value interface{}, ttl time.Duration) error {
	entry := cacheEntry{
		value:      value,
		expiration: time.Now().Add(ttl),
	}
	c.fallback.Store(key, entry)
	return nil
}

// startCleanup starts a goroutine to clean up expired entries
func (c *redisCache) startCleanup() {
	c.cleanupOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(1 * time.Minute)
			defer ticker.Stop()

			for range ticker.C {
				now := time.Now()
				c.fallback.Range(func(key, value interface{}) bool {
					entry, ok := value.(cacheEntry)
					if !ok || now.After(entry.expiration) {
						c.fallback.Delete(key)
					}
					return true
				})
			}
		}()
	})
}
