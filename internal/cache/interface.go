// Package cache provides caching abstraction
package cache

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrCacheMiss indicates that the key was not found in cache
	ErrCacheMiss = errors.New("cache miss")
	// ErrCacheUnavailable indicates that the cache is unavailable
	ErrCacheUnavailable = errors.New("cache unavailable")
)

// Service defines the caching interface
type Service interface {
	// Get retrieves a value from cache and unmarshals it into dest
	Get(ctx context.Context, key string, dest interface{}) error

	// Set stores a value in cache with the given TTL
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error

	// Delete removes a key from cache
	Delete(ctx context.Context, key string) error

	// Exists checks if a key exists in cache
	Exists(ctx context.Context, key string) (bool, error)

	// Ping checks if the cache is available
	Ping(ctx context.Context) error
}
