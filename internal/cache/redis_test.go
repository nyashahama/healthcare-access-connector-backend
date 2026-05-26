package cache

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedisCache_SetAndGet(t *testing.T) {
	cache := &redisCache{
		fallback:   sync.Map{},
		logger:     nil,
		defaultTTL: 5 * time.Minute,
		useRedis:   false,
	}

	t.Run("set and get string value", func(t *testing.T) {
		ctx := context.Background()
		key := "test-key-1"
		value := "test-value"

		err := cache.Set(ctx, key, value, time.Hour)
		require.NoError(t, err)

		var result string
		err = cache.Get(ctx, key, &result)
		require.NoError(t, err)
		assert.Equal(t, value, result)
	})

	t.Run("set and get struct value", func(t *testing.T) {
		ctx := context.Background()
		key := "test-key-2"
		value := struct {
			Name string `json:"name"`
			Age  int    `json:"age"`
		}{Name: "John", Age: 30}

		err := cache.Set(ctx, key, value, time.Hour)
		require.NoError(t, err)

		var result struct {
			Name string `json:"name"`
			Age  int    `json:"age"`
		}
		err = cache.Get(ctx, key, &result)
		require.NoError(t, err)
		assert.Equal(t, value.Name, result.Name)
		assert.Equal(t, value.Age, result.Age)
	})

	t.Run("cache miss returns error", func(t *testing.T) {
		ctx := context.Background()
		key := "non-existent-key"

		var result string
		err := cache.Get(ctx, key, &result)
		assert.Error(t, err)
		assert.Equal(t, ErrCacheMiss, err)
	})
}

func TestRedisCache_Delete(t *testing.T) {
	cache := &redisCache{
		fallback:   sync.Map{},
		logger:     nil,
		defaultTTL: 5 * time.Minute,
		useRedis:   false,
	}

	t.Run("delete existing key", func(t *testing.T) {
		ctx := context.Background()
		key := "test-key-delete"

		err := cache.Set(ctx, key, "value", time.Hour)
		require.NoError(t, err)

		err = cache.Delete(ctx, key)
		require.NoError(t, err)

		var result string
		err = cache.Get(ctx, key, &result)
		assert.Error(t, err)
		assert.Equal(t, ErrCacheMiss, err)
	})

	t.Run("delete non-existent key", func(t *testing.T) {
		ctx := context.Background()
		err := cache.Delete(ctx, "non-existent-key")
		require.NoError(t, err)
	})
}

func TestRedisCache_Exists(t *testing.T) {
	cache := &redisCache{
		fallback:   sync.Map{},
		logger:     nil,
		defaultTTL: 5 * time.Minute,
		useRedis:   false,
	}

	t.Run("returns true for existing key", func(t *testing.T) {
		ctx := context.Background()
		key := "test-key-exists"

		err := cache.Set(ctx, key, "value", time.Hour)
		require.NoError(t, err)

		exists, err := cache.Exists(ctx, key)
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("returns false for non-existent key", func(t *testing.T) {
		ctx := context.Background()
		exists, err := cache.Exists(ctx, "non-existent-key")
		require.NoError(t, err)
		assert.False(t, exists)
	})
}

func TestRedisCache_Ping(t *testing.T) {
	t.Run("in-memory cache ping succeeds", func(t *testing.T) {
		cache := &redisCache{
			useRedis: false,
		}

		err := cache.Ping(context.Background())
		require.NoError(t, err)
	})
}

func TestRedisCache_IsAvailable(t *testing.T) {
	t.Run("in-memory fallback always available", func(t *testing.T) {
		cache := &redisCache{
			useRedis: false,
		}

		assert.False(t, cache.IsAvailable())
	})

	t.Run("with nil redis client", func(t *testing.T) {
		cache := &redisCache{
			redis:    nil,
			useRedis: true,
		}

		assert.False(t, cache.IsAvailable())
	})
}

func TestRedisCache_DefaultTTL(t *testing.T) {
	cache := &redisCache{
		fallback:   sync.Map{},
		logger:     nil,
		defaultTTL: 5 * time.Minute,
		useRedis:   false,
	}

	ctx := context.Background()
	key := "test-key-default-ttl"

	err := cache.Set(ctx, key, "value", 0)
	require.NoError(t, err)

	entry, ok := cache.fallback.Load(key)
	require.True(t, ok)

	ce, ok := entry.(cacheEntry)
	require.True(t, ok)

	ttl := time.Until(ce.expiration)
	assert.True(t, ttl > 4*time.Minute && ttl <= 5*time.Minute)
}

func TestRedisCache_Expiration(t *testing.T) {
	cache := &redisCache{
		fallback:   sync.Map{},
		logger:     nil,
		defaultTTL: 5 * time.Minute,
		useRedis:   false,
	}

	t.Run("expired value returns cache miss", func(t *testing.T) {
		ctx := context.Background()
		key := "test-key-expired"

		cache.fallback.Store(key, cacheEntry{
			value:      "expired-value",
			expiration: time.Now().Add(-time.Hour),
		})

		var result string
		err := cache.Get(ctx, key, &result)
		assert.Error(t, err)
		assert.Equal(t, ErrCacheMiss, err)
	})
}

func TestRedisCache_ConcurrentAccess(t *testing.T) {
	cache := &redisCache{
		fallback:   sync.Map{},
		logger:     nil,
		defaultTTL: 5 * time.Minute,
		useRedis:   false,
	}

	ctx := context.Background()
	key := "test-key-concurrent"

	err := cache.Set(ctx, key, "initial-value", time.Hour)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			switch i % 3 {
			case 0:
				_ = cache.Set(ctx, key, "value", time.Hour)
			case 1:
				_ = cache.Get(ctx, key, new(string))
			case 2:
				_, _ = cache.Exists(ctx, key)
			}
		}(i)
	}

	wg.Wait()

	exists, err := cache.Exists(ctx, key)
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestRedisCache_ComplexTypes(t *testing.T) {
	cache := &redisCache{
		fallback:   sync.Map{},
		logger:     nil,
		defaultTTL: 5 * time.Minute,
		useRedis:   false,
	}

	t.Run("handles map values", func(t *testing.T) {
		ctx := context.Background()
		key := "test-key-map"

		value := map[string]interface{}{
			"string": "value",
			"number": 42,
			"nested": map[string]int{"a": 1},
		}

		err := cache.Set(ctx, key, value, time.Hour)
		require.NoError(t, err)

		var result map[string]interface{}
		err = cache.Get(ctx, key, &result)
		require.NoError(t, err)
		assert.Equal(t, "value", result["string"])
	})

	t.Run("handles slice values", func(t *testing.T) {
		ctx := context.Background()
		key := "test-key-slice"

		value := []int{1, 2, 3, 4, 5}

		err := cache.Set(ctx, key, value, time.Hour)
		require.NoError(t, err)

		var result []int
		err = cache.Get(ctx, key, &result)
		require.NoError(t, err)
		assert.Equal(t, value, result)
	})

	t.Run("handles named struct values", func(t *testing.T) {
		ctx := context.Background()
		key := "test-key-nested"

		type nestedItem struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		}
		type nestedData struct {
			Items []nestedItem `json:"items"`
		}
		type nestedValue struct {
			Data nestedData `json:"data"`
		}

		value := nestedValue{
			Data: nestedData{
				Items: []nestedItem{{ID: 1, Name: "Test"}},
			},
		}

		err := cache.Set(ctx, key, value, time.Hour)
		require.NoError(t, err)

		var result nestedValue
		err = cache.Get(ctx, key, &result)
		require.NoError(t, err)
		assert.Len(t, result.Data.Items, 1)
		assert.Equal(t, "Test", result.Data.Items[0].Name)
	})
}
