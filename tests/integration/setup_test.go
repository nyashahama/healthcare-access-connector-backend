//go:build integration

package integration

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/modules/redis"
)

var (
	dbURL  string
	redisURL string
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	postgresContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
	)
	if err != nil {
		log.Fatalf("failed to start postgres container: %v", err)
	}
	defer func() {
		if err := postgresContainer.Terminate(ctx); err != nil {
			log.Printf("failed to terminate postgres container: %v", err)
		}
	}()

	redisContainer, err := redis.Run(ctx,
		"redis:7-alpine",
	)
	if err != nil {
		log.Fatalf("failed to start redis container: %v", err)
	}
	defer func() {
		if err := redisContainer.Terminate(ctx); err != nil {
			log.Printf("failed to terminate redis container: %v", err)
		}
	}()

	dbURL, err = postgresContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		log.Fatalf("failed to get postgres connection string: %v", err)
	}

	redisURL, err = redisContainer.ConnectionString(ctx)
	if err != nil {
		log.Fatalf("failed to get redis connection string: %v", err)
	}

	os.Setenv("DB_URL", dbURL)
	os.Setenv("REDIS_URL", redisURL)
	os.Setenv("JWT_SECRET", "test-jwt-secret-key-for-integration-tests")
	os.Setenv("ENVIRONMENT", "test")

	time.Sleep(2 * time.Second)

	absPath := filepath.Join("..", "..", "database/migrations")
	migration, err := migrate.New(
		"file://"+absPath,
		dbURL,
	)
	if err != nil {
		log.Fatalf("failed to create migration: %v", err)
	}

	if err := migration.Up(); err != nil && err != migrate.ErrNoChange {
		log.Fatalf("failed to run migrations: %v", err)
	}

	log.Printf("Integration test setup complete - DB: %s, Redis: %s", dbURL, redisURL)

	os.Exit(m.Run())
}