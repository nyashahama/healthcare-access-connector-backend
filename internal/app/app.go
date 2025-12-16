// Package app handles application initialization and dependency injection
package app

import (
	"context"
	"fmt"

	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/config"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/email"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/messaging"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/server"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// App represents the application with all dependencies
type App struct {
	config *config.Config
	server *server.Server
	pool   *pgxpool.Pool
	logger *zerolog.Logger
}

// New creates a new application instance with all dependencies
func New(cfg *config.Config) (*App, error) {
	logger := cfg.Logger()

	// Initialize database connection pool
	pool, err := initDatabase(cfg.DBURL, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	// Initialize cache service
	cacheService := cache.NewRedisCache(cfg.RedisURL, logger, cfg.CacheTTL)

	// Initialize message broker
	broker, err := messaging.NewNATSBroker(cfg.NatsURL, logger)
	if err != nil {
		logger.Warn().Err(err).Msg("NATS broker unavailable, async operations disabled")
		// Don't return error, broker is optional
	}

	// Initialize email service
	emailService, err := email.NewFromEnv(logger)
	if err != nil {
		logger.Warn().Err(err).Msg("Email service initialization failed, continuing without email")
		// Don't return error, email is optional
	}

	// Initialize repositories
	userRepo := repository.NewUserRepository(pool)
	_ = repository.NewTxManager(pool) // Transaction manager available if needed

	// Initialize services
	authService := service.NewAuthService(
		userRepo,
		cacheService,
		broker,
		emailService,
		logger,
		cfg.JWTSecret,
		cfg.JWTExpiry,
	)
	userService := service.NewUserService(userRepo, cacheService, logger)

	// Initialize handlers
	authHandler := handler.NewAuthHandler(authService, userService, logger, cfg.Timeout)
	healthHandler := handler.NewHealthHandler(pool, cacheService, broker, emailService)

	// Initialize server
	srv := server.NewServer(cfg, logger, authHandler, healthHandler, authService)

	return &App{
		config: cfg,
		server: srv,
		pool:   pool,
		logger: logger,
	}, nil
}

// Run starts the application
func (a *App) Run() error {
	a.logger.Info().
		Str("environment", a.config.Environment).
		Str("port", a.config.Port).
		Msg("Starting application")

	return a.server.Start()
}

// Cleanup performs cleanup operations
func (a *App) Cleanup() {
	if a.pool != nil {
		a.pool.Close()
		a.logger.Info().Msg("Database connection closed")
	}
}

// initDatabase initializes the database connection pool
func initDatabase(dbURL string, logger *zerolog.Logger) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		return nil, err
	}

	// Test connection
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	logger.Info().Msg("Database connection established")
	return pool, nil
}
