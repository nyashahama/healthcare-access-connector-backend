// Package app handles application initialization and dependency injection
package app

import (
	"context"
	"fmt"
	"time"

	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/config"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/email"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/messaging"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/server"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"

	"github.com/jackc/pgx/v5"
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

	// Initialize database connection pool with proper configuration
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

// initDatabase initializes the database connection pool with optimized settings
func initDatabase(dbURL string, logger *zerolog.Logger) (*pgxpool.Pool, error) {
	// Parse the database URL
	config, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database URL: %w", err)
	}

	// Configure connection pool settings
	config.MaxConns = 25                       // Maximum number of connections
	config.MinConns = 5                        // Minimum number of idle connections
	config.MaxConnLifetime = 1 * time.Hour     // Max lifetime of a connection
	config.MaxConnIdleTime = 30 * time.Minute  // Max time a connection can be idle
	config.HealthCheckPeriod = 1 * time.Minute // How often to check connection health

	// CRITICAL FIX: Disable prepared statement cache to prevent conflicts
	// This is the root cause of the "prepared statement already exists" error
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	// Alternative: Use describe mode which is safer than exec mode
	// config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeDescribeExec

	// Create connection pool with configured settings
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	logger.Info().
		Int32("max_conns", config.MaxConns).
		Int32("min_conns", config.MinConns).
		Str("query_mode", "simple_protocol").
		Msg("Database connection pool established")

	return pool, nil
}
