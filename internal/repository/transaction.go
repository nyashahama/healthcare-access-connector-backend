// Package repository implements transaction management
package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type txKey struct{}

var txCtxKey = txKey{}

type txManager struct {
	pool *pgxpool.Pool
}

// NewTxManager creates a new transaction manager
func NewTxManager(pool *pgxpool.Pool) TxManager {
	return &txManager{pool: pool}
}

// WithTransaction executes a function within a database transaction
func (tm *txManager) WithTransaction(ctx context.Context, fn func(context.Context, pgx.Tx) error) error {
	// Check if there's already a transaction in the context
	if _, ok := tm.GetTransaction(ctx); ok {
		// Instead of error, we could use savepoints for nested transactions
		// But for simplicity, return error
		return fmt.Errorf("nested transactions not supported")
	}

	tx, err := tm.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Create a new context with the transaction
	newCtx := context.WithValue(ctx, txCtxKey, tx)

	// Ensure transaction is either committed or rolled back
	defer func() {
		if p := recover(); p != nil {
			// Rollback on panic
			_ = tx.Rollback(newCtx) // Ignore error on panic
			panic(p)                // Re-panic
		}
	}()

	// Execute the function within the transaction
	if err := fn(newCtx, tx); err != nil {
		// Rollback on error
		if rbErr := tx.Rollback(newCtx); rbErr != nil {
			return fmt.Errorf("transaction error: %w, rollback error: %v", err, rbErr)
		}
		return err
	}

	// Commit transaction
	if err := tx.Commit(newCtx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// WithReadOnlyTransaction executes a function within a read-only database transaction
func (tm *txManager) WithReadOnlyTransaction(ctx context.Context, fn func(context.Context, pgx.Tx) error) error {
	// Check if there's already a transaction in the context
	if _, ok := tm.GetTransaction(ctx); ok {
		return fmt.Errorf("nested transactions not supported")
	}

	// Use proper isolation level for read-only
	tx, err := tm.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return fmt.Errorf("failed to begin read-only transaction: %w", err)
	}

	// Create a new context with the transaction
	newCtx := context.WithValue(ctx, txCtxKey, tx)

	// Ensure transaction is rolled back
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(newCtx)
			panic(p)
		}
	}()

	// Execute the function
	if err := fn(newCtx, tx); err != nil {
		if rbErr := tx.Rollback(newCtx); rbErr != nil {
			return fmt.Errorf("read-only transaction error: %w, rollback error: %v", err, rbErr)
		}
		return err
	}

	// Always rollback read-only transactions
	if err := tx.Rollback(newCtx); err != nil {
		return fmt.Errorf("failed to rollback read-only transaction: %w", err)
	}

	return nil
}

// WithRetryTransaction executes a function within a database transaction with retries
func (tm *txManager) WithRetryTransaction(ctx context.Context, maxRetries int, fn func(context.Context, pgx.Tx) error) error {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		err := tm.WithTransaction(ctx, fn)
		if err == nil {
			return nil
		}

		lastErr = err

		// Check if retryable
		if !tm.isRetriableError(err) {
			return fmt.Errorf("non-retriable transaction error (attempt %d): %w", attempt+1, err)
		}

		// Don't wait on last attempt
		if attempt < maxRetries {
			// Simple fixed delay (application layer should handle complex backoff)
			select {
			case <-time.After(time.Duration(attempt+1) * 100 * time.Millisecond):
			case <-ctx.Done():
				return fmt.Errorf("transaction retry cancelled: %w", ctx.Err())
			}
		}
	}

	return fmt.Errorf("max retries (%d) exceeded: %w", maxRetries, lastErr)
}

// GetTransaction retrieves the current transaction from the context if it exists
func (tm *txManager) GetTransaction(ctx context.Context) (pgx.Tx, bool) {
	tx, ok := ctx.Value(txCtxKey).(pgx.Tx)
	return tx, ok
}

// InTransaction checks if context has an active transaction
func (tm *txManager) InTransaction(ctx context.Context) bool {
	_, ok := tm.GetTransaction(ctx)
	return ok
}

// isRetriableError checks if error is retriable
func (tm *txManager) isRetriableError(err error) bool {
	if err == nil {
		return false
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		// Retry on serialization failures and deadlocks
		switch pgErr.Code {
		case "40001": // serialization_failure
		case "40P01": // deadlock_detected
			return true
		}
	}

	return false
}
