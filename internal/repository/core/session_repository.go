// Package core
package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	sessionDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "session_db_query_duration_seconds",
			Help:    "Session database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	sessionDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "session_db_query_total",
			Help: "Total number of session database queries",
		},
		[]string{"operation", "status"},
	)
)

type sessionRepository struct {
	querier sqlc.Querier
}

// NewSessionRepository creates a new session repository using a pool
func NewSessionRepository(pool *pgxpool.Pool) repository.SessionRepository {
	return NewSessionRepositoryWithQuerier(sqlc.New(pool))
}

// NewSessionRepositoryWithQuerier creates a new session repository using a provided querier (for transactions)
func NewSessionRepositoryWithQuerier(querier sqlc.Querier) repository.SessionRepository {
	return &sessionRepository{
		querier: querier,
	}
}

func (r *sessionRepository) CreateSession(ctx context.Context, session core.UserSession) (core.UserSession, error) {
	start := time.Now()
	defer func() {
		sessionDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Convert IP address string to netip.Addr
	var ipAddr *netip.Addr
	if session.IPAddress != nil {
		addr, err := netip.ParseAddr(*session.IPAddress)
		if err == nil {
			ipAddr = &addr
		}
	}

	created, err := r.querier.CreateSession(ctx, sqlc.CreateSessionParams{
		UserID:       uuidToPgtypeUUID(session.UserID),
		SessionToken: session.SessionToken,
		DeviceType:   pgtypeTextFromStringPtr(session.DeviceType),
		DeviceID:     pgtypeTextFromStringPtr(session.DeviceID),
		IpAddress:    ipAddr,
		UserAgent:    pgtypeTextFromStringPtr(session.UserAgent),
		ExpiresAt:    timeToPgtypeTimestamp(session.ExpiresAt),
	})
	if err != nil {
		sessionDBQueryTotal.WithLabelValues("create_session", "error").Inc()
		return core.UserSession{}, r.handleError(err, "create session")
	}

	sessionDBQueryTotal.WithLabelValues("create_session", "success").Inc()
	return r.mapToUserSession(created), nil
}

func (r *sessionRepository) GetSession(ctx context.Context, sessionToken string) (core.UserSession, error) {
	start := time.Now()
	defer func() {
		sessionDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	session, err := r.querier.GetSession(ctx, sessionToken)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			sessionDBQueryTotal.WithLabelValues("get_session", "not_found").Inc()
			return core.UserSession{}, domain.ErrSessionNotFound
		}
		sessionDBQueryTotal.WithLabelValues("get_session", "error").Inc()
		return core.UserSession{}, r.handleError(err, "get session")
	}

	sessionDBQueryTotal.WithLabelValues("get_session", "success").Inc()
	return r.mapToUserSessionFromGet(session), nil
}

func (r *sessionRepository) DeleteSession(ctx context.Context, sessionToken string) error {
	start := time.Now()
	defer func() {
		sessionDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeleteSession(ctx, sessionToken)
	if err != nil {
		sessionDBQueryTotal.WithLabelValues("delete_session", "error").Inc()
		return r.handleError(err, "delete session")
	}

	sessionDBQueryTotal.WithLabelValues("delete_session", "success").Inc()
	return nil
}

func (r *sessionRepository) DeleteUserSessions(ctx context.Context, userID uuid.UUID) error {
	start := time.Now()
	defer func() {
		sessionDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeleteUserSessions(ctx, uuidToPgtypeUUID(userID))
	if err != nil {
		sessionDBQueryTotal.WithLabelValues("delete_user_sessions", "error").Inc()
		return r.handleError(err, "delete user sessions")
	}

	sessionDBQueryTotal.WithLabelValues("delete_user_sessions", "success").Inc()
	return nil
}

func (r *sessionRepository) DeleteExpiredSessions(ctx context.Context) error {
	start := time.Now()
	defer func() {
		sessionDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeleteExpiredSessions(ctx)
	if err != nil {
		sessionDBQueryTotal.WithLabelValues("delete_expired_sessions", "error").Inc()
		return r.handleError(err, "delete expired sessions")
	}

	sessionDBQueryTotal.WithLabelValues("delete_expired_sessions", "success").Inc()
	return nil
}

func (r *sessionRepository) UpdateSessionToken(ctx context.Context, id uuid.UUID, sessionToken string, expiresAt time.Time) error {
	start := time.Now()
	defer func() {
		sessionDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateSessionToken(ctx, sqlc.UpdateSessionTokenParams{
		ID:           uuidToPgtypeUUID(id),
		SessionToken: sessionToken,
		ExpiresAt:    timeToPgtypeTimestamp(expiresAt),
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			sessionDBQueryTotal.WithLabelValues("update_session_token", "not_found").Inc()
			return domain.ErrSessionNotFound
		}
		sessionDBQueryTotal.WithLabelValues("update_session_token", "error").Inc()
		return r.handleError(err, "update session token")
	}

	sessionDBQueryTotal.WithLabelValues("update_session_token", "success").Inc()
	return nil
}

func (r *sessionRepository) GetUserSessions(ctx context.Context, userID uuid.UUID) ([]core.UserSession, error) {
	start := time.Now()
	defer func() {
		sessionDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	sessions, err := r.querier.GetUserSessions(ctx, uuidToPgtypeUUID(userID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			sessionDBQueryTotal.WithLabelValues("get_user_sessions", "not_found").Inc()
			return []core.UserSession{}, nil
		}
		sessionDBQueryTotal.WithLabelValues("get_user_sessions", "error").Inc()
		return nil, r.handleError(err, "get user sessions")
	}

	sessionDBQueryTotal.WithLabelValues("get_user_sessions", "success").Inc()
	return r.mapToUserSessions(sessions), nil
}

func (r *sessionRepository) RevokeAllExceptCurrent(ctx context.Context, userID, currentSessionID uuid.UUID) error {
	start := time.Now()
	defer func() {
		sessionDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeleteAllSessionsExcept(ctx, sqlc.DeleteAllSessionsExceptParams{
		UserID: uuidToPgtypeUUID(userID),
		ID:     uuidToPgtypeUUID(currentSessionID),
	})
	if err != nil {
		sessionDBQueryTotal.WithLabelValues("revoke_all_except_current", "error").Inc()
		return r.handleError(err, "revoke all except current session")
	}

	sessionDBQueryTotal.WithLabelValues("revoke_all_except_current", "success").Inc()
	return nil
}

func (r *sessionRepository) InvalidateSessionByDevice(ctx context.Context, userID uuid.UUID, deviceID string) error {
	start := time.Now()
	defer func() {
		sessionDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeleteSessionByDevice(ctx, sqlc.DeleteSessionByDeviceParams{
		UserID:   uuidToPgtypeUUID(userID),
		DeviceID: pgtype.Text{String: deviceID, Valid: true},
	})
	if err != nil {
		sessionDBQueryTotal.WithLabelValues("invalidate_session_by_device", "error").Inc()
		return r.handleError(err, "invalidate session by device")
	}

	sessionDBQueryTotal.WithLabelValues("invalidate_session_by_device", "success").Inc()
	return nil
}

// handleError converts database errors to domain errors
func (r *sessionRepository) handleError(err error, operation string) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23503": // foreign_key_violation
			return fmt.Errorf("foreign key violation: %w", err)
		case "23514": // check_violation
			return fmt.Errorf("check constraint violation: %w", err)
		}
	}
	return fmt.Errorf("%s failed: %w", operation, err)
}

// Helper mapping functions
func (r *sessionRepository) mapToUserSession(row sqlc.UserSession) core.UserSession {
	// Convert netip.Addr to string pointer
	var ipAddr *string
	if row.IpAddress != nil {
		addrStr := row.IpAddress.String()
		ipAddr = &addrStr
	}

	return core.UserSession{
		ID:           pgtypeUUIDToUUID(row.ID),
		UserID:       pgtypeUUIDToUUID(row.UserID),
		SessionToken: row.SessionToken,
		DeviceType:   pgtypeTextToStringPtr(row.DeviceType),
		DeviceID:     pgtypeTextToStringPtr(row.DeviceID),
		IPAddress:    ipAddr,
		UserAgent:    pgtypeTextToStringPtr(row.UserAgent),
		ExpiresAt:    row.ExpiresAt.Time,
		CreatedAt:    row.CreatedAt.Time,
	}
}

func (r *sessionRepository) mapToUserSessionFromGet(row sqlc.GetSessionRow) core.UserSession {
	// Convert netip.Addr to string pointer
	var ipAddr *string
	if row.IpAddress != nil {
		addrStr := row.IpAddress.String()
		ipAddr = &addrStr
	}

	return core.UserSession{
		ID:           pgtypeUUIDToUUID(row.ID),
		UserID:       pgtypeUUIDToUUID(row.UserID),
		SessionToken: row.SessionToken,
		DeviceType:   pgtypeTextToStringPtr(row.DeviceType),
		DeviceID:     nil, // Not included in GetSession query
		IPAddress:    ipAddr,
		UserAgent:    pgtypeTextToStringPtr(row.UserAgent),
		ExpiresAt:    row.ExpiresAt.Time,
		CreatedAt:    row.CreatedAt.Time,
	}
}

func (r *sessionRepository) mapToUserSessions(rows []sqlc.UserSession) []core.UserSession {
	sessions := make([]core.UserSession, len(rows))
	for i, row := range rows {
		// Convert netip.Addr to string pointer
		var ipAddr *string
		if row.IpAddress != nil {
			addrStr := row.IpAddress.String()
			ipAddr = &addrStr
		}

		sessions[i] = core.UserSession{
			ID:           pgtypeUUIDToUUID(row.ID),
			UserID:       pgtypeUUIDToUUID(row.UserID),
			SessionToken: row.SessionToken,
			DeviceType:   pgtypeTextToStringPtr(row.DeviceType),
			DeviceID:     pgtypeTextToStringPtr(row.DeviceID),
			IPAddress:    ipAddr,
			UserAgent:    pgtypeTextToStringPtr(row.UserAgent),
			ExpiresAt:    row.ExpiresAt.Time,
			CreatedAt:    row.CreatedAt.Time,
		}
	}
	return sessions
}
