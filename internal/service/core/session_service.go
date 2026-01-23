package core

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
)

type sessionService struct {
	sessionRepo repository.SessionRepository
	userRepo    repository.UserRepository
	cache       cache.Service
	logger      *zerolog.Logger
}

// NewSessionService creates a new session service
func NewSessionService(
	sessionRepo repository.SessionRepository,
	userRepo repository.UserRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) service.SessionService {
	return &sessionService{
		sessionRepo: sessionRepo,
		userRepo:    userRepo,
		cache:       cache,
		logger:      logger,
	}
}

func (s *sessionService) CreateSession(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time, ipAddress, userAgent, deviceType string) (core.UserSession, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Msg("CreateSession completed")
	}()

	session := core.UserSession{
		ID:           uuid.New(),
		UserID:       userID,
		SessionToken: token,
		DeviceType:   stringPtr(deviceType),
		IPAddress:    stringPtr(ipAddress),
		UserAgent:    stringPtr(userAgent),
		ExpiresAt:    expiresAt,
		CreatedAt:    time.Now(),
	}

	createdSession, err := s.sessionRepo.CreateSession(ctx, session)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to create session")
		return core.UserSession{}, domain.NewAppError(err, "Failed to create session", 500)
	}

	// Cache the session
	cacheKey := fmt.Sprintf("session:%s", token)
	if err := s.cache.Set(ctx, cacheKey, createdSession, 5*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache session")
	}

	// Invalidate user sessions cache
	s.cache.Delete(ctx, fmt.Sprintf("user:sessions:%s", userID.String()))

	s.logger.Info().
		Str("session_id", createdSession.ID.String()).
		Str("user_id", userID.String()).
		Str("ip_address", ipAddress).
		Msg("Session created successfully")

	return createdSession, nil
}

// GetSession retrieves a session by token
func (s *sessionService) GetSession(ctx context.Context, token string) (core.UserSession, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("token_prefix", token[:8]).
			Msg("GetSession completed")
	}()

	// Try cache first
	cacheKey := fmt.Sprintf("session:%s", token)
	var session core.UserSession
	if err := s.cache.Get(ctx, cacheKey, &session); err == nil {
		s.logger.Debug().Str("token_prefix", token[:8]).Msg("Session retrieved from cache")
		return session, nil
	}

	// Fetch from database
	session, err := s.sessionRepo.GetSession(ctx, token)
	if err != nil {
		if errors.Is(err, domain.ErrSessionNotFound) {
			return core.UserSession{}, domain.NewAppError(domain.ErrInvalidSession, "Session not found", 404)
		}
		s.logger.Error().Err(err).Msg("Failed to get session")
		return core.UserSession{}, domain.NewAppError(err, "Failed to get session", 500)
	}

	// Check if session is expired
	if session.ExpiresAt.Before(time.Now()) {
		// Delete expired session asynchronously
		go s.cleanupExpiredSession(token)
		return core.UserSession{}, domain.NewAppError(domain.ErrSessionExpired, "Session expired", 401)
	}

	// Cache the session
	if err := s.cache.Set(ctx, cacheKey, session, 5*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache session")
	}

	return session, nil
}

// GetUserSessions retrieves all active sessions for a user
func (s *sessionService) GetUserSessions(ctx context.Context, userID uuid.UUID) ([]core.UserSession, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Msg("GetUserSessions completed")
	}()

	// Try cache first
	cacheKey := fmt.Sprintf("user:sessions:%s", userID.String())
	var sessions []core.UserSession
	if err := s.cache.Get(ctx, cacheKey, &sessions); err == nil {
		s.logger.Debug().Str("user_id", userID.String()).Msg("User sessions retrieved from cache")
		return sessions, nil
	}

	// Fetch from database
	sessions, err := s.sessionRepo.GetUserSessions(ctx, userID)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to get user sessions")
		return nil, domain.NewAppError(err, "Failed to get user sessions", 500)
	}

	// Filter out expired sessions
	activeSessions := make([]core.UserSession, 0, len(sessions))
	now := time.Now()
	for _, session := range sessions {
		if session.ExpiresAt.After(now) {
			activeSessions = append(activeSessions, session)
		}
	}

	// Cache the active sessions
	if err := s.cache.Set(ctx, cacheKey, activeSessions, 2*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache user sessions")
	}

	return activeSessions, nil
}

// RevokeSession revokes a specific session
func (s *sessionService) RevokeSession(ctx context.Context, token string, userID uuid.UUID) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("token_prefix", token[:8]).
			Str("user_id", userID.String()).
			Msg("RevokeSession completed")
	}()

	// Get session first to verify ownership
	session, err := s.sessionRepo.GetSession(ctx, token)
	if err != nil {
		if errors.Is(err, domain.ErrSessionNotFound) {
			return nil // Session already doesn't exist, nothing to do
		}
		s.logger.Error().Err(err).Msg("Failed to get session for revocation")
		return domain.NewAppError(err, "Failed to revoke session", 500)
	}

	// Verify session belongs to the user
	if session.UserID != userID {
		return domain.NewAppError(domain.ErrUnauthorized, "Cannot revoke another user's session", 403)
	}

	// Delete the session
	if err := s.sessionRepo.DeleteSession(ctx, token); err != nil {
		s.logger.Error().Err(err).Msg("Failed to delete session")
		return domain.NewAppError(err, "Failed to revoke session", 500)
	}

	// Invalidate caches
	s.invalidateSessionCaches(ctx, token, userID)

	s.logger.Info().
		Str("session_id", session.ID.String()).
		Str("user_id", userID.String()).
		Msg("Session revoked")

	return nil
}

// RevokeAllSessions revokes all sessions for a user
func (s *sessionService) RevokeAllSessions(ctx context.Context, userID uuid.UUID) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Msg("RevokeAllSessions completed")
	}()

	// Delete all user sessions
	if err := s.sessionRepo.DeleteUserSessions(ctx, userID); err != nil {
		s.logger.Error().Err(err).Msg("Failed to delete user sessions")
		return domain.NewAppError(err, "Failed to revoke all sessions", 500)
	}

	// Invalidate cache
	s.cache.Delete(ctx, fmt.Sprintf("user:sessions:%s", userID.String()))

	s.logger.Info().
		Str("user_id", userID.String()).
		Msg("All sessions revoked for user")

	return nil
}

// RevokeAllExceptCurrent revokes all sessions except the current one
func (s *sessionService) RevokeAllExceptCurrent(ctx context.Context, userID, currentSessionID uuid.UUID) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Str("current_session_id", currentSessionID.String()).
			Msg("RevokeAllExceptCurrent completed")
	}()

	// Revoke all sessions except current
	if err := s.sessionRepo.RevokeAllExceptCurrent(ctx, userID, currentSessionID); err != nil {
		s.logger.Error().Err(err).Msg("Failed to revoke other sessions")
		return domain.NewAppError(err, "Failed to revoke other sessions", 500)
	}

	// Invalidate cache
	s.cache.Delete(ctx, fmt.Sprintf("user:sessions:%s", userID.String()))

	s.logger.Info().
		Str("user_id", userID.String()).
		Str("current_session_id", currentSessionID.String()).
		Msg("All other sessions revoked")

	return nil
}

// InvalidateSessionByDevice invalidates session by device ID
func (s *sessionService) InvalidateSessionByDevice(ctx context.Context, userID uuid.UUID, deviceID string) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Str("device_id", deviceID).
			Msg("InvalidateSessionByDevice completed")
	}()

	// Get user sessions first to find the device session
	sessions, err := s.sessionRepo.GetUserSessions(ctx, userID)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to get user sessions")
		return domain.NewAppError(err, "Failed to invalidate device session", 500)
	}

	// Find and delete session by device
	for _, session := range sessions {
		if session.DeviceID != nil && *session.DeviceID == deviceID {
			if err := s.sessionRepo.DeleteSession(ctx, session.SessionToken); err != nil {
				s.logger.Warn().Err(err).Msg("Failed to delete device session")
				continue
			}

			// Invalidate cache
			s.invalidateSessionCaches(ctx, session.SessionToken, userID)

			s.logger.Info().
				Str("user_id", userID.String()).
				Str("device_id", deviceID).
				Msg("Device session invalidated")

			return nil
		}
	}

	// Device session not found
	s.logger.Debug().
		Str("user_id", userID.String()).
		Str("device_id", deviceID).
		Msg("No session found for device")

	return nil
}

// UpdateSessionToken updates a session token
func (s *sessionService) UpdateSessionToken(ctx context.Context, sessionID uuid.UUID, newToken string, expiresAt time.Time) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("session_id", sessionID.String()).
			Msg("UpdateSessionToken completed")
	}()

	// Update session token in database
	if err := s.sessionRepo.UpdateSessionToken(ctx, sessionID, newToken, expiresAt); err != nil {
		if errors.Is(err, domain.ErrSessionNotFound) {
			return domain.NewAppError(domain.ErrSessionNotFound, "Session not found", 404)
		}
		s.logger.Error().Err(err).Msg("Failed to update session token")
		return domain.NewAppError(err, "Failed to update session token", 500)
	}

	// Invalidate old session cache (we don't have the old token, so we'll rely on expiration)
	s.logger.Info().
		Str("session_id", sessionID.String()).
		Msg("Session token updated")

	return nil
}

// CleanupExpiredSessions cleans up expired sessions
func (s *sessionService) CleanupExpiredSessions(ctx context.Context) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Msg("CleanupExpiredSessions completed")
	}()

	// Delete expired sessions
	if err := s.sessionRepo.DeleteExpiredSessions(ctx); err != nil {
		s.logger.Error().Err(err).Msg("Failed to delete expired sessions")
		return domain.NewAppError(err, "Failed to cleanup expired sessions", 500)
	}

	s.logger.Info().Msg("Expired sessions cleaned up")
	return nil
}

// GetActiveSessionCount gets the count of active sessions for a user
func (s *sessionService) GetActiveSessionCount(ctx context.Context, userID uuid.UUID) (int, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Msg("GetActiveSessionCount completed")
	}()

	sessions, err := s.GetUserSessions(ctx, userID)
	if err != nil {
		return 0, err
	}

	count := len(sessions)
	s.logger.Debug().
		Str("user_id", userID.String()).
		Int("count", count).
		Msg("Active session count retrieved")

	return count, nil
}

// ValidateAndExtendSession validates a session and optionally extends it
func (s *sessionService) ValidateAndExtendSession(ctx context.Context, token string, extendDuration time.Duration) (core.UserSession, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("token_prefix", token[:8]).
			Msg("ValidateAndExtendSession completed")
	}()

	// Get session
	session, err := s.GetSession(ctx, token)
	if err != nil {
		return core.UserSession{}, err
	}

	// Check if session is close to expiration and should be extended
	timeUntilExpiry := session.ExpiresAt.Sub(time.Now())
	if extendDuration > 0 && timeUntilExpiry < extendDuration/2 {
		// Extend the session
		newExpiresAt := time.Now().Add(extendDuration)
		if err := s.sessionRepo.UpdateSessionToken(ctx, session.ID, token, newExpiresAt); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to extend session")
		} else {
			session.ExpiresAt = newExpiresAt
			// Update cache
			s.invalidateSessionCaches(ctx, token, session.UserID)
			s.logger.Debug().
				Str("session_id", session.ID.String()).
				Dur("extended_by", extendDuration).
				Msg("Session extended")
		}
	}

	return session, nil
}

// Helper methods

func (s *sessionService) cleanupExpiredSession(token string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.sessionRepo.DeleteSession(ctx, token); err != nil && !errors.Is(err, domain.ErrSessionNotFound) {
		s.logger.Warn().Err(err).Msg("Failed to delete expired session")
	}

	// Invalidate cache
	s.cache.Delete(ctx, fmt.Sprintf("session:%s", token))
}

func (s *sessionService) invalidateSessionCaches(ctx context.Context, token string, userID uuid.UUID) {
	cacheKeys := []string{
		fmt.Sprintf("session:%s", token),
		fmt.Sprintf("user:sessions:%s", userID.String()),
	}

	for _, key := range cacheKeys {
		if err := s.cache.Delete(ctx, key); err != nil {
			s.logger.Warn().Err(err).Str("key", key).Msg("Failed to invalidate session cache")
		}
	}
}

// StartSessionCleanupJob starts a background job to clean up expired sessions
func (s *sessionService) StartSessionCleanupJob(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	s.logger.Info().Dur("interval", interval).Msg("Starting session cleanup job")

	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := s.CleanupExpiredSessions(ctx); err != nil {
			s.logger.Warn().Err(err).Msg("Session cleanup job failed")
		}
		cancel()
	}
}
