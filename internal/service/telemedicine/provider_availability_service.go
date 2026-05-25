// Package telemedicine implements the provider availability service
package telemedicine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/telemedicine"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
)

// cache TTLs
const (
	availabilityByStaffCacheTTL      = 30 * time.Second
	availableProvidersCacheTTL       = 15 * time.Second // patient-facing list; keep near-real-time
	availableProvidersBySpecCacheTTL = 15 * time.Second
	availableProvidersIndexTTL       = 5 * time.Minute
)

type providerAvailabilityService struct {
	availabilityRepo repository.ProviderAvailabilityRepository
	cache            cache.Service
	logger           *zerolog.Logger
}

// NewProviderAvailabilityService creates a new provider availability service.
func NewProviderAvailabilityService(
	availabilityRepo repository.ProviderAvailabilityRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) service.ProviderAvailabilityService {
	return &providerAvailabilityService{
		availabilityRepo: availabilityRepo,
		cache:            cache,
		logger:           logger,
	}
}

// ─── Provider Self-Management ─────────────────────────────────────────────────

// GoOnline marks the provider as online and records their shift start.
// Upserts the availability row if it doesn't exist yet (first login).
func (s *providerAvailabilityService) GoOnline(ctx context.Context, staffID uuid.UUID) (telemedicine.ProviderAvailability, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().Dur("duration_ms", time.Since(start)).Str("staff_id", staffID.String()).Msg("GoOnline completed")
	}()

	if staffID == uuid.Nil {
		return telemedicine.ProviderAvailability{}, domain.NewAppError(domain.ErrValidation, "staff_id is required", 400)
	}

	// Ensure a row exists before transitioning
	if _, err := s.availabilityRepo.UpsertAvailability(ctx, staffID); err != nil {
		s.logger.Error().Err(err).Str("staff_id", staffID.String()).Msg("Failed to upsert availability")
		return telemedicine.ProviderAvailability{}, domain.NewAppError(err, "failed to initialise provider availability", 500)
	}

	avail, err := s.availabilityRepo.GoOnline(ctx, staffID)
	if err != nil {
		s.logger.Error().Err(err).Str("staff_id", staffID.String()).Msg("Failed to go online")
		return telemedicine.ProviderAvailability{}, domain.NewAppError(err, "failed to go online", 500)
	}

	s.invalidateProviderCache(ctx, staffID)
	s.logger.Info().Str("staff_id", staffID.String()).Msg("Provider went online")
	return avail, nil
}

// GoOffline marks the provider as offline, clears their accepting state, and nulls shift_start.
func (s *providerAvailabilityService) GoOffline(ctx context.Context, staffID uuid.UUID) error {
	if staffID == uuid.Nil {
		return domain.NewAppError(domain.ErrValidation, "staff_id is required", 400)
	}

	if err := s.availabilityRepo.GoOffline(ctx, staffID); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			// Provider never registered an availability row — treat as no-op
			return nil
		}
		s.logger.Error().Err(err).Str("staff_id", staffID.String()).Msg("Failed to go offline")
		return domain.NewAppError(err, "failed to go offline", 500)
	}

	s.invalidateProviderCache(ctx, staffID)
	s.logger.Info().Str("staff_id", staffID.String()).Msg("Provider went offline")
	return nil
}

// SetAccepting toggles the provider's accepting state and optionally updates fee override
// and estimated wait minutes. Provider must be online to accept new consultations.
func (s *providerAvailabilityService) SetAccepting(ctx context.Context, staffID uuid.UUID, accepting bool, feeOverride *float64, waitMinutes *int) (telemedicine.ProviderAvailability, error) {
	if staffID == uuid.Nil {
		return telemedicine.ProviderAvailability{}, domain.NewAppError(domain.ErrValidation, "staff_id is required", 400)
	}
	if feeOverride != nil && *feeOverride < 0 {
		return telemedicine.ProviderAvailability{}, domain.NewAppError(domain.ErrValidation, "fee_override must be non-negative", 400)
	}
	if waitMinutes != nil && *waitMinutes < 0 {
		return telemedicine.ProviderAvailability{}, domain.NewAppError(domain.ErrValidation, "wait_minutes must be non-negative", 400)
	}

	// Enforce online check when setting to accepting
	if accepting {
		current, err := s.availabilityRepo.GetAvailabilityByStaffID(ctx, staffID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return telemedicine.ProviderAvailability{}, domain.NewAppError(err, "provider availability not found — go online first", 404)
			}
			return telemedicine.ProviderAvailability{}, domain.NewAppError(err, "failed to check provider status", 500)
		}
		if !current.IsOnline {
			return telemedicine.ProviderAvailability{}, domain.NewAppError(domain.ErrValidation, "provider must be online before accepting consultations", 400)
		}
	}

	avail, err := s.availabilityRepo.SetAccepting(ctx, staffID, accepting, feeOverride, waitMinutes)
	if err != nil {
		s.logger.Error().Err(err).Str("staff_id", staffID.String()).Msg("Failed to set accepting state")
		return telemedicine.ProviderAvailability{}, domain.NewAppError(err, "failed to update accepting state", 500)
	}

	s.invalidateProviderCache(ctx, staffID)
	s.logger.Info().Str("staff_id", staffID.String()).Bool("accepting", accepting).Msg("Provider accepting state updated")
	return avail, nil
}

// UpdateStatus sets the provider's status enum (available, busy, away) and optional message.
// Providers cannot set themselves to "offline" via this method — use GoOffline instead.
func (s *providerAvailabilityService) UpdateStatus(ctx context.Context, staffID uuid.UUID, status telemedicine.ProviderAvailabilityStatus, message *string) error {
	if staffID == uuid.Nil {
		return domain.NewAppError(domain.ErrValidation, "staff_id is required", 400)
	}
	if status == telemedicine.AvailabilityStatusOffline {
		return domain.NewAppError(domain.ErrValidation, "use GoOffline to set status to offline", 400)
	}
	if !isValidProviderStatus(status) {
		return domain.NewAppError(domain.ErrValidation, fmt.Sprintf("invalid status: %s", status), 400)
	}

	if err := s.availabilityRepo.UpdateStatus(ctx, staffID, status, message); err != nil {
		s.logger.Error().Err(err).Str("staff_id", staffID.String()).Msg("Failed to update status")
		return domain.NewAppError(err, "failed to update status", 500)
	}

	s.invalidateProviderCache(ctx, staffID)
	return nil
}

// UpdateHeartbeat records last_seen_at to keep the provider's presence alive.
// Should be called every ~30 seconds from the provider dashboard.
func (s *providerAvailabilityService) UpdateHeartbeat(ctx context.Context, staffID uuid.UUID) error {
	if staffID == uuid.Nil {
		return domain.NewAppError(domain.ErrValidation, "staff_id is required", 400)
	}

	if err := s.availabilityRepo.UpdateHeartbeat(ctx, staffID); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			// Row doesn't exist yet — provider hasn't gone online formally; no-op
			return nil
		}
		s.logger.Error().Err(err).Str("staff_id", staffID.String()).Msg("Failed to update heartbeat")
		return domain.NewAppError(err, "failed to update heartbeat", 500)
	}

	return nil
}

// UpdateWaitTime updates the estimated wait minutes displayed to patients.
func (s *providerAvailabilityService) UpdateWaitTime(ctx context.Context, staffID uuid.UUID, minutes int) error {
	if staffID == uuid.Nil {
		return domain.NewAppError(domain.ErrValidation, "staff_id is required", 400)
	}
	if minutes < 0 {
		return domain.NewAppError(domain.ErrValidation, "wait time must be non-negative", 400)
	}
	if minutes > 480 {
		return domain.NewAppError(domain.ErrValidation, "wait time cannot exceed 480 minutes", 400)
	}

	if err := s.availabilityRepo.UpdateWaitTime(ctx, staffID, minutes); err != nil {
		s.logger.Error().Err(err).Str("staff_id", staffID.String()).Msg("Failed to update wait time")
		return domain.NewAppError(err, "failed to update wait time", 500)
	}

	s.invalidateProviderCache(ctx, staffID)
	return nil
}

// GetAvailabilityByStaffID fetches the full availability record for a provider.
func (s *providerAvailabilityService) GetAvailabilityByStaffID(ctx context.Context, staffID uuid.UUID) (telemedicine.ProviderAvailability, error) {
	cacheKey := availabilityByStaffCacheKey(staffID)
	if s.cache != nil && s.cache.IsAvailable() {
		var cached telemedicine.ProviderAvailability
		if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
			return cached, nil
		}
	}

	avail, err := s.availabilityRepo.GetAvailabilityByStaffID(ctx, staffID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return telemedicine.ProviderAvailability{}, domain.NewAppError(err, "provider availability not found", 404)
		}
		s.logger.Error().Err(err).Str("staff_id", staffID.String()).Msg("Failed to get availability")
		return telemedicine.ProviderAvailability{}, domain.NewAppError(err, "failed to retrieve availability", 500)
	}

	if s.cache != nil && s.cache.IsAvailable() {
		if err := s.cache.Set(ctx, cacheKey, avail, availabilityByStaffCacheTTL); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache provider availability")
		}
	}

	return avail, nil
}

// ─── Patient-Facing ───────────────────────────────────────────────────────────

// GetAvailableProviders returns all currently accepting providers for the patient-facing list.
// Pass nil clinicID to return providers across all clinics.
func (s *providerAvailabilityService) GetAvailableProviders(ctx context.Context, clinicID *uuid.UUID) ([]telemedicine.AvailableProvider, error) {
	cacheKey := availableProvidersCacheKey(clinicID)
	if s.cache != nil && s.cache.IsAvailable() {
		var cached []telemedicine.AvailableProvider
		if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
			return cached, nil
		}
	}

	providers, err := s.availabilityRepo.GetAvailableProviders(ctx, clinicID)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to get available providers")
		return nil, domain.NewAppError(err, "failed to retrieve available providers", 500)
	}

	if s.cache != nil && s.cache.IsAvailable() {
		if err := s.cache.Set(ctx, cacheKey, providers, availableProvidersCacheTTL); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache available providers")
		} else {
			s.registerAvailableProvidersCacheKey(ctx, availableProvidersRegistryKey(), cacheKey)
		}
	}

	return providers, nil
}

// GetAvailableProvidersBySpecialization returns providers filtered by specialization.
func (s *providerAvailabilityService) GetAvailableProvidersBySpecialization(ctx context.Context, specialization string) ([]telemedicine.AvailableProviderBySpecialization, error) {
	if specialization == "" {
		return nil, domain.NewAppError(domain.ErrValidation, "specialization is required", 400)
	}

	cacheKey := availableProvidersBySpecCacheKey(specialization)
	if s.cache != nil && s.cache.IsAvailable() {
		var cached []telemedicine.AvailableProviderBySpecialization
		if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
			return cached, nil
		}
	}

	providers, err := s.availabilityRepo.GetAvailableProvidersBySpecialization(ctx, specialization)
	if err != nil {
		s.logger.Error().Err(err).Str("specialization", specialization).Msg("Failed to get providers by specialization")
		return nil, domain.NewAppError(err, "failed to retrieve providers", 500)
	}

	if s.cache != nil && s.cache.IsAvailable() {
		if err := s.cache.Set(ctx, cacheKey, providers, availableProvidersBySpecCacheTTL); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache providers by specialization")
		} else {
			s.registerAvailableProvidersCacheKey(ctx, availableProvidersBySpecRegistryKey(), cacheKey)
		}
	}

	return providers, nil
}

// ─── Background Job ───────────────────────────────────────────────────────────

// GetStaleProviders returns providers whose heartbeat is older than 2 minutes.
// Intended for use by the background stale-provider cleanup job.
func (s *providerAvailabilityService) GetStaleProviders(ctx context.Context) ([]telemedicine.StaleProvider, error) {
	providers, err := s.availabilityRepo.GetStaleProviders(ctx)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to get stale providers")
		return nil, domain.NewAppError(err, "failed to retrieve stale providers", 500)
	}
	return providers, nil
}

// SetStaleProvidersOffline bulk-marks heartbeat-stale providers as offline.
// Should be called on a recurring schedule (e.g. every 2 minutes).
func (s *providerAvailabilityService) SetStaleProvidersOffline(ctx context.Context) error {
	if err := s.availabilityRepo.SetStaleProvidersOffline(ctx); err != nil {
		s.logger.Error().Err(err).Msg("Failed to set stale providers offline")
		return domain.NewAppError(err, "failed to run stale provider cleanup", 500)
	}
	// Bust the patient-facing provider list after cleanup
	s.invalidateAvailableProvidersCache(ctx)
	s.logger.Info().Msg("Stale providers set offline")
	return nil
}

// ─── Cache helpers ─────────────────────────────────────────────────────────────

func (s *providerAvailabilityService) invalidateProviderCache(ctx context.Context, staffID uuid.UUID) {
	if s.cache == nil || !s.cache.IsAvailable() {
		return
	}
	keys := []string{
		availabilityByStaffCacheKey(staffID),
		availableProvidersCacheKey(nil), // global list
	}
	keys = append(keys, s.collectRegisteredCacheKeys(ctx, availableProvidersRegistryKey())...)
	keys = append(keys, s.collectRegisteredCacheKeys(ctx, availableProvidersBySpecRegistryKey())...)
	keys = append(keys, availableProvidersRegistryKey(), availableProvidersBySpecRegistryKey())
	for _, k := range uniqueCacheKeys(keys) {
		if err := s.cache.Delete(ctx, k); err != nil {
			s.logger.Warn().Err(err).Str("key", k).Msg("Failed to invalidate cache key")
		}
	}
}

func (s *providerAvailabilityService) invalidateAvailableProvidersCache(ctx context.Context) {
	if s.cache == nil || !s.cache.IsAvailable() {
		return
	}
	keys := []string{availableProvidersCacheKey(nil)}
	keys = append(keys, s.collectRegisteredCacheKeys(ctx, availableProvidersRegistryKey())...)
	keys = append(keys, s.collectRegisteredCacheKeys(ctx, availableProvidersBySpecRegistryKey())...)
	keys = append(keys, availableProvidersRegistryKey(), availableProvidersBySpecRegistryKey())
	for _, key := range uniqueCacheKeys(keys) {
		if err := s.cache.Delete(ctx, key); err != nil {
			s.logger.Warn().Err(err).Str("key", key).Msg("Failed to invalidate available providers cache")
		}
	}
}

func (s *providerAvailabilityService) registerAvailableProvidersCacheKey(ctx context.Context, indexKey, cacheKey string) {
	if s.cache == nil || !s.cache.IsAvailable() {
		return
	}

	keys := s.collectRegisteredCacheKeys(ctx, indexKey)
	keys = append(keys, cacheKey)
	if err := s.cache.Set(ctx, indexKey, uniqueCacheKeys(keys), availableProvidersIndexTTL); err != nil {
		s.logger.Warn().Err(err).Str("index_key", indexKey).Msg("Failed to update provider availability cache index")
	}
}

func (s *providerAvailabilityService) collectRegisteredCacheKeys(ctx context.Context, indexKey string) []string {
	if s.cache == nil || !s.cache.IsAvailable() {
		return nil
	}

	var keys []string
	if err := s.cache.Get(ctx, indexKey, &keys); err != nil {
		return nil
	}
	return keys
}

// ─── Cache key builders ───────────────────────────────────────────────────────

func availabilityByStaffCacheKey(staffID uuid.UUID) string {
	return fmt.Sprintf("provider:availability:%s", staffID.String())
}

func availableProvidersCacheKey(clinicID *uuid.UUID) string {
	if clinicID == nil {
		return "providers:available:all"
	}
	return fmt.Sprintf("providers:available:clinic:%s", clinicID.String())
}

func availableProvidersBySpecCacheKey(specialization string) string {
	return fmt.Sprintf("providers:available:spec:%s", specialization)
}

func availableProvidersRegistryKey() string {
	return "providers:available:index"
}

func availableProvidersBySpecRegistryKey() string {
	return "providers:available:spec:index"
}

func uniqueCacheKeys(keys []string) []string {
	seen := make(map[string]struct{}, len(keys))
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, key)
	}
	return result
}

// ─── Misc helpers ─────────────────────────────────────────────────────────────

func isValidProviderStatus(s telemedicine.ProviderAvailabilityStatus) bool {
	switch s {
	case telemedicine.AvailabilityStatusAvailable,
		telemedicine.AvailabilityStatusBusy,
		telemedicine.AvailabilityStatusAway,
		telemedicine.AvailabilityStatusOffline:
		return true
	}
	return false
}
