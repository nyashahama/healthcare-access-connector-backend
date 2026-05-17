package patients

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
)

type emergencyContactService struct {
	emergencyContactRepo repository.EmergencyContactRepository
	patientRepo          repository.PatientProfileRepository
	cache                cache.Service
	logger               *zerolog.Logger
}

// NewEmergencyContactService creates a new emergency contact service
func NewEmergencyContactService(
	emergencyContactRepo repository.EmergencyContactRepository,
	patientRepo repository.PatientProfileRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) service.EmergencyContactService {
	return &emergencyContactService{
		emergencyContactRepo: emergencyContactRepo,
		patientRepo:          patientRepo,
		cache:                cache,
		logger:               logger,
	}
}

// AddEmergencyContact adds a new emergency contact for a patient
func (s *emergencyContactService) AddEmergencyContact(ctx context.Context, contact patients.EmergencyContact) (patients.EmergencyContact, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", contact.PatientID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Add emergency contact completed")
	}()

	// Validate input
	if err := s.validateEmergencyContact(contact); err != nil {
		return patients.EmergencyContact{}, domain.NewAppError(domain.ErrValidation, err.Error(), 400)
	}

	// Verify patient exists
	_, err := s.patientRepo.GetPatientProfileByID(ctx, contact.PatientID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			s.logger.Debug().Str("patient_id", contact.PatientID.String()).Msg("Patient not found")
			return patients.EmergencyContact{}, domain.NewAppError(domain.ErrPatientNotFound, "Patient not found", 404)
		}
		s.logger.Error().Err(err).Str("patient_id", contact.PatientID.String()).Msg("Failed to verify patient")
		return patients.EmergencyContact{}, domain.NewAppError(err, "Failed to verify patient", 500)
	}

	// Check if this is the first contact - if so, mark as primary
	existingContacts, err := s.emergencyContactRepo.GetPatientEmergencyContacts(ctx, contact.PatientID)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		s.logger.Error().Err(err).Str("patient_id", contact.PatientID.String()).Msg("Failed to get existing emergency contacts")
		return patients.EmergencyContact{}, domain.NewAppError(err, "Failed to get existing emergency contacts", 500)
	}

	// If no existing contacts, this one becomes primary
	if len(existingContacts) == 0 {
		contact.IsPrimary = true
	}

	// If this contact is marked as primary, unset primary flag from other contacts
	if contact.IsPrimary {
		if err := s.unsetPrimaryContact(ctx, contact.PatientID, uuid.Nil); err != nil {
			s.logger.Warn().Err(err).Str("patient_id", contact.PatientID.String()).Msg("Failed to unset primary flag from existing contacts")
		}
	}

	// Set timestamps
	now := time.Now()
	contact.ID = uuid.New()
	contact.CreatedAt = now
	contact.UpdatedAt = now

	// Set default access level if not provided
	if contact.AccessLevel == nil || *contact.AccessLevel == "" {
		defaultAccess := "limited"
		contact.AccessLevel = &defaultAccess
	}

	// Add emergency contact
	created, err := s.emergencyContactRepo.AddEmergencyContact(ctx, contact)
	if err != nil {
		s.logger.Error().Err(err).
			Str("patient_id", contact.PatientID.String()).
			Str("contact_name", contact.ContactName).
			Msg("Failed to add emergency contact")
		return patients.EmergencyContact{}, domain.NewAppError(err, "Failed to add emergency contact", 500)
	}

	// Invalidate cache
	s.invalidateEmergencyContactCache(ctx, contact.PatientID)

	s.logger.Info().
		Str("emergency_contact_id", created.ID.String()).
		Str("patient_id", created.PatientID.String()).
		Str("contact_name", created.ContactName).
		Bool("is_primary", created.IsPrimary).
		Msg("Emergency contact added successfully")

	return created, nil
}

// GetPatientEmergencyContacts retrieves all emergency contacts for a patient
func (s *emergencyContactService) GetPatientEmergencyContacts(ctx context.Context, patientID uuid.UUID) ([]patients.EmergencyContact, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", patientID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Get patient emergency contacts completed")
	}()

	// Verify patient exists
	_, err := s.patientRepo.GetPatientProfileByID(ctx, patientID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			s.logger.Debug().Str("patient_id", patientID.String()).Msg("Patient not found")
			return nil, domain.NewAppError(domain.ErrPatientNotFound, "Patient not found", 404)
		}
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to verify patient")
		return nil, domain.NewAppError(err, "Failed to verify patient", 500)
	}

	// Try cache first
	cacheKey := fmt.Sprintf("emergency_contacts:all:%s", patientID.String())
	var contacts []patients.EmergencyContact
	if err := s.cache.Get(ctx, cacheKey, &contacts); err == nil {
		s.logger.Debug().Str("patient_id", patientID.String()).Msg("Patient emergency contacts retrieved from cache")
		return contacts, nil
	}

	// Fetch from database
	contacts, err = s.emergencyContactRepo.GetPatientEmergencyContacts(ctx, patientID)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to get patient emergency contacts")
		return nil, domain.NewAppError(err, "Failed to get patient emergency contacts", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, contacts, 60*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache patient emergency contacts")
	}

	s.logger.Debug().
		Str("patient_id", patientID.String()).
		Int("count", len(contacts)).
		Msg("Patient emergency contacts retrieved successfully")

	return contacts, nil
}

// GetPrimaryEmergencyContact retrieves the primary emergency contact for a patient
func (s *emergencyContactService) GetPrimaryEmergencyContact(ctx context.Context, patientID uuid.UUID) (patients.EmergencyContact, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", patientID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Get primary emergency contact completed")
	}()

	// Verify patient exists
	_, err := s.patientRepo.GetPatientProfileByID(ctx, patientID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			s.logger.Debug().Str("patient_id", patientID.String()).Msg("Patient not found")
			return patients.EmergencyContact{}, domain.NewAppError(domain.ErrPatientNotFound, "Patient not found", 404)
		}
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to verify patient")
		return patients.EmergencyContact{}, domain.NewAppError(err, "Failed to verify patient", 500)
	}

	// Try cache first
	cacheKey := fmt.Sprintf("emergency_contacts:primary:%s", patientID.String())
	var contact patients.EmergencyContact
	if err := s.cache.Get(ctx, cacheKey, &contact); err == nil {
		s.logger.Debug().Str("patient_id", patientID.String()).Msg("Primary emergency contact retrieved from cache")
		return contact, nil
	}

	// Fetch from database
	contact, err = s.emergencyContactRepo.GetPrimaryEmergencyContact(ctx, patientID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			s.logger.Debug().Str("patient_id", patientID.String()).Msg("No primary emergency contact found")
			return patients.EmergencyContact{}, domain.NewAppError(domain.ErrNotFound, "No primary emergency contact found", 404)
		}
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to get primary emergency contact")
		return patients.EmergencyContact{}, domain.NewAppError(err, "Failed to get primary emergency contact", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, contact, 60*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache primary emergency contact")
	}

	s.logger.Debug().
		Str("patient_id", patientID.String()).
		Str("contact_name", contact.ContactName).
		Msg("Primary emergency contact retrieved successfully")

	return contact, nil
}

// UpdateEmergencyContact updates an emergency contact record
func (s *emergencyContactService) UpdateEmergencyContact(ctx context.Context, contact patients.EmergencyContact) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("emergency_contact_id", contact.ID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Update emergency contact completed")
	}()

	// Validate input
	if err := s.validateEmergencyContact(contact); err != nil {
		return domain.NewAppError(domain.ErrValidation, err.Error(), 400)
	}

	// Get existing contacts for the patient to verify ownership
	allContacts, err := s.emergencyContactRepo.GetPatientEmergencyContacts(ctx, contact.PatientID)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", contact.PatientID.String()).Msg("Failed to get patient emergency contacts")
		return domain.NewAppError(err, "Failed to get patient emergency contacts", 500)
	}

	// Find the contact
	var found bool
	var oldIsPrimary bool
	for _, existing := range allContacts {
		if existing.ID == contact.ID {
			found = true
			oldIsPrimary = existing.IsPrimary
			break
		}
	}

	if !found {
		s.logger.Debug().
			Str("emergency_contact_id", contact.ID.String()).
			Str("patient_id", contact.PatientID.String()).
			Msg("Emergency contact not found for patient")
		return domain.NewAppError(domain.ErrNotFound, "Emergency contact not found for this patient", 404)
	}

	// If this contact is being set as primary and wasn't before, unset primary flag from other contacts
	if contact.IsPrimary && !oldIsPrimary {
		if err := s.unsetPrimaryContact(ctx, contact.PatientID, contact.ID); err != nil {
			s.logger.Warn().Err(err).Str("patient_id", contact.PatientID.String()).Msg("Failed to unset primary flag from existing contacts")
		}
	}

	// Update timestamps
	contact.UpdatedAt = time.Now()

	// Update emergency contact
	if err := s.emergencyContactRepo.UpdateEmergencyContact(ctx, contact); err != nil {
		s.logger.Error().Err(err).
			Str("emergency_contact_id", contact.ID.String()).
			Str("patient_id", contact.PatientID.String()).
			Msg("Failed to update emergency contact")

		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(domain.ErrNotFound, "Emergency contact not found", 404)
		}
		return domain.NewAppError(err, "Failed to update emergency contact", 500)
	}

	// Invalidate cache
	s.invalidateEmergencyContactCache(ctx, contact.PatientID)

	s.logger.Info().
		Str("emergency_contact_id", contact.ID.String()).
		Str("patient_id", contact.PatientID.String()).
		Msg("Emergency contact updated successfully")

	return nil
}

// DeleteEmergencyContact deletes an emergency contact record
func (s *emergencyContactService) DeleteEmergencyContact(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("emergency_contact_id", id.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Delete emergency contact completed")
	}()

	// Delete emergency contact
	if err := s.emergencyContactRepo.DeleteEmergencyContact(ctx, id); err != nil {
		s.logger.Error().Err(err).Str("emergency_contact_id", id.String()).Msg("Failed to delete emergency contact")

		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(domain.ErrNotFound, "Emergency contact not found", 404)
		}
		return domain.NewAppError(err, "Failed to delete emergency contact", 500)
	}

	// Note: Cache invalidation is skipped here because we don't have the patient ID.
	// In a production system, you would add a GetEmergencyContactByID method.

	s.logger.Info().Str("emergency_contact_id", id.String()).Msg("Emergency contact deleted successfully")
	return nil
}

// Unset primary flag from all contacts for a patient, optionally keeping one contact primary.
func (s *emergencyContactService) unsetPrimaryContact(ctx context.Context, patientID uuid.UUID, excludeContactID uuid.UUID) error {
	contacts, err := s.emergencyContactRepo.GetPatientEmergencyContacts(ctx, patientID)
	if err != nil {
		return err
	}

	for _, contact := range contacts {
		if !contact.IsPrimary {
			continue
		}
		if excludeContactID != uuid.Nil && contact.ID == excludeContactID {
			continue
		}

		contact.IsPrimary = false
		if err := s.emergencyContactRepo.UpdateEmergencyContact(ctx, contact); err != nil {
			return err
		}
	}

	return nil
}

// Validate emergency contact
func (s *emergencyContactService) validateEmergencyContact(contact patients.EmergencyContact) error {
	if contact.PatientID == uuid.Nil {
		return fmt.Errorf("patient ID is required")
	}
	if strings.TrimSpace(contact.ContactName) == "" {
		return fmt.Errorf("contact name is required")
	}
	if strings.TrimSpace(contact.Relationship) == "" {
		return fmt.Errorf("relationship is required")
	}
	if strings.TrimSpace(contact.PhoneNumber) == "" {
		return fmt.Errorf("phone number is required")
	}

	// Validate phone number format (basic validation)
	if len(contact.PhoneNumber) < 10 {
		return fmt.Errorf("phone number must be at least 10 digits")
	}

	// Validate email if provided
	if contact.Email != nil && *contact.Email != "" {
		if !s.isValidEmail(*contact.Email) {
			return fmt.Errorf("invalid email format")
		}
	}

	// Validate access level if provided
	if contact.AccessLevel != nil && !s.isValidAccessLevel(*contact.AccessLevel) {
		return fmt.Errorf("invalid access level: %s", *contact.AccessLevel)
	}

	return nil
}

// Helper methods
func (s *emergencyContactService) invalidateEmergencyContactCache(ctx context.Context, patientID uuid.UUID) {
	cacheKeys := []string{
		fmt.Sprintf("emergency_contacts:all:%s", patientID.String()),
		fmt.Sprintf("emergency_contacts:primary:%s", patientID.String()),
	}

	for _, key := range cacheKeys {
		if err := s.cache.Delete(ctx, key); err != nil {
			s.logger.Warn().Err(err).Str("key", key).Msg("Failed to invalidate emergency contact cache")
		}
	}
}

func (s *emergencyContactService) isValidEmail(email string) bool {
	// Basic email validation
	return strings.Contains(email, "@") && strings.Contains(email, ".")
}

func (s *emergencyContactService) isValidAccessLevel(accessLevel string) bool {
	validAccessLevels := []string{"none", "limited", "full"}
	for _, validLevel := range validAccessLevels {
		if strings.EqualFold(accessLevel, validLevel) {
			return true
		}
	}
	return false
}
