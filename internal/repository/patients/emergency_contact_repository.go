package patients

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	emergencyContactDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "emergency_contact_db_query_duration_seconds",
			Help:    "Emergency contact database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	emergencyContactDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "emergency_contact_db_query_total",
			Help: "Total number of emergency contact database queries",
		},
		[]string{"operation", "status"},
	)
)

type emergencyContactRepository struct {
	querier sqlc.Querier
}

func NewEmergencyContactRepository(pool *pgxpool.Pool) repository.EmergencyContactRepository {
	return NewEmergencyContactRepositoryWithQuerier(sqlc.New(pool))
}

func NewEmergencyContactRepositoryWithQuerier(querier sqlc.Querier) repository.EmergencyContactRepository {
	return &emergencyContactRepository{
		querier: querier,
	}
}

// ===== Core CRUD Operations =====

func (r *emergencyContactRepository) AddEmergencyContact(ctx context.Context, contact patients.EmergencyContact) (patients.EmergencyContact, error) {
	start := time.Now()
	defer func() {
		emergencyContactDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	created, err := r.querier.AddEmergencyContact(ctx, sqlc.AddEmergencyContactParams{
		PatientID:            uuidToPgtypeUUID(contact.PatientID),
		ContactName:          contact.ContactName,
		Relationship:         contact.Relationship,
		PhoneNumber:          contact.PhoneNumber,
		Email:                pgtypeTextFromStringPtr(contact.Email),
		Address:              pgtypeTextFromStringPtr(contact.Address),
		IsPrimary:            pgtype.Bool{Bool: contact.IsPrimary, Valid: true},
		CanAccessMedicalInfo: pgtype.Bool{Bool: contact.CanAccessMedicalInfo, Valid: true},
		AccessLevel:          pgtypeTextFromStringPtr(contact.AccessLevel),
		RelationshipVerified: pgtype.Bool{Bool: contact.RelationshipVerified, Valid: true},
		VerificationNotes:    pgtypeTextFromStringPtr(contact.VerificationNotes),
	})
	if err != nil {
		emergencyContactDBQueryTotal.WithLabelValues("add_emergency_contact", "error").Inc()
		return patients.EmergencyContact{}, r.handleError(err, "add emergency contact")
	}

	emergencyContactDBQueryTotal.WithLabelValues("add_emergency_contact", "success").Inc()
	return r.mapToEmergencyContact(created), nil
}

func (r *emergencyContactRepository) GetPatientEmergencyContacts(ctx context.Context, patientID uuid.UUID) ([]patients.EmergencyContact, error) {
	start := time.Now()
	defer func() {
		emergencyContactDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientEmergencyContacts(ctx, uuidToPgtypeUUID(patientID))
	if err != nil {
		emergencyContactDBQueryTotal.WithLabelValues("get_patient_emergency_contacts", "error").Inc()
		return nil, r.handleError(err, "get patient emergency contacts")
	}

	contacts := make([]patients.EmergencyContact, len(rows))
	for i, row := range rows {
		contacts[i] = r.mapToEmergencyContact(sqlc.EmergencyContact{
			ID:                   row.ID,
			PatientID:            row.PatientID,
			ContactName:          row.ContactName,
			Relationship:         row.Relationship,
			PhoneNumber:          row.PhoneNumber,
			Email:                row.Email,
			Address:              row.Address,
			IsPrimary:            row.IsPrimary,
			CanAccessMedicalInfo: row.CanAccessMedicalInfo,
			AccessLevel:          row.AccessLevel,
			RelationshipVerified: row.RelationshipVerified,
			CreatedAt:            row.CreatedAt,
			UpdatedAt:            row.UpdatedAt,
		})
	}

	emergencyContactDBQueryTotal.WithLabelValues("get_patient_emergency_contacts", "success").Inc()
	return contacts, nil
}

func (r *emergencyContactRepository) GetPrimaryEmergencyContact(ctx context.Context, patientID uuid.UUID) (patients.EmergencyContact, error) {
	start := time.Now()
	defer func() {
		emergencyContactDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	row, err := r.querier.GetPrimaryEmergencyContact(ctx, uuidToPgtypeUUID(patientID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			emergencyContactDBQueryTotal.WithLabelValues("get_primary_emergency_contact", "not_found").Inc()
			return patients.EmergencyContact{}, domain.ErrNotFound
		}
		emergencyContactDBQueryTotal.WithLabelValues("get_primary_emergency_contact", "error").Inc()
		return patients.EmergencyContact{}, r.handleError(err, "get primary emergency contact")
	}

	contact := patients.EmergencyContact{
		ID:                   pgtypeUUIDToUUID(row.ID),
		PatientID:            patientID,
		ContactName:          row.ContactName,
		Relationship:         row.Relationship,
		PhoneNumber:          row.PhoneNumber,
		Email:                pgtypeTextToStringPtr(row.Email),
		CanAccessMedicalInfo: row.CanAccessMedicalInfo.Bool,
		AccessLevel:          pgtypeTextToStringPtr(row.AccessLevel),
	}

	emergencyContactDBQueryTotal.WithLabelValues("get_primary_emergency_contact", "success").Inc()
	return contact, nil
}

func (r *emergencyContactRepository) UpdateEmergencyContact(ctx context.Context, contact patients.EmergencyContact) error {
	start := time.Now()
	defer func() {
		emergencyContactDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateEmergencyContact(ctx, sqlc.UpdateEmergencyContactParams{
		ID:                   uuidToPgtypeUUID(contact.ID),
		ContactName:          contact.ContactName,
		Relationship:         contact.Relationship,
		PhoneNumber:          contact.PhoneNumber,
		Email:                pgtypeTextFromStringPtr(contact.Email),
		Address:              pgtypeTextFromStringPtr(contact.Address),
		CanAccessMedicalInfo: pgtype.Bool{Bool: contact.CanAccessMedicalInfo, Valid: true},
		AccessLevel:          pgtypeTextFromStringPtr(contact.AccessLevel),
	})
	if err != nil {
		emergencyContactDBQueryTotal.WithLabelValues("update_emergency_contact", "error").Inc()
		return r.handleError(err, "update emergency contact")
	}

	emergencyContactDBQueryTotal.WithLabelValues("update_emergency_contact", "success").Inc()
	return nil
}

func (r *emergencyContactRepository) DeleteEmergencyContact(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		emergencyContactDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeleteEmergencyContact(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		emergencyContactDBQueryTotal.WithLabelValues("delete_emergency_contact", "error").Inc()
		return r.handleError(err, "delete emergency contact")
	}

	emergencyContactDBQueryTotal.WithLabelValues("delete_emergency_contact", "success").Inc()
	return nil
}

// ===== Helper Functions =====

func (r *emergencyContactRepository) mapToEmergencyContact(row sqlc.EmergencyContact) patients.EmergencyContact {
	return patients.EmergencyContact{
		ID:                   pgtypeUUIDToUUID(row.ID),
		PatientID:            pgtypeUUIDToUUID(row.PatientID),
		ContactName:          row.ContactName,
		Relationship:         row.Relationship,
		PhoneNumber:          row.PhoneNumber,
		Email:                pgtypeTextToStringPtr(row.Email),
		Address:              pgtypeTextToStringPtr(row.Address),
		IsPrimary:            row.IsPrimary.Bool,
		CanAccessMedicalInfo: row.CanAccessMedicalInfo.Bool,
		AccessLevel:          pgtypeTextToStringPtr(row.AccessLevel),
		RelationshipVerified: row.RelationshipVerified.Bool,
		VerificationNotes:    pgtypeTextToStringPtr(row.VerificationNotes),
		CreatedAt:            row.CreatedAt.Time,
		UpdatedAt:            row.UpdatedAt.Time,
	}
}

func (r *emergencyContactRepository) handleError(err error, operation string) error {
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	return fmt.Errorf("%s: %w", operation, err)
}
