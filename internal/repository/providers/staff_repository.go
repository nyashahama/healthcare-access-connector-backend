package providers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ============================================
// METRICS
// ============================================

var (
	staffDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "staff_db_query_duration_seconds",
			Help:    "Staff database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	staffDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "staff_db_query_total",
			Help: "Total number of staff database queries",
		},
		[]string{"operation", "status"},
	)
)

// ============================================
// REPOSITORY IMPLEMENTATION
// ============================================

type staffRepository struct {
	querier sqlc.Querier
	pool    *pgxpool.Pool
}

// NewStaffRepository creates a new staff repository using a pool
func NewStaffRepository(pool *pgxpool.Pool) repository.StaffRepository {
	return &staffRepository{
		querier: sqlc.New(pool),
		pool:    pool,
	}
}

// NewStaffRepositoryWithQuerier creates a new staff repository using a provided querier (for transactions)
func NewStaffRepositoryWithQuerier(querier sqlc.Querier) repository.StaffRepository {
	return &staffRepository{
		querier: querier,
	}
}

// ============================================
// BASIC CRUD OPERATIONS
// ============================================

func (r *staffRepository) CreateStaffMember(ctx context.Context, staff providers.ClinicStaff) (providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	otherLicenseNumbersJSON, err := jsonbFromMap(staff.OtherLicenseNumbers)
	if err != nil {
		return providers.ClinicStaff{}, fmt.Errorf("marshal other license numbers: %w", err)
	}

	workingHoursJSON, err := jsonbFromMap(staff.WorkingHours)
	if err != nil {
		return providers.ClinicStaff{}, fmt.Errorf("marshal working hours: %w", err)
	}

	params := sqlc.CreateStaffMemberParams{
		ClinicID:               uuidToPgtypeUUID(staff.ClinicID),
		UserID:                 uuidToPgtypeUUID(staff.UserID),
		Title:                  pgtypeTextFromStringPtr(staff.Title),
		FirstName:              staff.FirstName,
		LastName:               staff.LastName,
		ProfessionalTitle:      pgtypeTextFromStringPtr(staff.ProfessionalTitle),
		Specialization:         pgtypeTextFromStringPtr(staff.Specialization),
		WorkEmail:              pgtypeTextFromStringPtr(staff.WorkEmail),
		WorkPhone:              pgtypeTextFromStringPtr(staff.WorkPhone),
		PersonalPhone:          pgtypeTextFromStringPtr(staff.PersonalPhone),
		HpcsNumber:             pgtypeTextFromStringPtr(staff.HPCSNumber),
		OtherLicenseNumbers:    otherLicenseNumbersJSON,
		Qualifications:         staff.Qualifications,
		YearsExperience:        intPtrToPgtypeInt4(staff.YearsExperience),
		Bio:                    pgtypeTextFromStringPtr(staff.Bio),
		StaffRole:              staff.StaffRole,
		Department:             pgtypeTextFromStringPtr(staff.Department),
		IsPrimaryContact:       pgtype.Bool{Bool: staff.IsPrimaryContact, Valid: true},
		WorkingHours:           workingHoursJSON,
		AvailableDays:          staff.AvailableDays,
		IsAcceptingNewPatients: pgtype.Bool{Bool: staff.IsAcceptingNewPatients, Valid: true},
		EmploymentStatus:       pgtype.Text{String: staff.EmploymentStatus, Valid: true},
		StartDate:              datePtrToPgtypeDate(staff.StartDate),
		EndDate:                datePtrToPgtypeDate(staff.EndDate),
		ProfilePictureUrl:      pgtypeTextFromStringPtr(staff.ProfilePictureURL),
		LanguagesSpoken:        staff.LanguagesSpoken,
	}

	created, err := r.querier.CreateStaffMember(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("create_staff_member", "error").Inc()
		return providers.ClinicStaff{}, r.handleError(err, "create staff member")
	}

	staffDBQueryTotal.WithLabelValues("create_staff_member", "success").Inc()
	return r.mapToClinicStaff(created), nil
}

func (r *staffRepository) GetStaffByID(ctx context.Context, id uuid.UUID) (providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	s, err := r.querier.GetStaffByID(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			staffDBQueryTotal.WithLabelValues("get_staff_by_id", "not_found").Inc()
			return providers.ClinicStaff{}, domain.ErrStaffNotFound
		}
		staffDBQueryTotal.WithLabelValues("get_staff_by_id", "error").Inc()
		return providers.ClinicStaff{}, err
	}

	staffDBQueryTotal.WithLabelValues("get_staff_by_id", "success").Inc()
	return r.mapToClinicStaff(s), nil
}

func (r *staffRepository) GetStaffByUserID(ctx context.Context, userID uuid.UUID) (providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	s, err := r.querier.GetStaffByUserID(ctx, uuidToPgtypeUUID(userID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			staffDBQueryTotal.WithLabelValues("get_staff_by_user_id", "not_found").Inc()
			return providers.ClinicStaff{}, domain.ErrStaffNotFound
		}
		staffDBQueryTotal.WithLabelValues("get_staff_by_user_id", "error").Inc()
		return providers.ClinicStaff{}, err
	}

	staffDBQueryTotal.WithLabelValues("get_staff_by_user_id", "success").Inc()
	return r.mapToClinicStaff(s), nil
}

func (r *staffRepository) UpdateStaffMember(ctx context.Context, staff providers.ClinicStaff) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateStaffMemberParams{
		ID:                     uuidToPgtypeUUID(staff.ID),
		Title:                  pgtypeTextFromStringPtr(staff.Title),
		FirstName:              staff.FirstName,
		LastName:               staff.LastName,
		ProfessionalTitle:      pgtypeTextFromStringPtr(staff.ProfessionalTitle),
		Specialization:         pgtypeTextFromStringPtr(staff.Specialization),
		WorkEmail:              pgtypeTextFromStringPtr(staff.WorkEmail),
		WorkPhone:              pgtypeTextFromStringPtr(staff.WorkPhone),
		Bio:                    pgtypeTextFromStringPtr(staff.Bio),
		YearsExperience:        intPtrToPgtypeInt4(staff.YearsExperience),
		IsAcceptingNewPatients: pgtype.Bool{Bool: staff.IsAcceptingNewPatients, Valid: true},
	}

	err := r.querier.UpdateStaffMember(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("update_staff_member", "error").Inc()
		return r.handleError(err, "update staff member")
	}

	staffDBQueryTotal.WithLabelValues("update_staff_member", "success").Inc()
	return nil
}

func (r *staffRepository) DeleteStaffMember(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeleteStaffMember(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		staffDBQueryTotal.WithLabelValues("delete_staff_member", "error").Inc()
		return r.handleError(err, "delete staff member")
	}

	staffDBQueryTotal.WithLabelValues("delete_staff_member", "success").Inc()
	return nil
}

// ============================================
// CLINIC STAFF MANAGEMENT
// ============================================

func (r *staffRepository) GetClinicStaff(ctx context.Context, clinicID uuid.UUID, role *string) ([]providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetClinicStaffParams{
		ClinicID: uuidToPgtypeUUID(clinicID),
		Column2:  stringPtrToString(role),
	}

	rows, err := r.querier.GetClinicStaff(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("get_clinic_staff", "error").Inc()
		return nil, r.handleError(err, "get clinic staff")
	}

	staffList := make([]providers.ClinicStaff, len(rows))
	for i, row := range rows {
		staffList[i] = providers.ClinicStaff{
			ID:                     pgtypeUUIDToUUID(row.ID),
			ClinicID:               pgtypeUUIDToUUID(row.ClinicID),
			UserID:                 pgtypeUUIDToUUID(row.UserID),
			Title:                  pgtypeTextToStringPtr(row.Title),
			FirstName:              row.FirstName,
			LastName:               row.LastName,
			ProfessionalTitle:      pgtypeTextToStringPtr(row.ProfessionalTitle),
			Specialization:         pgtypeTextToStringPtr(row.Specialization),
			StaffRole:              row.StaffRole,
			WorkEmail:              pgtypeTextToStringPtr(row.WorkEmail),
			WorkPhone:              pgtypeTextToStringPtr(row.WorkPhone),
			IsAcceptingNewPatients: pgtypeBoolToBool(row.IsAcceptingNewPatients),
			EmploymentStatus:       pgtypeTextToString(row.EmploymentStatus),
			CreatedAt:              row.CreatedAt.Time,
		}
	}

	staffDBQueryTotal.WithLabelValues("get_clinic_staff", "success").Inc()
	return staffList, nil
}

func (r *staffRepository) GetActiveClinicStaff(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetActiveClinicStaff(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		staffDBQueryTotal.WithLabelValues("get_active_clinic_staff", "error").Inc()
		return nil, r.handleError(err, "get active clinic staff")
	}

	staffList := make([]providers.ClinicStaff, len(rows))
	for i, row := range rows {
		staffList[i] = providers.ClinicStaff{
			ID:                     pgtypeUUIDToUUID(row.ID),
			UserID:                 pgtypeUUIDToUUID(row.UserID),
			Title:                  pgtypeTextToStringPtr(row.Title),
			FirstName:              row.FirstName,
			LastName:               row.LastName,
			ProfessionalTitle:      pgtypeTextToStringPtr(row.ProfessionalTitle),
			Specialization:         pgtypeTextToStringPtr(row.Specialization),
			StaffRole:              row.StaffRole,
			WorkEmail:              pgtypeTextToStringPtr(row.WorkEmail),
			WorkPhone:              pgtypeTextToStringPtr(row.WorkPhone),
			IsAcceptingNewPatients: pgtypeBoolToBool(row.IsAcceptingNewPatients),
		}
	}

	staffDBQueryTotal.WithLabelValues("get_active_clinic_staff", "success").Inc()
	return staffList, nil
}

func (r *staffRepository) StaffExists(ctx context.Context, id uuid.UUID) (bool, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	exists, err := r.querier.StaffExists(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		staffDBQueryTotal.WithLabelValues("staff_exists", "error").Inc()
		return false, r.handleError(err, "staff exists")
	}

	staffDBQueryTotal.WithLabelValues("staff_exists", "success").Inc()
	return exists, nil
}

// ============================================
// ERROR HANDLING
// ============================================

func (r *staffRepository) handleError(err error, operation string) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			if strings.Contains(pgErr.ConstraintName, "user_id") {
				return domain.ErrDuplicateUserStaff
			}
			if strings.Contains(pgErr.ConstraintName, "work_email") {
				return domain.ErrDuplicateStaffEmail
			}
			if strings.Contains(pgErr.ConstraintName, "hpcs_number") {
				return domain.ErrDuplicateHPCSNumber
			}
			return fmt.Errorf("duplicate constraint violation: %w", err)
		case "23503": // foreign_key_violation
			return fmt.Errorf("foreign key violation: %w", err)
		case "23514": // check_violation
			return fmt.Errorf("check constraint violation: %w", err)
		}
	}
	return fmt.Errorf("%s failed: %w", operation, err)
}

// ============================================
// MAPPING FUNCTIONS
// ============================================

func (r *staffRepository) mapToClinicStaff(row sqlc.ClinicStaff) providers.ClinicStaff {
	return providers.ClinicStaff{
		ID:                     pgtypeUUIDToUUID(row.ID),
		ClinicID:               pgtypeUUIDToUUID(row.ClinicID),
		UserID:                 pgtypeUUIDToUUID(row.UserID),
		Title:                  pgtypeTextToStringPtr(row.Title),
		FirstName:              row.FirstName,
		LastName:               row.LastName,
		ProfessionalTitle:      pgtypeTextToStringPtr(row.ProfessionalTitle),
		Specialization:         pgtypeTextToStringPtr(row.Specialization),
		WorkEmail:              pgtypeTextToStringPtr(row.WorkEmail),
		WorkPhone:              pgtypeTextToStringPtr(row.WorkPhone),
		PersonalPhone:          pgtypeTextToStringPtr(row.PersonalPhone),
		HPCSNumber:             pgtypeTextToStringPtr(row.HpcsNumber),
		OtherLicenseNumbers:    mapFromJSONB(row.OtherLicenseNumbers),
		Qualifications:         row.Qualifications,
		YearsExperience:        pgtypeInt4ToIntPtr(row.YearsExperience),
		Bio:                    pgtypeTextToStringPtr(row.Bio),
		StaffRole:              row.StaffRole,
		Department:             pgtypeTextToStringPtr(row.Department),
		IsPrimaryContact:       pgtypeBoolToBool(row.IsPrimaryContact),
		WorkingHours:           mapFromJSONB(row.WorkingHours),
		AvailableDays:          row.AvailableDays,
		IsAcceptingNewPatients: pgtypeBoolToBool(row.IsAcceptingNewPatients),
		EmploymentStatus:       pgtypeTextToString(row.EmploymentStatus),
		StartDate:              pgtypeDateToTimePtr(row.StartDate),
		EndDate:                pgtypeDateToTimePtr(row.EndDate),
		ProfilePictureURL:      pgtypeTextToStringPtr(row.ProfilePictureUrl),
		LanguagesSpoken:        row.LanguagesSpoken,
		CreatedAt:              row.CreatedAt.Time,
		UpdatedAt:              row.UpdatedAt.Time,
	}
}
