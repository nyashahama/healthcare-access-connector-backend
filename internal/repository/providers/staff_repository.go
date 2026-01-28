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
		EmploymentStatus:       pgtypeTextFromString(staff.EmploymentStatus),
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
// PROFESSIONAL INFORMATION
// ============================================

func (r *staffRepository) UpdateStaffProfessionalInfo(ctx context.Context, id uuid.UUID, info providers.StaffProfessionalInfo) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateStaffProfessionalInfoParams{
		ID:                uuidToPgtypeUUID(id),
		ProfessionalTitle: pgtypeTextFromStringPtr(info.ProfessionalTitle),
		Specialization:    pgtypeTextFromStringPtr(info.Specialization),
		Qualifications:    info.Qualifications,
		YearsExperience:   intPtrToPgtypeInt4(info.YearsExperience),
		Bio:               pgtypeTextFromStringPtr(info.Bio),
	}

	err := r.querier.UpdateStaffProfessionalInfo(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("update_staff_professional_info", "error").Inc()
		return r.handleError(err, "update staff professional info")
	}

	staffDBQueryTotal.WithLabelValues("update_staff_professional_info", "success").Inc()
	return nil
}

func (r *staffRepository) UpdateStaffLicenses(ctx context.Context, id uuid.UUID, licenses providers.StaffLicenses) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	otherLicenseNumbersJSON, err := jsonbFromMap(licenses.OtherLicenseNumbers)
	if err != nil {
		return fmt.Errorf("marshal other license numbers: %w", err)
	}

	params := sqlc.UpdateStaffLicensesParams{
		ID:                  uuidToPgtypeUUID(id),
		HpcsNumber:          pgtypeTextFromStringPtr(licenses.HPCSNumber),
		OtherLicenseNumbers: otherLicenseNumbersJSON,
	}

	err = r.querier.UpdateStaffLicenses(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("update_staff_licenses", "error").Inc()
		return r.handleError(err, "update staff licenses")
	}

	staffDBQueryTotal.WithLabelValues("update_staff_licenses", "success").Inc()
	return nil
}

func (r *staffRepository) UpdateStaffQualifications(ctx context.Context, id uuid.UUID, qualifications []string) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateStaffQualificationsParams{
		ID:             uuidToPgtypeUUID(id),
		Qualifications: qualifications,
	}

	err := r.querier.UpdateStaffQualifications(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("update_staff_qualifications", "error").Inc()
		return r.handleError(err, "update staff qualifications")
	}

	staffDBQueryTotal.WithLabelValues("update_staff_qualifications", "success").Inc()
	return nil
}

func (r *staffRepository) AddStaffQualification(ctx context.Context, id uuid.UUID, qualification string) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.AddStaffQualificationParams{
		ID:          uuidToPgtypeUUID(id),
		ArrayAppend: qualification,
	}

	err := r.querier.AddStaffQualification(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("add_staff_qualification", "error").Inc()
		return r.handleError(err, "add staff qualification")
	}

	staffDBQueryTotal.WithLabelValues("add_staff_qualification", "success").Inc()
	return nil
}

// ============================================
// CONTACT INFORMATION
// ============================================

func (r *staffRepository) UpdateStaffContact(ctx context.Context, id uuid.UUID, contact providers.StaffContact) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateStaffContactParams{
		ID:            uuidToPgtypeUUID(id),
		WorkEmail:     pgtypeTextFromStringPtr(contact.WorkEmail),
		WorkPhone:     pgtypeTextFromStringPtr(contact.WorkPhone),
		PersonalPhone: pgtypeTextFromStringPtr(contact.PersonalPhone),
	}

	err := r.querier.UpdateStaffContact(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("update_staff_contact", "error").Inc()
		return r.handleError(err, "update staff contact")
	}

	staffDBQueryTotal.WithLabelValues("update_staff_contact", "success").Inc()
	return nil
}

func (r *staffRepository) UpdateStaffProfile(ctx context.Context, id uuid.UUID, profile providers.StaffProfile) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateStaffProfileParams{
		ID:                uuidToPgtypeUUID(id),
		Bio:               pgtypeTextFromStringPtr(profile.Bio),
		ProfilePictureUrl: pgtypeTextFromStringPtr(profile.ProfilePictureURL),
		LanguagesSpoken:   profile.LanguagesSpoken,
	}

	err := r.querier.UpdateStaffProfile(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("update_staff_profile", "error").Inc()
		return r.handleError(err, "update staff profile")
	}

	staffDBQueryTotal.WithLabelValues("update_staff_profile", "success").Inc()
	return nil
}

// ============================================
// ROLE & EMPLOYMENT
// ============================================

func (r *staffRepository) UpdateStaffRole(ctx context.Context, id uuid.UUID, role, department string) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateStaffRoleParams{
		ID:         uuidToPgtypeUUID(id),
		StaffRole:  role,
		Department: pgtypeTextFromString(department),
	}

	err := r.querier.UpdateStaffRole(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("update_staff_role", "error").Inc()
		return r.handleError(err, "update staff role")
	}

	staffDBQueryTotal.WithLabelValues("update_staff_role", "success").Inc()
	return nil
}

func (r *staffRepository) UpdateStaffStatus(ctx context.Context, id uuid.UUID, status string, endDate *time.Time) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateStaffStatusParams{
		ID:               uuidToPgtypeUUID(id),
		EmploymentStatus: pgtypeTextFromString(status),
		EndDate:          datePtrToPgtypeDate(endDate),
	}

	err := r.querier.UpdateStaffStatus(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("update_staff_status", "error").Inc()
		return r.handleError(err, "update staff status")
	}

	staffDBQueryTotal.WithLabelValues("update_staff_status", "success").Inc()
	return nil
}

func (r *staffRepository) UpdateStaffEmploymentDates(ctx context.Context, id uuid.UUID, startDate, endDate *time.Time) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateStaffEmploymentDatesParams{
		ID:        uuidToPgtypeUUID(id),
		StartDate: datePtrToPgtypeDate(startDate),
		EndDate:   datePtrToPgtypeDate(endDate),
	}

	err := r.querier.UpdateStaffEmploymentDates(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("update_staff_employment_dates", "error").Inc()
		return r.handleError(err, "update staff employment dates")
	}

	staffDBQueryTotal.WithLabelValues("update_staff_employment_dates", "success").Inc()
	return nil
}

func (r *staffRepository) SetPrimaryContact(ctx context.Context, clinicID, staffID uuid.UUID) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.SetPrimaryContactParams{
		ClinicID: uuidToPgtypeUUID(clinicID),
		ID:       uuidToPgtypeUUID(staffID),
	}

	err := r.querier.SetPrimaryContact(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("set_primary_contact", "error").Inc()
		return r.handleError(err, "set primary contact")
	}

	staffDBQueryTotal.WithLabelValues("set_primary_contact", "success").Inc()
	return nil
}

func (r *staffRepository) ActivateStaff(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.ActivateStaff(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		staffDBQueryTotal.WithLabelValues("activate_staff", "error").Inc()
		return r.handleError(err, "activate staff")
	}

	staffDBQueryTotal.WithLabelValues("activate_staff", "success").Inc()
	return nil
}

func (r *staffRepository) DeactivateStaff(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeactivateStaff(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		staffDBQueryTotal.WithLabelValues("deactivate_staff", "error").Inc()
		return r.handleError(err, "deactivate staff")
	}

	staffDBQueryTotal.WithLabelValues("deactivate_staff", "success").Inc()
	return nil
}

func (r *staffRepository) SetStaffOnLeave(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.SetStaffOnLeave(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		staffDBQueryTotal.WithLabelValues("set_staff_on_leave", "error").Inc()
		return r.handleError(err, "set staff on leave")
	}

	staffDBQueryTotal.WithLabelValues("set_staff_on_leave", "success").Inc()
	return nil
}

// ============================================
// AVAILABILITY & SCHEDULING
// ============================================

func (r *staffRepository) UpdateStaffAvailability(ctx context.Context, id uuid.UUID, workingHours map[string]any, availableDays []string) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	hoursJSON, err := jsonbFromMap(workingHours)
	if err != nil {
		return fmt.Errorf("marshal working hours: %w", err)
	}

	params := sqlc.UpdateStaffAvailabilityParams{
		ID:            uuidToPgtypeUUID(id),
		WorkingHours:  hoursJSON,
		AvailableDays: availableDays,
	}

	err = r.querier.UpdateStaffAvailability(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("update_staff_availability", "error").Inc()
		return r.handleError(err, "update staff availability")
	}

	staffDBQueryTotal.WithLabelValues("update_staff_availability", "success").Inc()
	return nil
}

func (r *staffRepository) UpdatePatientAcceptanceStatus(ctx context.Context, id uuid.UUID, accepting bool) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdatePatientAcceptanceStatusParams{
		ID:                     uuidToPgtypeUUID(id),
		IsAcceptingNewPatients: pgtype.Bool{Bool: accepting, Valid: true},
	}

	err := r.querier.UpdatePatientAcceptanceStatus(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("update_patient_acceptance_status", "error").Inc()
		return r.handleError(err, "update patient acceptance status")
	}

	staffDBQueryTotal.WithLabelValues("update_patient_acceptance_status", "success").Inc()
	return nil
}

func (r *staffRepository) SetAcceptingPatients(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.SetAcceptingPatients(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		staffDBQueryTotal.WithLabelValues("set_accepting_patients", "error").Inc()
		return r.handleError(err, "set accepting patients")
	}

	staffDBQueryTotal.WithLabelValues("set_accepting_patients", "success").Inc()
	return nil
}

func (r *staffRepository) SetNotAcceptingPatients(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.SetNotAcceptingPatients(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		staffDBQueryTotal.WithLabelValues("set_not_accepting_patients", "error").Inc()
		return r.handleError(err, "set not accepting patients")
	}

	staffDBQueryTotal.WithLabelValues("set_not_accepting_patients", "success").Inc()
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

func (r *staffRepository) GetAllClinicStaff(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetAllClinicStaff(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		staffDBQueryTotal.WithLabelValues("get_all_clinic_staff", "error").Inc()
		return nil, r.handleError(err, "get all clinic staff")
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
			EmploymentStatus:       row.EmploymentStatus,
			StartDate:              pgtypeDateToTimePtr(row.StartDate),
			EndDate:                pgtypeDateToTimePtr(row.EndDate),
			ProfilePictureURL:      pgtypeTextToStringPtr(row.ProfilePictureUrl),
			LanguagesSpoken:        row.LanguagesSpoken,
			CreatedAt:              row.CreatedAt.Time,
			UpdatedAt:              row.UpdatedAt.Time,
		}
	}

	staffDBQueryTotal.WithLabelValues("get_all_clinic_staff", "success").Inc()
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
			ClinicID:               pgtypeUUIDToUUID(row.ClinicID),
			UserID:                 pgtypeUUIDToUUID(row.UserID),
			Title:                  pgtypeTextToStringPtr(row.Title),
			FirstName:              row.FirstName,
			LastName:               row.LastName,
			ProfessionalTitle:      pgtypeTextToStringPtr(row.ProfessionalTitle),
			Specialization:         pgtypeTextToStringPtr(row.Specialization),
			StaffRole:              row.StaffRole,
			Department:             pgtypeTextToStringPtr(row.Department),
			WorkEmail:              pgtypeTextToStringPtr(row.WorkEmail),
			IsAcceptingNewPatients: pgtypeBoolToBool(row.IsAcceptingNewPatients),
			EmploymentStatus:       row.EmploymentStatus,
			CreatedAt:              row.CreatedAt.Time,
			UpdatedAt:              row.UpdatedAt.Time,
		}
	}

	staffDBQueryTotal.WithLabelValues("get_active_clinic_staff", "success").Inc()
	return staffList, nil
}

func (r *staffRepository) GetClinicStaffByRole(ctx context.Context, clinicID uuid.UUID, role string) ([]providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetClinicStaffByRoleParams{
		ClinicID:  uuidToPgtypeUUID(clinicID),
		StaffRole: role,
	}

	rows, err := r.querier.GetClinicStaffByRole(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("get_clinic_staff_by_role", "error").Inc()
		return nil, r.handleError(err, "get clinic staff by role")
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
			Department:             pgtypeTextToStringPtr(row.Department),
			WorkEmail:              pgtypeTextToStringPtr(row.WorkEmail),
			WorkPhone:              pgtypeTextToStringPtr(row.WorkPhone),
			IsAcceptingNewPatients: pgtypeBoolToBool(row.IsAcceptingNewPatients),
			EmploymentStatus:       row.EmploymentStatus,
			CreatedAt:              row.CreatedAt.Time,
			UpdatedAt:              row.UpdatedAt.Time,
		}
	}

	staffDBQueryTotal.WithLabelValues("get_clinic_staff_by_role", "success").Inc()
	return staffList, nil
}

func (r *staffRepository) GetClinicDoctors(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetClinicDoctors(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		staffDBQueryTotal.WithLabelValues("get_clinic_doctors", "error").Inc()
		return nil, r.handleError(err, "get clinic doctors")
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
			WorkEmail:              pgtypeTextToStringPtr(row.WorkEmail),
			WorkPhone:              pgtypeTextToStringPtr(row.WorkPhone),
			YearsExperience:        pgtypeInt4ToIntPtr(row.YearsExperience),
			Bio:                    pgtypeTextToStringPtr(row.Bio),
			StaffRole:              row.StaffRole,
			IsAcceptingNewPatients: pgtypeBoolToBool(row.IsAcceptingNewPatients),
			EmploymentStatus:       row.EmploymentStatus,
			CreatedAt:              row.CreatedAt.Time,
			UpdatedAt:              row.UpdatedAt.Time,
		}
	}

	staffDBQueryTotal.WithLabelValues("get_clinic_doctors", "success").Inc()
	return staffList, nil
}

func (r *staffRepository) GetClinicNurses(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetClinicNurses(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		staffDBQueryTotal.WithLabelValues("get_clinic_nurses", "error").Inc()
		return nil, r.handleError(err, "get clinic nurses")
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
			WorkEmail:              pgtypeTextToStringPtr(row.WorkEmail),
			WorkPhone:              pgtypeTextToStringPtr(row.WorkPhone),
			YearsExperience:        pgtypeInt4ToIntPtr(row.YearsExperience),
			StaffRole:              row.StaffRole,
			IsAcceptingNewPatients: pgtypeBoolToBool(row.IsAcceptingNewPatients),
			EmploymentStatus:       row.EmploymentStatus,
			CreatedAt:              row.CreatedAt.Time,
			UpdatedAt:              row.UpdatedAt.Time,
		}
	}

	staffDBQueryTotal.WithLabelValues("get_clinic_nurses", "success").Inc()
	return staffList, nil
}

func (r *staffRepository) GetClinicPrimaryContact(ctx context.Context, clinicID uuid.UUID) (providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	row, err := r.querier.GetClinicPrimaryContact(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			staffDBQueryTotal.WithLabelValues("get_clinic_primary_contact", "not_found").Inc()
			return providers.ClinicStaff{}, domain.ErrStaffNotFound
		}
		staffDBQueryTotal.WithLabelValues("get_clinic_primary_contact", "error").Inc()
		return providers.ClinicStaff{}, r.handleError(err, "get clinic primary contact")
	}

	staff := providers.ClinicStaff{
		ID:                pgtypeUUIDToUUID(row.ID),
		ClinicID:          pgtypeUUIDToUUID(row.ClinicID),
		UserID:            pgtypeUUIDToUUID(row.UserID),
		Title:             pgtypeTextToStringPtr(row.Title),
		FirstName:         row.FirstName,
		LastName:          row.LastName,
		ProfessionalTitle: pgtypeTextToStringPtr(row.ProfessionalTitle),
		WorkEmail:         pgtypeTextToStringPtr(row.WorkEmail),
		WorkPhone:         pgtypeTextToStringPtr(row.WorkPhone),
		PersonalPhone:     pgtypeTextToStringPtr(row.PersonalPhone),
		StaffRole:         row.StaffRole,
		Department:        pgtypeTextToStringPtr(row.Department),
		IsPrimaryContact:  true,
		EmploymentStatus:  row.EmploymentStatus,
		CreatedAt:         row.CreatedAt.Time,
		UpdatedAt:         row.UpdatedAt.Time,
	}

	staffDBQueryTotal.WithLabelValues("get_clinic_primary_contact", "success").Inc()
	return staff, nil
}

// ============================================
// STAFF SEARCH & FILTERING
// ============================================

func (r *staffRepository) SearchStaffByName(ctx context.Context, name string, clinicID *uuid.UUID, limit, offset int) ([]providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.SearchStaffByNameParams{
		Column1:  "%" + name + "%",
		ClinicID: uuidPtrToPgtypeUUID(clinicID),
		Limit:    int32(limit),
		Offset:   int32(offset),
	}

	rows, err := r.querier.SearchStaffByName(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("search_staff_by_name", "error").Inc()
		return nil, r.handleError(err, "search staff by name")
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
			WorkEmail:              pgtypeTextToStringPtr(row.WorkEmail),
			WorkPhone:              pgtypeTextToStringPtr(row.WorkPhone),
			StaffRole:              row.StaffRole,
			Department:             pgtypeTextToStringPtr(row.Department),
			YearsExperience:        pgtypeInt4ToIntPtr(row.YearsExperience),
			IsAcceptingNewPatients: pgtypeBoolToBool(row.IsAcceptingNewPatients),
			EmploymentStatus:       row.EmploymentStatus,
			CreatedAt:              row.CreatedAt.Time,
			UpdatedAt:              row.UpdatedAt.Time,
		}
	}

	staffDBQueryTotal.WithLabelValues("search_staff_by_name", "success").Inc()
	return staffList, nil
}

func (r *staffRepository) SearchStaffBySpecialization(ctx context.Context, specialization string, clinicID *uuid.UUID, limit, offset int) ([]providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetStaffBySpecializationParams{
		Specialization: pgtypeTextFromString("%" + specialization + "%"),
		ClinicID:       uuidPtrToPgtypeUUID(clinicID),
		Limit:          int32(limit),
		Offset:         int32(offset),
	}

	rows, err := r.querier.GetStaffBySpecialization(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("search_staff_by_specialization", "error").Inc()
		return nil, r.handleError(err, "search staff by specialization")
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
			WorkEmail:              pgtypeTextToStringPtr(row.WorkEmail),
			WorkPhone:              pgtypeTextToStringPtr(row.WorkPhone),
			StaffRole:              row.StaffRole,
			YearsExperience:        pgtypeInt4ToIntPtr(row.YearsExperience),
			IsAcceptingNewPatients: pgtypeBoolToBool(row.IsAcceptingNewPatients),
			EmploymentStatus:       row.EmploymentStatus,
			CreatedAt:              row.CreatedAt.Time,
			UpdatedAt:              row.UpdatedAt.Time,
		}
	}

	staffDBQueryTotal.WithLabelValues("search_staff_by_specialization", "success").Inc()
	return staffList, nil
}

func (r *staffRepository) GetStaffByDepartment(ctx context.Context, clinicID uuid.UUID, department string) ([]providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetStaffByDepartmentParams{
		ClinicID:   uuidToPgtypeUUID(clinicID),
		Department: pgtypeTextFromString(department),
	}

	rows, err := r.querier.GetStaffByDepartment(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("get_staff_by_department", "error").Inc()
		return nil, r.handleError(err, "get staff by department")
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
			Department:             pgtypeTextToStringPtr(row.Department),
			WorkEmail:              pgtypeTextToStringPtr(row.WorkEmail),
			WorkPhone:              pgtypeTextToStringPtr(row.WorkPhone),
			IsAcceptingNewPatients: pgtypeBoolToBool(row.IsAcceptingNewPatients),
			EmploymentStatus:       row.EmploymentStatus,
			CreatedAt:              row.CreatedAt.Time,
			UpdatedAt:              row.UpdatedAt.Time,
		}
	}

	staffDBQueryTotal.WithLabelValues("get_staff_by_department", "success").Inc()
	return staffList, nil
}

// ============================================
// STAFF AVAILABILITY QUERIES
// ============================================

func (r *staffRepository) GetStaffAvailableOnDay(ctx context.Context, clinicID uuid.UUID, day string) ([]providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetStaffAvailableOnDayParams{
		ClinicID:      uuidToPgtypeUUID(clinicID),
		AvailableDays: []string{day},
	}

	rows, err := r.querier.GetStaffAvailableOnDay(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("get_staff_available_on_day", "error").Inc()
		return nil, r.handleError(err, "get staff available on day")
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
			Department:             pgtypeTextToStringPtr(row.Department),
			WorkingHours:           mapFromJSONB(row.WorkingHours),
			AvailableDays:          row.AvailableDays,
			IsAcceptingNewPatients: pgtypeBoolToBool(row.IsAcceptingNewPatients),
			EmploymentStatus:       row.EmploymentStatus,
			CreatedAt:              row.CreatedAt.Time,
			UpdatedAt:              row.UpdatedAt.Time,
		}
	}

	staffDBQueryTotal.WithLabelValues("get_staff_available_on_day", "success").Inc()
	return staffList, nil
}

func (r *staffRepository) GetStaffWorkingHours(ctx context.Context, id uuid.UUID) (providers.StaffWorkingHours, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	row, err := r.querier.GetStaffWorkingHours(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			staffDBQueryTotal.WithLabelValues("get_staff_working_hours", "not_found").Inc()
			return providers.StaffWorkingHours{}, domain.ErrStaffNotFound
		}
		staffDBQueryTotal.WithLabelValues("get_staff_working_hours", "error").Inc()
		return providers.StaffWorkingHours{}, r.handleError(err, "get staff working hours")
	}

	hours := providers.StaffWorkingHours{
		ID:            pgtypeUUIDToUUID(row.ID),
		FirstName:     row.FirstName,
		LastName:      row.LastName,
		WorkingHours:  mapFromJSONB(row.WorkingHours),
		AvailableDays: row.AvailableDays,
	}

	staffDBQueryTotal.WithLabelValues("get_staff_working_hours", "success").Inc()
	return hours, nil
}

// ============================================
// LICENSING & CREDENTIALS
// ============================================

func (r *staffRepository) GetStaffByHPCSNumber(ctx context.Context, hpcsNumber string) (providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	s, err := r.querier.GetStaffByHPCSNumber(ctx, pgtypeTextFromString(hpcsNumber))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			staffDBQueryTotal.WithLabelValues("get_staff_by_hpcs_number", "not_found").Inc()
			return providers.ClinicStaff{}, domain.ErrStaffNotFound
		}
		staffDBQueryTotal.WithLabelValues("get_staff_by_hpcs_number", "error").Inc()
		return providers.ClinicStaff{}, r.handleError(err, "get staff by HPCS number")
	}

	staffDBQueryTotal.WithLabelValues("get_staff_by_hpcs_number", "success").Inc()
	return r.mapToClinicStaff(s), nil
}

func (r *staffRepository) CheckHPCSNumberExists(ctx context.Context, hpcsNumber string, excludeID *uuid.UUID) (bool, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.CheckHPCSNumberExistsParams{
		HpcsNumber: pgtypeTextFromString(hpcsNumber),
		Column2:    uuidPtrToPgtypeUUID(excludeID),
	}

	exists, err := r.querier.CheckHPCSNumberExists(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("check_hpcs_number_exists", "error").Inc()
		return false, r.handleError(err, "check HPCS number exists")
	}

	staffDBQueryTotal.WithLabelValues("check_hpcs_number_exists", "success").Inc()
	return exists, nil
}

func (r *staffRepository) GetStaffWithExpiredLicenses(ctx context.Context) ([]providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetStaffWithExpiredLicenses(ctx)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("get_staff_with_expired_licenses", "error").Inc()
		return nil, r.handleError(err, "get staff with expired licenses")
	}

	staffList := make([]providers.ClinicStaff, len(rows))
	for i, row := range rows {
		staffList[i] = providers.ClinicStaff{
			ID:                pgtypeUUIDToUUID(row.ID),
			ClinicID:          pgtypeUUIDToUUID(row.ClinicID),
			FirstName:         row.FirstName,
			LastName:          row.LastName,
			ProfessionalTitle: pgtypeTextToStringPtr(row.ProfessionalTitle),
			HPCSNumber:        pgtypeTextToStringPtr(row.HpcsNumber),
			WorkEmail:         pgtypeTextToStringPtr(row.WorkEmail),
			EmploymentStatus:  row.EmploymentStatus,
		}
	}

	staffDBQueryTotal.WithLabelValues("get_staff_with_expired_licenses", "success").Inc()
	return staffList, nil
}

func (r *staffRepository) GetStaffNeedingCredentialRenewal(ctx context.Context) ([]providers.StaffCredentialRenewal, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetStaffNeedingCredentialRenewal(ctx)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("get_staff_needing_credential_renewal", "error").Inc()
		return nil, r.handleError(err, "get staff needing credential renewal")
	}

	renewalList := make([]providers.StaffCredentialRenewal, 0)
	for _, row := range rows {
		renewalList = append(renewalList, providers.StaffCredentialRenewal{
			ID:             pgtypeUUIDToUUID(row.ID),
			ClinicID:       pgtypeUUIDToUUID(row.ClinicID),
			FirstName:      row.FirstName,
			LastName:       row.LastName,
			WorkEmail:      pgtypeTextToStringPtr(row.WorkEmail),
			CredentialType: "HPCS License",
			ExpiryDate:     nil, // This would come from license_expiry_date if it existed in the schema
		})
	}

	staffDBQueryTotal.WithLabelValues("get_staff_needing_credential_renewal", "success").Inc()
	return renewalList, nil
}

// ============================================
// TRANSFER & REASSIGNMENT
// ============================================

func (r *staffRepository) TransferStaffToClinic(ctx context.Context, staffID, newClinicID uuid.UUID) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.TransferStaffToClinicParams{
		Column1: uuidToPgtypeUUID(staffID),
		Column2: uuidToPgtypeUUID(newClinicID),
	}

	err := r.querier.TransferStaffToClinic(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("transfer_staff_to_clinic", "error").Inc()
		return r.handleError(err, "transfer staff to clinic")
	}

	staffDBQueryTotal.WithLabelValues("transfer_staff_to_clinic", "success").Inc()
	return nil
}

func (r *staffRepository) GetStaffTransferHistory(ctx context.Context, userID uuid.UUID) ([]providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetStaffTransferHistory(ctx, uuidToPgtypeUUID(userID))
	if err != nil {
		staffDBQueryTotal.WithLabelValues("get_staff_transfer_history", "error").Inc()
		return nil, r.handleError(err, "get staff transfer history")
	}

	staffList := make([]providers.ClinicStaff, len(rows))
	for i, row := range rows {
		staffList[i] = providers.ClinicStaff{
			ID:               pgtypeUUIDToUUID(row.ID),
			ClinicID:         pgtypeUUIDToUUID(row.ClinicID),
			UserID:           pgtypeUUIDToUUID(row.UserID),
			FirstName:        row.FirstName,
			LastName:         row.LastName,
			StaffRole:        row.StaffRole,
			EmploymentStatus: row.EmploymentStatus,
			StartDate:        pgtypeDateToTimePtr(row.StartDate),
			EndDate:          pgtypeDateToTimePtr(row.EndDate),
			CreatedAt:        row.CreatedAt.Time,
			UpdatedAt:        row.UpdatedAt.Time,
		}
	}

	staffDBQueryTotal.WithLabelValues("get_staff_transfer_history", "success").Inc()
	return staffList, nil
}

// ============================================
// STATISTICS & ANALYTICS
// ============================================

func (r *staffRepository) GetStaffStatistics(ctx context.Context, id uuid.UUID) (providers.StaffStatistics, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	row, err := r.querier.GetStaffStatistics(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			staffDBQueryTotal.WithLabelValues("get_staff_statistics", "not_found").Inc()
			return providers.StaffStatistics{}, domain.ErrStaffNotFound
		}
		staffDBQueryTotal.WithLabelValues("get_staff_statistics", "error").Inc()
		return providers.StaffStatistics{}, r.handleError(err, "get staff statistics")
	}

	stats := providers.StaffStatistics{
		ID:                     pgtypeUUIDToUUID(row.ID),
		FullName:               row.FirstName + " " + row.LastName,
		ProfessionalTitle:      pgtypeTextToStringPtr(row.ProfessionalTitle),
		Specialization:         pgtypeTextToStringPtr(row.Specialization),
		YearsExperience:        pgtypeInt4ToIntPtr(row.YearsExperience),
		EmploymentStatus:       row.EmploymentStatus,
		IsAcceptingNewPatients: pgtypeBoolToBool(row.IsAcceptingNewPatients),
		CreatedAt:              row.CreatedAt.Time,
	}

	staffDBQueryTotal.WithLabelValues("get_staff_statistics", "success").Inc()
	return stats, nil
}

func (r *staffRepository) GetClinicStaffMetrics(ctx context.Context, clinicID uuid.UUID) (providers.StaffMetrics, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	row, err := r.querier.GetClinicStaffMetrics(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		staffDBQueryTotal.WithLabelValues("get_clinic_staff_metrics", "error").Inc()
		return providers.StaffMetrics{}, r.handleError(err, "get clinic staff metrics")
	}

	metrics := providers.StaffMetrics{
		TotalStaff:             row.TotalStaff,
		ActiveStaff:            row.ActiveStaff,
		OnLeaveStaff:           row.OnLeaveStaff,
		TerminatedStaff:        row.TerminatedStaff,
		DoctorCount:            row.DoctorCount,
		NurseCount:             row.NurseCount,
		AdminCount:             row.AdminCount,
		AcceptingPatientsCount: row.AcceptingPatientsCount,
		AverageExperience:      pgtypeNumericToFloat64Ptr(row.AverageExperience),
	}

	staffDBQueryTotal.WithLabelValues("get_clinic_staff_metrics", "success").Inc()
	return metrics, nil
}

func (r *staffRepository) GetStaffRoleDistribution(ctx context.Context, clinicID uuid.UUID) ([]providers.StaffRoleDistribution, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetStaffRoleDistribution(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		staffDBQueryTotal.WithLabelValues("get_staff_role_distribution", "error").Inc()
		return nil, r.handleError(err, "get staff role distribution")
	}

	distribution := make([]providers.StaffRoleDistribution, len(rows))
	for i, row := range rows {
		distribution[i] = providers.StaffRoleDistribution{
			StaffRole:         row.StaffRole,
			Count:             row.Count,
			AverageExperience: pgtypeNumericToFloat64Ptr(row.AverageExperience),
		}
	}

	staffDBQueryTotal.WithLabelValues("get_staff_role_distribution", "success").Inc()
	return distribution, nil
}

func (r *staffRepository) GetStaffByExperience(ctx context.Context, clinicID uuid.UUID, minYears int) ([]providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetStaffByExperienceParams{
		ClinicID:        uuidToPgtypeUUID(clinicID),
		YearsExperience: pgtype.Int4{Int32: int32(minYears), Valid: true},
	}

	rows, err := r.querier.GetStaffByExperience(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("get_staff_by_experience", "error").Inc()
		return nil, r.handleError(err, "get staff by experience")
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
			YearsExperience:        pgtypeInt4ToIntPtr(row.YearsExperience),
			StaffRole:              row.StaffRole,
			WorkEmail:              pgtypeTextToStringPtr(row.WorkEmail),
			IsAcceptingNewPatients: pgtypeBoolToBool(row.IsAcceptingNewPatients),
			EmploymentStatus:       row.EmploymentStatus,
			CreatedAt:              row.CreatedAt.Time,
			UpdatedAt:              row.UpdatedAt.Time,
		}
	}

	staffDBQueryTotal.WithLabelValues("get_staff_by_experience", "success").Inc()
	return staffList, nil
}

func (r *staffRepository) GetStaffDemographics(ctx context.Context, clinicID uuid.UUID) (providers.StaffDemographics, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	row, err := r.querier.GetStaffDemographics(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		staffDBQueryTotal.WithLabelValues("get_staff_demographics", "error").Inc()
		return providers.StaffDemographics{}, r.handleError(err, "get staff demographics")
	}

	demographics := providers.StaffDemographics{
		TotalStaff:             row.TotalStaff,
		UniqueSpecializations:  row.UniqueSpecializations,
		UniqueRoles:            row.UniqueRoles,
		AverageLanguagesSpoken: pgtypeNumericToFloat64Ptr(row.AverageLanguagesSpoken),
	}

	staffDBQueryTotal.WithLabelValues("get_staff_demographics", "success").Inc()
	return demographics, nil
}

// ============================================
// COUNTING & EXISTENCE CHECKS
// ============================================

func (r *staffRepository) CountClinicStaff(ctx context.Context, clinicID uuid.UUID, employmentStatus *string) (int64, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.CountClinicStaffParams{
		ClinicID:         uuidToPgtypeUUID(clinicID),
		EmploymentStatus: pgtypeTextFromStringPtr(employmentStatus),
	}

	count, err := r.querier.CountClinicStaff(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("count_clinic_staff", "error").Inc()
		return 0, r.handleError(err, "count clinic staff")
	}

	staffDBQueryTotal.WithLabelValues("count_clinic_staff", "success").Inc()
	return count, nil
}

func (r *staffRepository) CountStaffByRole(ctx context.Context, clinicID uuid.UUID, role string) (int64, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.CountStaffByRoleParams{
		ClinicID:  uuidToPgtypeUUID(clinicID),
		StaffRole: role,
	}

	count, err := r.querier.CountStaffByRole(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("count_staff_by_role", "error").Inc()
		return 0, r.handleError(err, "count staff by role")
	}

	staffDBQueryTotal.WithLabelValues("count_staff_by_role", "success").Inc()
	return count, nil
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

func (r *staffRepository) CheckStaffEmailExists(ctx context.Context, email string, excludeID *uuid.UUID) (bool, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.CheckStaffEmailExistsParams{
		WorkEmail: pgtypeTextFromString(email),
		Column2:   uuidPtrToPgtypeUUID(excludeID),
	}

	exists, err := r.querier.CheckStaffEmailExists(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("check_staff_email_exists", "error").Inc()
		return false, r.handleError(err, "check staff email exists")
	}

	staffDBQueryTotal.WithLabelValues("check_staff_email_exists", "success").Inc()
	return exists, nil
}

func (r *staffRepository) CheckUserStaffExists(ctx context.Context, userID uuid.UUID) (bool, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	exists, err := r.querier.CheckUserStaffExists(ctx, uuidToPgtypeUUID(userID))
	if err != nil {
		staffDBQueryTotal.WithLabelValues("check_user_staff_exists", "error").Inc()
		return false, r.handleError(err, "check user staff exists")
	}

	staffDBQueryTotal.WithLabelValues("check_user_staff_exists", "success").Inc()
	return exists, nil
}

// ============================================
// BULK OPERATIONS
// ============================================

func (r *staffRepository) GetStaffByIDs(ctx context.Context, ids []uuid.UUID) ([]providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	pgtypeIDs := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		pgtypeIDs[i] = uuidToPgtypeUUID(id)
	}

	rows, err := r.querier.GetStaffByIDs(ctx, pgtypeIDs)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("get_staff_by_ids", "error").Inc()
		return nil, r.handleError(err, "get staff by ids")
	}

	staffList := make([]providers.ClinicStaff, len(rows))
	for i, row := range rows {
		staffList[i] = r.mapToClinicStaff(row)
	}

	staffDBQueryTotal.WithLabelValues("get_staff_by_ids", "success").Inc()
	return staffList, nil
}

func (r *staffRepository) BulkUpdateStaffStatus(ctx context.Context, ids []uuid.UUID, status string) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	pgtypeIDs := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		pgtypeIDs[i] = uuidToPgtypeUUID(id)
	}

	params := sqlc.BulkUpdateStaffStatusParams{
		Column1:          pgtypeIDs,
		EmploymentStatus: pgtypeTextFromString(status),
	}

	err := r.querier.BulkUpdateStaffStatus(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("bulk_update_staff_status", "error").Inc()
		return r.handleError(err, "bulk update staff status")
	}

	staffDBQueryTotal.WithLabelValues("bulk_update_staff_status", "success").Inc()
	return nil
}

func (r *staffRepository) BulkSetAcceptingPatients(ctx context.Context, ids []uuid.UUID, accepting bool) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	pgtypeIDs := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		pgtypeIDs[i] = uuidToPgtypeUUID(id)
	}

	params := sqlc.BulkSetAcceptingPatientsParams{
		Column1:                pgtypeIDs,
		IsAcceptingNewPatients: pgtype.Bool{Bool: accepting, Valid: true},
	}

	err := r.querier.BulkSetAcceptingPatients(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("bulk_set_accepting_patients", "error").Inc()
		return r.handleError(err, "bulk set accepting patients")
	}

	staffDBQueryTotal.WithLabelValues("bulk_set_accepting_patients", "success").Inc()
	return nil
}

func (r *staffRepository) DeactivateClinicStaff(ctx context.Context, clinicID uuid.UUID) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeactivateClinicStaff(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		staffDBQueryTotal.WithLabelValues("deactivate_clinic_staff", "error").Inc()
		return r.handleError(err, "deactivate clinic staff")
	}

	staffDBQueryTotal.WithLabelValues("deactivate_clinic_staff", "success").Inc()
	return nil
}

// ============================================
// LANGUAGE & COMMUNICATION
// ============================================

func (r *staffRepository) GetStaffByLanguage(ctx context.Context, clinicID uuid.UUID, language string) ([]providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetStaffByLanguageParams{
		ClinicID:        uuidToPgtypeUUID(clinicID),
		LanguagesSpoken: []string{language},
	}

	rows, err := r.querier.GetStaffByLanguage(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("get_staff_by_language", "error").Inc()
		return nil, r.handleError(err, "get staff by language")
	}

	staffList := make([]providers.ClinicStaff, len(rows))
	for i, row := range rows {
		staffList[i] = providers.ClinicStaff{
			ID:                pgtypeUUIDToUUID(row.ID),
			ClinicID:          pgtypeUUIDToUUID(row.ClinicID),
			UserID:            pgtypeUUIDToUUID(row.UserID),
			Title:             pgtypeTextToStringPtr(row.Title),
			FirstName:         row.FirstName,
			LastName:          row.LastName,
			ProfessionalTitle: pgtypeTextToStringPtr(row.ProfessionalTitle),
			StaffRole:         row.StaffRole,
			WorkEmail:         pgtypeTextToStringPtr(row.WorkEmail),
			LanguagesSpoken:   row.LanguagesSpoken,
			EmploymentStatus:  row.EmploymentStatus,
			CreatedAt:         row.CreatedAt.Time,
			UpdatedAt:         row.UpdatedAt.Time,
		}
	}

	staffDBQueryTotal.WithLabelValues("get_staff_by_language", "success").Inc()
	return staffList, nil
}

func (r *staffRepository) GetMultilingualStaff(ctx context.Context, clinicID uuid.UUID, minLanguages int) ([]providers.StaffLanguageInfo, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetMultilingualStaffParams{
		ClinicID: uuidToPgtypeUUID(clinicID),
		Column2:  int64(minLanguages),
	}

	rows, err := r.querier.GetMultilingualStaff(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("get_multilingual_staff", "error").Inc()
		return nil, r.handleError(err, "get multilingual staff")
	}

	staffList := make([]providers.StaffLanguageInfo, len(rows))
	for i, row := range rows {
		staffList[i] = providers.StaffLanguageInfo{
			ID:                pgtypeUUIDToUUID(row.ID),
			FirstName:         row.FirstName,
			LastName:          row.LastName,
			ProfessionalTitle: pgtypeTextToStringPtr(row.ProfessionalTitle),
			LanguagesSpoken:   row.LanguagesSpoken,
			LanguageCount:     int(row.LanguageCount),
		}
	}

	staffDBQueryTotal.WithLabelValues("get_multilingual_staff", "success").Inc()
	return staffList, nil
}

// ============================================
// REPORTING & COMPLIANCE
// ============================================

func (r *staffRepository) GetStaffWithoutHPCSNumber(ctx context.Context) ([]providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetStaffWithoutHPCSNumber(ctx)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("get_staff_without_hpcs_number", "error").Inc()
		return nil, r.handleError(err, "get staff without HPCS number")
	}

	staffList := make([]providers.ClinicStaff, len(rows))
	for i, row := range rows {
		staffList[i] = providers.ClinicStaff{
			ID:                pgtypeUUIDToUUID(row.ID),
			ClinicID:          pgtypeUUIDToUUID(row.ClinicID),
			FirstName:         row.FirstName,
			LastName:          row.LastName,
			ProfessionalTitle: pgtypeTextToStringPtr(row.ProfessionalTitle),
			StaffRole:         row.StaffRole,
			WorkEmail:         pgtypeTextToStringPtr(row.WorkEmail),
		}
	}

	staffDBQueryTotal.WithLabelValues("get_staff_without_hpcs_number", "success").Inc()
	return staffList, nil
}

func (r *staffRepository) GetStaffWithIncompleteProfiles(ctx context.Context) ([]providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetStaffWithIncompleteProfiles(ctx)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("get_staff_with_incomplete_profiles", "error").Inc()
		return nil, r.handleError(err, "get staff with incomplete profiles")
	}

	staffList := make([]providers.ClinicStaff, len(rows))
	for i, row := range rows {
		staffList[i] = providers.ClinicStaff{
			ID:                pgtypeUUIDToUUID(row.ID),
			ClinicID:          pgtypeUUIDToUUID(row.ClinicID),
			FirstName:         row.FirstName,
			LastName:          row.LastName,
			ProfessionalTitle: pgtypeTextToStringPtr(row.ProfessionalTitle),
			WorkEmail:         pgtypeTextToStringPtr(row.WorkEmail),
		}
	}

	staffDBQueryTotal.WithLabelValues("get_staff_with_incomplete_profiles", "success").Inc()
	return staffList, nil
}

func (r *staffRepository) GetStaffHiredBetweenDates(ctx context.Context, startDate, endDate time.Time) ([]providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetStaffHiredBetweenDatesParams{
		StartDate: datePtrToPgtypeDate(&startDate),
		EndDate:   datePtrToPgtypeDate(&endDate),
	}

	rows, err := r.querier.GetStaffHiredBetweenDates(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("get_staff_hired_between_dates", "error").Inc()
		return nil, r.handleError(err, "get staff hired between dates")
	}

	staffList := make([]providers.ClinicStaff, len(rows))
	for i, row := range rows {
		staffList[i] = providers.ClinicStaff{
			ID:                pgtypeUUIDToUUID(row.ID),
			ClinicID:          pgtypeUUIDToUUID(row.ClinicID),
			FirstName:         row.FirstName,
			LastName:          row.LastName,
			ProfessionalTitle: pgtypeTextToStringPtr(row.ProfessionalTitle),
			StaffRole:         row.StaffRole,
			StartDate:         pgtypeDateToTimePtr(row.StartDate),
		}
	}

	staffDBQueryTotal.WithLabelValues("get_staff_hired_between_dates", "success").Inc()
	return staffList, nil
}

func (r *staffRepository) GetStaffTerminatedBetweenDates(ctx context.Context, startDate, endDate time.Time) ([]providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetStaffTerminatedBetweenDatesParams{
		StartDate: datePtrToPgtypeDate(&startDate),
		EndDate:   datePtrToPgtypeDate(&endDate),
	}

	rows, err := r.querier.GetStaffTerminatedBetweenDates(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("get_staff_terminated_between_dates", "error").Inc()
		return nil, r.handleError(err, "get staff terminated between dates")
	}

	staffList := make([]providers.ClinicStaff, len(rows))
	for i, row := range rows {
		staffList[i] = providers.ClinicStaff{
			ID:                pgtypeUUIDToUUID(row.ID),
			ClinicID:          pgtypeUUIDToUUID(row.ClinicID),
			FirstName:         row.FirstName,
			LastName:          row.LastName,
			ProfessionalTitle: pgtypeTextToStringPtr(row.ProfessionalTitle),
			StaffRole:         row.StaffRole,
			EndDate:           pgtypeDateToTimePtr(row.EndDate),
		}
	}

	staffDBQueryTotal.WithLabelValues("get_staff_terminated_between_dates", "success").Inc()
	return staffList, nil
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
