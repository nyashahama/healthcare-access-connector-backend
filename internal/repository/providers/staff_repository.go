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
}

// NewStaffRepository creates a new staff repository using a pool
func NewStaffRepository(pool *pgxpool.Pool) repository.StaffRepository {
	return NewStaffRepositoryWithQuerier(sqlc.New(pool))
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
		UserID:                 uuidPtrToPgtypeUUID(staff.UserID),
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
		InvitationStatus:       pgtypeTextFromStringPtr(staff.InvitationStatus),
		CanManageStaff:         pgtype.Bool{Bool: staff.CanManageStaff, Valid: true},
		CanApproveAppointments: pgtype.Bool{Bool: staff.CanApproveAppointments, Valid: true},
		CanEditClinicInfo:      pgtype.Bool{Bool: staff.CanEditClinicInfo, Valid: true},
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
			UserID:                 pgtypeUUIDToUUIDPtr(row.UserID),
			Title:                  pgtypeTextToStringPtr(row.Title),
			FirstName:              row.FirstName,
			LastName:               row.LastName,
			ProfessionalTitle:      pgtypeTextToStringPtr(row.ProfessionalTitle),
			Specialization:         pgtypeTextToStringPtr(row.Specialization),
			StaffRole:              row.StaffRole,
			EmploymentStatus:       pgtypeTextToString(row.EmploymentStatus),
			IsAcceptingNewPatients: pgtypeBoolToBool(row.IsAcceptingNewPatients),
			StartDate:              pgtypeDateToTimePtr(row.StartDate),
			EndDate:                pgtypeDateToTimePtr(row.EndDate),
			InvitationStatus:       pgtypeTextToStringPtr(row.InvitationStatus),
			CreatedAt:              row.CreatedAt.Time,
		}
	}

	staffDBQueryTotal.WithLabelValues("get_all_clinic_staff", "success").Inc()
	return staffList, nil
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
			UserID:                 pgtypeUUIDToUUIDPtr(row.UserID),
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
			InvitationStatus:       pgtypeTextToStringPtr(row.InvitationStatus),
			CanManageStaff:         pgtypeBoolToBool(row.CanManageStaff),
			CanApproveAppointments: pgtypeBoolToBool(row.CanApproveAppointments),
			CanEditClinicInfo:      pgtypeBoolToBool(row.CanEditClinicInfo),
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
			UserID:                 pgtypeUUIDToUUIDPtr(row.UserID),
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

func (r *staffRepository) CreateStaffInvitation(ctx context.Context, invitation providers.StaffInvitation) (providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.CreateStaffInvitationParams{
		ClinicID:               uuidToPgtypeUUID(invitation.ClinicID),
		WorkEmail:              pgtype.Text{String: invitation.WorkEmail, Valid: true},
		FirstName:              invitation.FirstName,
		LastName:               invitation.LastName,
		StaffRole:              invitation.StaffRole,
		ProfessionalTitle:      pgtypeTextFromStringPtr(invitation.ProfessionalTitle),
		InvitationToken:        pgtype.Text{String: invitation.InvitationToken, Valid: true},
		InvitedBy:              uuidToPgtypeUUID(invitation.InvitedBy),
		InvitationExpires:      pgtype.Timestamp{Time: invitation.InvitationExpires, Valid: true},
		CanManageStaff:         pgtype.Bool{Bool: invitation.CanManageStaff, Valid: true},
		CanApproveAppointments: pgtype.Bool{Bool: invitation.CanApproveAppointments, Valid: true},
		CanEditClinicInfo:      pgtype.Bool{Bool: invitation.CanEditClinicInfo, Valid: true},
	}

	created, err := r.querier.CreateStaffInvitation(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("create_invitation", "error").Inc()
		return providers.ClinicStaff{}, r.handleError(err, "create staff invitation")
	}

	staffDBQueryTotal.WithLabelValues("create_invitation", "success").Inc()
	return r.mapToClinicStaff(created), nil
}

func (r *staffRepository) GetStaffInvitationByToken(ctx context.Context, token string) (*providers.StaffInvitationDetails, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	row, err := r.querier.GetStaffInvitationByToken(ctx, pgtype.Text{String: token, Valid: true})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			staffDBQueryTotal.WithLabelValues("get_invitation_by_token", "not_found").Inc()
			return nil, domain.ErrInvitationNotFound
		}
		staffDBQueryTotal.WithLabelValues("get_invitation_by_token", "error").Inc()
		return nil, fmt.Errorf("get invitation by token: %w", err)
	}

	details := &providers.StaffInvitationDetails{
		StaffInvitation: providers.StaffInvitation{
			ClinicID:               pgtypeUUIDToUUID(row.ClinicID),
			WorkEmail:              pgtypeTextToString(row.WorkEmail),
			FirstName:              row.FirstName,
			LastName:               row.LastName,
			StaffRole:              row.StaffRole,
			ProfessionalTitle:      pgtypeTextToStringPtr(row.ProfessionalTitle),
			InvitationToken:        pgtypeTextToString(row.InvitationToken),
			InvitedBy:              pgtypeUUIDToUUID(row.InvitedBy),
			InvitationExpires:      *pgtypeTimestampToTimePtr(row.InvitationExpires),
			CanManageStaff:         pgtypeBoolToBool(row.CanManageStaff),
			CanApproveAppointments: pgtypeBoolToBool(row.CanApproveAppointments),
			CanEditClinicInfo:      pgtypeBoolToBool(row.CanEditClinicInfo),
		},
		ClinicName:   row.ClinicName,
		City:         pgtypeTextToStringPtr(row.City),
		Province:     pgtypeTextToStringPtr(row.Province),
		InviterEmail: pgtypeTextToStringPtr(row.InviterEmail),
		InviterPhone: pgtypeTextToStringPtr(row.InviterPhone),
	}

	staffDBQueryTotal.WithLabelValues("get_invitation_by_token", "success").Inc()
	return details, nil
}

func (r *staffRepository) AcceptStaffInvitation(ctx context.Context, token string, userID uuid.UUID) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.AcceptStaffInvitationParams{
		InvitationToken: pgtype.Text{String: token, Valid: true},
		UserID:          uuidToPgtypeUUID(userID),
	}

	err := r.querier.AcceptStaffInvitation(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("accept_invitation", "error").Inc()
		return fmt.Errorf("accept staff invitation: %w", err)
	}

	staffDBQueryTotal.WithLabelValues("accept_invitation", "success").Inc()
	return nil
}

func (r *staffRepository) DeclineStaffInvitation(ctx context.Context, token string) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeclineStaffInvitation(ctx, pgtype.Text{String: token, Valid: true})
	if err != nil {
		staffDBQueryTotal.WithLabelValues("decline_invitation", "error").Inc()
		return fmt.Errorf("decline staff invitation: %w", err)
	}

	staffDBQueryTotal.WithLabelValues("decline_invitation", "success").Inc()
	return nil
}

func (r *staffRepository) GetPendingInvitationsByClinic(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPendingInvitationsByClinic(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		staffDBQueryTotal.WithLabelValues("get_pending_invitations", "error").Inc()
		return nil, fmt.Errorf("get pending invitations: %w", err)
	}

	invitations := make([]providers.ClinicStaff, len(rows))
	for i, row := range rows {
		invitations[i] = providers.ClinicStaff{
			ID:                pgtypeUUIDToUUID(row.ID),
			WorkEmail:         pgtypeTextToStringPtr(row.WorkEmail),
			FirstName:         row.FirstName,
			LastName:          row.LastName,
			StaffRole:         row.StaffRole,
			ProfessionalTitle: pgtypeTextToStringPtr(row.ProfessionalTitle),
			InvitationToken:   pgtypeTextToStringPtr(row.InvitationToken),
			InvitedAt:         pgtypeTimestampToTimePtr(row.InvitedAt),
			InvitationExpires: pgtypeTimestampToTimePtr(row.InvitationExpires),
			InvitedBy:         pgtypeUUIDToUUIDPtr(row.InvitedBy),
		}
	}

	staffDBQueryTotal.WithLabelValues("get_pending_invitations", "success").Inc()
	return invitations, nil
}

func (r *staffRepository) GetStaffInvitationsByEmail(ctx context.Context, email string) ([]providers.StaffInvitationDetails, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetStaffInvitationsByEmail(ctx, pgtype.Text{String: email, Valid: true})
	if err != nil {
		staffDBQueryTotal.WithLabelValues("get_invitations_by_email", "error").Inc()
		return nil, fmt.Errorf("get invitations by email: %w", err)
	}

	invitations := make([]providers.StaffInvitationDetails, len(rows))
	for i, row := range rows {
		invitations[i] = providers.StaffInvitationDetails{
			StaffInvitation: providers.StaffInvitation{
				ClinicID:               pgtypeUUIDToUUID(row.ClinicID),
				WorkEmail:              pgtypeTextToString(row.WorkEmail),
				FirstName:              row.FirstName,
				LastName:               row.LastName,
				StaffRole:              row.StaffRole,
				ProfessionalTitle:      pgtypeTextToStringPtr(row.ProfessionalTitle),
				InvitationToken:        pgtypeTextToString(row.InvitationToken),
				InvitedBy:              pgtypeUUIDToUUID(row.InvitedBy),
				InvitationExpires:      *pgtypeTimestampToTimePtr(row.InvitationExpires),
				CanManageStaff:         pgtypeBoolToBool(row.CanManageStaff),
				CanApproveAppointments: pgtypeBoolToBool(row.CanApproveAppointments),
				CanEditClinicInfo:      pgtypeBoolToBool(row.CanEditClinicInfo),
			},
			ClinicName: row.ClinicName,
			City:       pgtypeTextToStringPtr(row.City),
			Province:   pgtypeTextToStringPtr(row.Province),
		}
	}

	staffDBQueryTotal.WithLabelValues("get_invitations_by_email", "success").Inc()
	return invitations, nil
}

func (r *staffRepository) CancelStaffInvitation(ctx context.Context, token string) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.CancelStaffInvitation(ctx, pgtype.Text{String: token, Valid: true})
	if err != nil {
		staffDBQueryTotal.WithLabelValues("cancel_invitation", "error").Inc()
		return fmt.Errorf("cancel staff invitation: %w", err)
	}

	staffDBQueryTotal.WithLabelValues("cancel_invitation", "success").Inc()
	return nil
}

func (r *staffRepository) ResendStaffInvitation(ctx context.Context, invitationID uuid.UUID) (string, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Generate new token and expiry
	newToken := uuid.New().String()
	newExpiry := time.Now().Add(7 * 24 * time.Hour)

	params := sqlc.ResendStaffInvitationParams{
		ID:                uuidToPgtypeUUID(invitationID),
		InvitationToken:   pgtype.Text{String: newToken, Valid: true},
		InvitationExpires: pgtype.Timestamp{Time: newExpiry, Valid: true},
	}

	err := r.querier.ResendStaffInvitation(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("resend_invitation", "error").Inc()
		return "", fmt.Errorf("resend staff invitation: %w", err)
	}

	staffDBQueryTotal.WithLabelValues("resend_invitation", "success").Inc()
	return newToken, nil
}

func (r *staffRepository) CheckStaffEmailExists(ctx context.Context, clinicID uuid.UUID, email string) (bool, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.CheckStaffEmailExistsParams{
		ClinicID:  uuidToPgtypeUUID(clinicID),
		WorkEmail: pgtype.Text{String: email, Valid: true},
	}

	exists, err := r.querier.CheckStaffEmailExists(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("check_email_exists", "error").Inc()
		return false, fmt.Errorf("check staff email exists: %w", err)
	}

	staffDBQueryTotal.WithLabelValues("check_email_exists", "success").Inc()
	return exists, nil
}

func (r *staffRepository) GetStaffByUserAndClinic(ctx context.Context, userID, clinicID uuid.UUID) (*providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetStaffByUserAndClinicParams{
		UserID:   uuidToPgtypeUUID(userID),
		ClinicID: uuidToPgtypeUUID(clinicID),
	}

	row, err := r.querier.GetStaffByUserAndClinic(ctx, params)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			staffDBQueryTotal.WithLabelValues("get_staff_by_user_clinic", "not_found").Inc()
			return nil, domain.ErrStaffNotFound
		}
		staffDBQueryTotal.WithLabelValues("get_staff_by_user_clinic", "error").Inc()
		return nil, fmt.Errorf("get staff by user and clinic: %w", err)
	}

	staff := r.mapToClinicStaff(row)
	staffDBQueryTotal.WithLabelValues("get_staff_by_user_clinic", "success").Inc()
	return &staff, nil
}

func (r *staffRepository) UpdateStaffPermissions(ctx context.Context, staffID uuid.UUID, permissions providers.StaffPermissions) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	permissionsJSON, err := jsonbFromMap(permissions.CustomPermissions)
	if err != nil {
		return fmt.Errorf("marshal custom permissions: %w", err)
	}

	params := sqlc.UpdateStaffPermissionsParams{
		ID:                     uuidToPgtypeUUID(staffID),
		CanManageStaff:         pgtype.Bool{Bool: permissions.CanManageStaff, Valid: true},
		CanApproveAppointments: pgtype.Bool{Bool: permissions.CanApproveAppointments, Valid: true},
		CanEditClinicInfo:      pgtype.Bool{Bool: permissions.CanEditClinicInfo, Valid: true},
		Permissions:            permissionsJSON,
	}

	err = r.querier.UpdateStaffPermissions(ctx, params)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("update_permissions", "error").Inc()
		return fmt.Errorf("update staff permissions: %w", err)
	}

	staffDBQueryTotal.WithLabelValues("update_permissions", "success").Inc()
	return nil
}

func (r *staffRepository) ExpireStaffInvitations(ctx context.Context) error {
	start := time.Now()
	defer func() {
		staffDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.ExpireStaffInvitations(ctx)
	if err != nil {
		staffDBQueryTotal.WithLabelValues("expire_invitations", "error").Inc()
		return fmt.Errorf("expire staff invitations: %w", err)
	}

	staffDBQueryTotal.WithLabelValues("expire_invitations", "success").Inc()
	return nil
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
		ID:                  pgtypeUUIDToUUID(row.ID),
		ClinicID:            pgtypeUUIDToUUID(row.ClinicID),
		UserID:              pgtypeUUIDToUUIDPtr(row.UserID),
		Title:               pgtypeTextToStringPtr(row.Title),
		FirstName:           row.FirstName,
		LastName:            row.LastName,
		ProfessionalTitle:   pgtypeTextToStringPtr(row.ProfessionalTitle),
		Specialization:      pgtypeTextToStringPtr(row.Specialization),
		WorkEmail:           pgtypeTextToStringPtr(row.WorkEmail),
		WorkPhone:           pgtypeTextToStringPtr(row.WorkPhone),
		PersonalPhone:       pgtypeTextToStringPtr(row.PersonalPhone),
		HPCSNumber:          pgtypeTextToStringPtr(row.HpcsNumber),
		OtherLicenseNumbers: mapFromJSONB(row.OtherLicenseNumbers),
		Qualifications:      row.Qualifications,
		YearsExperience:     pgtypeInt4ToIntPtr(row.YearsExperience),
		Bio:                 pgtypeTextToStringPtr(row.Bio),
		StaffRole:           row.StaffRole,
		Department:          pgtypeTextToStringPtr(row.Department),
		IsPrimaryContact:    pgtypeBoolToBool(row.IsPrimaryContact),
		// Invitation fields
		InvitationToken:   pgtypeTextToStringPtr(row.InvitationToken),
		InvitationStatus:  pgtypeTextToStringPtr(row.InvitationStatus),
		InvitedBy:         pgtypeUUIDToUUIDPtr(row.InvitedBy),
		InvitedAt:         pgtypeTimestampToTimePtr(row.InvitedAt),
		InvitationExpires: pgtypeTimestampToTimePtr(row.InvitationExpires),
		// Permission fields - CRITICAL FIX
		Permissions:            mapFromJSONB(row.Permissions),
		CanManageStaff:         pgtypeBoolToBool(row.CanManageStaff),
		CanApproveAppointments: pgtypeBoolToBool(row.CanApproveAppointments),
		CanEditClinicInfo:      pgtypeBoolToBool(row.CanEditClinicInfo),
		// Working hours and availability
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
