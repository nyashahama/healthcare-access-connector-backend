package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	auditDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "audit_db_query_duration_seconds",
			Help:    "Audit database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	auditDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "audit_db_query_total",
			Help: "Total number of audit database queries",
		},
		[]string{"operation", "status"},
	)
)

type auditRepository struct {
	querier sqlc.Querier
}

// NewAuditRepository creates a new audit repository using a pool
func NewAuditRepository(pool *pgxpool.Pool) repository.AuditRepository {
	return NewAuditRepositoryWithQuerier(sqlc.New(pool))
}

// NewAuditRepositoryWithQuerier creates a new audit repository using a provided querier (for transactions)
func NewAuditRepositoryWithQuerier(querier sqlc.Querier) repository.AuditRepository {
	return &auditRepository{
		querier: querier,
	}
}

func (r *auditRepository) LogUserActivity(ctx context.Context, activity core.UserActivity) error {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Convert activity details to JSONB
	activityDetails, err := json.Marshal(activity.ActivityDetails)
	if err != nil {
		auditDBQueryTotal.WithLabelValues("log_user_activity", "error").Inc()
		return fmt.Errorf("convert activity details: %w", err)
	}

	// Convert location to JSONB
	location, err := json.Marshal(activity.Location)
	if err != nil {
		auditDBQueryTotal.WithLabelValues("log_user_activity", "error").Inc()
		return fmt.Errorf("convert location: %w", err)
	}

	var ipAddr *netip.Addr
	if activity.IPAddress != nil {
		addr, err := netip.ParseAddr(*activity.IPAddress)
		if err == nil {
			ipAddr = &addr
		}
	}

	err = r.querier.LogUserActivity(ctx, sqlc.LogUserActivityParams{
		UserID:          uuidPtrToPgtypeUUID(activity.UserID),
		ActivityType:    activity.ActivityType,
		ActivityDetails: activityDetails,
		IpAddress:       ipAddr,
		UserAgent:       pgtypeTextFromStringPtr(activity.UserAgent),
		DeviceType:      pgtypeTextFromStringPtr(activity.DeviceType),
		DeviceID:        pgtypeTextFromStringPtr(activity.DeviceID),
		Location:        location,
		ResourceType:    pgtypeTextFromStringPtr(activity.ResourceType),
		ResourceID:      uuidPtrToPgtypeUUID(activity.ResourceID),
	})
	if err != nil {
		auditDBQueryTotal.WithLabelValues("log_user_activity", "error").Inc()
		return r.handleError(err, "log user activity")
	}

	auditDBQueryTotal.WithLabelValues("log_user_activity", "success").Inc()
	return nil
}

func (r *auditRepository) GetUserActivities(ctx context.Context, userID uuid.UUID, limit, offset int) ([]core.UserActivity, error) {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	activities, err := r.querier.GetUserActivities(ctx, sqlc.GetUserActivitiesParams{
		UserID: uuidToPgtypeUUID(userID),
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		auditDBQueryTotal.WithLabelValues("get_user_activities", "error").Inc()
		return nil, r.handleError(err, "get user activities")
	}

	auditDBQueryTotal.WithLabelValues("get_user_activities", "success").Inc()

	result := make([]core.UserActivity, len(activities))
	for i, a := range activities {
		result[i] = r.mapUserActivityFromRow(a)
	}

	return result, nil
}

func (r *auditRepository) GetActivitiesByType(ctx context.Context, activityType string, startDate, endDate time.Time) ([]core.UserActivity, error) {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	activities, err := r.querier.GetActivitiesByType(ctx, sqlc.GetActivitiesByTypeParams{
		ActivityType:  activityType,
		PerformedAt:   timeToPgtypeTimestamp(startDate),
		PerformedAt_2: timeToPgtypeTimestamp(endDate),
	})
	if err != nil {
		auditDBQueryTotal.WithLabelValues("get_activities_by_type", "error").Inc()
		return nil, r.handleError(err, "get activities by type")
	}

	auditDBQueryTotal.WithLabelValues("get_activities_by_type", "success").Inc()

	result := make([]core.UserActivity, len(activities))
	for i, a := range activities {
		result[i] = r.mapUserActivityFromRow(a)
	}

	return result, nil
}

func (r *auditRepository) GetActivitiesByResource(ctx context.Context, resourceType string, resourceID uuid.UUID) ([]core.UserActivity, error) {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	activities, err := r.querier.GetActivitiesByResource(ctx, sqlc.GetActivitiesByResourceParams{
		ResourceType: pgtypeTextFromString(resourceType),
		ResourceID:   uuidToPgtypeUUID(resourceID),
	})
	if err != nil {
		auditDBQueryTotal.WithLabelValues("get_activities_by_resource", "error").Inc()
		return nil, r.handleError(err, "get activities by resource")
	}

	auditDBQueryTotal.WithLabelValues("get_activities_by_resource", "success").Inc()

	result := make([]core.UserActivity, len(activities))
	for i, a := range activities {
		result[i] = r.mapUserActivityFromRow(a)
	}

	return result, nil
}

func (r *auditRepository) LogDataAccess(ctx context.Context, access core.DataAccessLog) error {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Convert location to JSONB
	location, err := json.Marshal(access.Location)
	if err != nil {
		auditDBQueryTotal.WithLabelValues("log_data_access", "error").Inc()
		return fmt.Errorf("convert location: %w", err)
	}

	var ipAddr *netip.Addr
	if access.IPAddress != nil {
		addr, err := netip.ParseAddr(*access.IPAddress)
		if err == nil {
			ipAddr = &addr
		}
	}

	err = r.querier.LogDataAccess(ctx, sqlc.LogDataAccessParams{
		AccessedByUserID:     uuidPtrToPgtypeUUID(access.AccessedByUserID),
		AccessedByRole:       pgtypeTextFromStringPtr(access.AccessedByRole),
		AccessedUserID:       uuidToPgtypeUUID(access.AccessedUserID),
		AccessedResourceType: pgtypeTextFromStringPtr(access.AccessedResourceType),
		AccessedResourceID:   uuidPtrToPgtypeUUID(access.AccessedResourceID),
		AccessType:           pgtypeTextFromString(access.AccessType),
		AccessReason:         pgtypeTextFromStringPtr(access.AccessReason),
		IsEmergencyAccess:    pgtype.Bool{Bool: access.IsEmergencyAccess, Valid: true},
		IpAddress:            ipAddr,
		UserAgent:            pgtypeTextFromStringPtr(access.UserAgent),
		Location:             location,
	})
	if err != nil {
		auditDBQueryTotal.WithLabelValues("log_data_access", "error").Inc()
		return r.handleError(err, "log data access")
	}

	auditDBQueryTotal.WithLabelValues("log_data_access", "success").Inc()
	return nil
}

func (r *auditRepository) GetDataAccessLogs(ctx context.Context, accessedUserID uuid.UUID, limit, offset int) ([]core.DataAccessLog, error) {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	logs, err := r.querier.GetDataAccessLogs(ctx, sqlc.GetDataAccessLogsParams{
		AccessedUserID: uuidToPgtypeUUID(accessedUserID),
		Limit:          int32(limit),
		Offset:         int32(offset),
	})
	if err != nil {
		auditDBQueryTotal.WithLabelValues("get_data_access_logs", "error").Inc()
		return nil, r.handleError(err, "get data access logs")
	}

	auditDBQueryTotal.WithLabelValues("get_data_access_logs", "success").Inc()

	result := make([]core.DataAccessLog, len(logs))
	for i, l := range logs {
		result[i] = r.mapDataAccessLogFromRow(l)
	}

	return result, nil
}

func (r *auditRepository) GetDataAccessLogsByAccessor(ctx context.Context, accessedByUserID uuid.UUID, limit, offset int) ([]core.DataAccessLog, error) {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	logs, err := r.querier.GetAccessLogsByAccessedByUser(ctx, sqlc.GetAccessLogsByAccessedByUserParams{
		AccessedByUserID: uuidToPgtypeUUID(accessedByUserID),
		Limit:            int32(limit),
		Offset:           int32(offset),
	})
	if err != nil {
		auditDBQueryTotal.WithLabelValues("get_data_access_logs_by_accessor", "error").Inc()
		return nil, r.handleError(err, "get data access logs by accessor")
	}

	auditDBQueryTotal.WithLabelValues("get_data_access_logs_by_accessor", "success").Inc()

	result := make([]core.DataAccessLog, len(logs))
	for i, l := range logs {
		result[i] = r.mapDataAccessLogFromRow(l)
	}

	return result, nil
}

func (r *auditRepository) GetEmergencyAccessLogs(ctx context.Context, limit, offset int) ([]core.DataAccessLog, error) {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	logs, err := r.querier.GetEmergencyAccessLogs(ctx, sqlc.GetEmergencyAccessLogsParams{
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		auditDBQueryTotal.WithLabelValues("get_emergency_access_logs", "error").Inc()
		return nil, r.handleError(err, "get emergency access logs")
	}

	auditDBQueryTotal.WithLabelValues("get_emergency_access_logs", "success").Inc()

	result := make([]core.DataAccessLog, len(logs))
	for i, l := range logs {
		result[i] = r.mapDataAccessLogFromRow(l)
	}

	return result, nil
}

func (r *auditRepository) GetAccessLogsByResourceType(ctx context.Context, resourceType string, startDate, endDate time.Time) ([]core.DataAccessLog, error) {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	logs, err := r.querier.SearchDataAccessLogs(ctx, sqlc.SearchDataAccessLogsParams{
		Column1: pgtype.UUID{Valid: false},        // accessed_user_id - NULL
		Column2: pgtype.UUID{Valid: false},        // accessed_by_user_id - NULL
		Column3: "",                               // access_type - empty string
		Column4: resourceType,                     // accessed_resource_type
		Column5: false,                            // is_emergency_access - false (not filtering)
		Column6: timeToPgtypeTimestamp(startDate), // accessed_at >=
		Column7: timeToPgtypeTimestamp(endDate),   // accessed_at <=
		Limit:   1000,
		Offset:  0,
	})
	if err != nil {
		auditDBQueryTotal.WithLabelValues("get_access_logs_by_resource_type", "error").Inc()
		return nil, r.handleError(err, "get access logs by resource type")
	}

	auditDBQueryTotal.WithLabelValues("get_access_logs_by_resource_type", "success").Inc()

	result := make([]core.DataAccessLog, len(logs))
	for i, l := range logs {
		result[i] = r.mapDataAccessLogFromRow(l)
	}

	return result, nil
}

func (r *auditRepository) GetSuspiciousActivities(ctx context.Context, threshold int) ([]core.UserActivity, error) {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// This would typically query for activities that match certain suspicious patterns
	// For now, we'll return an empty slice as a placeholder
	// In a real implementation, you'd have a SQL query for this
	auditDBQueryTotal.WithLabelValues("get_suspicious_activities", "success").Inc()
	return []core.UserActivity{}, nil
}

func (r *auditRepository) GetFailedLoginAttempts(ctx context.Context, userID *uuid.UUID, within time.Duration) ([]core.UserActivity, error) {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	since := time.Now().Add(-within)

	var pgUserID pgtype.UUID
	if userID != nil {
		pgUserID = uuidToPgtypeUUID(*userID)
	}

	activities, err := r.querier.SearchUserActivities(ctx, sqlc.SearchUserActivitiesParams{
		Column1: pgUserID,
		Column2: "login_failed",
		Column3: "",                             // resource_type - empty
		Column4: timeToPgtypeTimestamp(since),   // performed_at >=
		Column5: pgtype.Timestamp{Valid: false}, // performed_at <= - not filtering
		Limit:   1000,
		Offset:  0,
	})
	if err != nil {
		auditDBQueryTotal.WithLabelValues("get_failed_login_attempts", "error").Inc()
		return nil, r.handleError(err, "get failed login attempts")
	}

	auditDBQueryTotal.WithLabelValues("get_failed_login_attempts", "success").Inc()

	result := make([]core.UserActivity, len(activities))
	for i, a := range activities {
		result[i] = r.mapUserActivityFromRow(a)
	}

	return result, nil
}

func (r *auditRepository) GetUnauthorizedAccessAttempts(ctx context.Context, within time.Duration) ([]core.DataAccessLog, error) {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	since := time.Now().Add(-within)

	logs, err := r.querier.SearchDataAccessLogs(ctx, sqlc.SearchDataAccessLogsParams{
		Column1: pgtype.UUID{Valid: false},      // accessed_user_id - NULL
		Column2: pgtype.UUID{Valid: false},      // accessed_by_user_id - NULL
		Column3: "unauthorized",                 // access_type
		Column4: "",                             // accessed_resource_type - empty
		Column5: false,                          // is_emergency_access - false
		Column6: timeToPgtypeTimestamp(since),   // accessed_at >=
		Column7: pgtype.Timestamp{Valid: false}, // accessed_at <= - not filtering
		Limit:   1000,
		Offset:  0,
	})
	if err != nil {
		auditDBQueryTotal.WithLabelValues("get_unauthorized_access_attempts", "error").Inc()
		return nil, r.handleError(err, "get unauthorized access attempts")
	}

	auditDBQueryTotal.WithLabelValues("get_unauthorized_access_attempts", "success").Inc()

	result := make([]core.DataAccessLog, len(logs))
	for i, l := range logs {
		result[i] = r.mapDataAccessLogFromRow(l)
	}

	return result, nil
}

func (r *auditRepository) ArchiveOldLogs(ctx context.Context, olderThan time.Duration) error {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	cutoffDate := time.Now().Add(-olderThan)

	err := r.querier.DeleteOldDataAccessLogs(ctx, timeToPgtypeTimestamp(cutoffDate))
	if err != nil {
		auditDBQueryTotal.WithLabelValues("archive_old_logs", "error").Inc()
		return r.handleError(err, "archive old logs")
	}

	auditDBQueryTotal.WithLabelValues("archive_old_logs", "success").Inc()
	return nil
}

func (r *auditRepository) DeleteArchivedLogs(ctx context.Context, olderThan time.Duration) error {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// This would delete from an archive table
	// For now, we'll just return success
	auditDBQueryTotal.WithLabelValues("delete_archived_logs", "success").Inc()
	return nil
}

func (r *auditRepository) ArchiveOldActivities(ctx context.Context, olderThan time.Duration) error {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	cutoffDate := time.Now().Add(-olderThan)

	err := r.querier.DeleteOldUserActivities(ctx, timeToPgtypeTimestamp(cutoffDate))
	if err != nil {
		auditDBQueryTotal.WithLabelValues("archive_old_activities", "error").Inc()
		return r.handleError(err, "archive old activities")
	}

	auditDBQueryTotal.WithLabelValues("archive_old_activities", "success").Inc()
	return nil
}

func (r *auditRepository) GenerateAccessReport(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) (interface{}, error) {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	logs, err := r.querier.ExportDataAccessLogs(ctx, sqlc.ExportDataAccessLogsParams{
		AccessedUserID: uuidToPgtypeUUID(userID),
		AccessedAt:     timeToPgtypeTimestamp(startDate),
		AccessedAt_2:   timeToPgtypeTimestamp(endDate),
	})
	if err != nil {
		auditDBQueryTotal.WithLabelValues("generate_access_report", "error").Inc()
		return nil, r.handleError(err, "generate access report")
	}

	// Convert to domain objects
	accessLogs := make([]core.DataAccessLog, len(logs))
	for i, l := range logs {
		accessLogs[i] = r.mapDataAccessLogFromRow(l)
	}

	// Create a report structure
	report := struct {
		UserID    uuid.UUID            `json:"user_id"`
		StartDate time.Time            `json:"start_date"`
		EndDate   time.Time            `json:"end_date"`
		Total     int                  `json:"total"`
		Logs      []core.DataAccessLog `json:"logs"`
		Summary   map[string]int       `json:"summary"`
	}{
		UserID:    userID,
		StartDate: startDate,
		EndDate:   endDate,
		Total:     len(accessLogs),
		Logs:      accessLogs,
		Summary:   make(map[string]int),
	}

	// Generate summary by access type
	for _, log := range accessLogs {
		report.Summary[log.AccessType]++
	}

	auditDBQueryTotal.WithLabelValues("generate_access_report", "success").Inc()
	return report, nil
}

func (r *auditRepository) GenerateActivityReport(ctx context.Context, startDate, endDate time.Time) (interface{}, error) {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Get recent activities within the date range
	activities, err := r.querier.GetRecentActivities(ctx, sqlc.GetRecentActivitiesParams{
		PerformedAt: timeToPgtypeTimestamp(startDate),
		Limit:       10000,
		Offset:      0,
	})
	if err != nil {
		auditDBQueryTotal.WithLabelValues("generate_activity_report", "error").Inc()
		return nil, r.handleError(err, "generate activity report")
	}

	// Filter by end date
	var filtered []sqlc.UserActivity
	for _, activity := range activities {
		if !activity.PerformedAt.Time.After(endDate) {
			filtered = append(filtered, activity)
		}
	}

	// Create a report structure
	report := struct {
		StartDate    time.Time                 `json:"start_date"`
		EndDate      time.Time                 `json:"end_date"`
		Total        int                       `json:"total"`
		ByType       map[string]int            `json:"by_type"`
		ByUser       map[uuid.UUID]int         `json:"by_user"`
		TopResources map[string]map[string]int `json:"top_resources"`
	}{
		StartDate:    startDate,
		EndDate:      endDate,
		Total:        len(filtered),
		ByType:       make(map[string]int),
		ByUser:       make(map[uuid.UUID]int),
		TopResources: make(map[string]map[string]int),
	}

	// Generate statistics
	for _, activity := range filtered {
		// Count by type
		report.ByType[activity.ActivityType]++

		// Count by user
		if activity.UserID.Valid {
			userID := pgtypeUUIDToUUID(activity.UserID)
			report.ByUser[userID]++
		}

		// Count by resource
		if activity.ResourceType.Valid && activity.ResourceID.Valid {
			resourceType := activity.ResourceType.String
			resourceID := pgtypeUUIDToUUID(activity.ResourceID).String()

			if _, exists := report.TopResources[resourceType]; !exists {
				report.TopResources[resourceType] = make(map[string]int)
			}
			report.TopResources[resourceType][resourceID]++
		}
	}

	auditDBQueryTotal.WithLabelValues("generate_activity_report", "success").Inc()
	return report, nil
}

func (r *auditRepository) ExportUserAuditTrail(ctx context.Context, userID uuid.UUID) ([]byte, error) {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Get all activities for the user in the last year
	activities, err := r.querier.ExportUserActivities(ctx, sqlc.ExportUserActivitiesParams{
		UserID:        uuidToPgtypeUUID(userID),
		PerformedAt:   timeToPgtypeTimestamp(time.Now().AddDate(-1, 0, 0)),
		PerformedAt_2: timeToPgtypeTimestamp(time.Now()),
	})
	if err != nil {
		auditDBQueryTotal.WithLabelValues("export_user_audit_trail", "error").Inc()
		return nil, r.handleError(err, "export user audit trail")
	}

	// Get all data access logs for the user in the last year
	accessLogs, err := r.querier.ExportDataAccessLogs(ctx, sqlc.ExportDataAccessLogsParams{
		AccessedUserID: uuidToPgtypeUUID(userID),
		AccessedAt:     timeToPgtypeTimestamp(time.Now().AddDate(-1, 0, 0)),
		AccessedAt_2:   timeToPgtypeTimestamp(time.Now()),
	})
	if err != nil {
		auditDBQueryTotal.WithLabelValues("export_user_audit_trail", "error").Inc()
		return nil, r.handleError(err, "export user audit trail")
	}

	// Create audit trail structure
	auditTrail := struct {
		UserID      uuid.UUID              `json:"user_id"`
		GeneratedAt time.Time              `json:"generated_at"`
		Activities  []core.UserActivity    `json:"activities"`
		AccessLogs  []core.DataAccessLog   `json:"access_logs"`
		Summary     map[string]interface{} `json:"summary"`
	}{
		UserID:      userID,
		GeneratedAt: time.Now(),
		Activities:  make([]core.UserActivity, len(activities)),
		AccessLogs:  make([]core.DataAccessLog, len(accessLogs)),
		Summary: map[string]interface{}{
			"total_activities":  len(activities),
			"total_access_logs": len(accessLogs),
			"time_period":       "1 year",
			"report_generated":  time.Now().Format(time.RFC3339),
		},
	}

	// Map activities
	for i, a := range activities {
		auditTrail.Activities[i] = r.mapUserActivityFromRow(a)
	}

	// Map access logs
	for i, l := range accessLogs {
		auditTrail.AccessLogs[i] = r.mapDataAccessLogFromRow(l)
	}

	// Convert to JSON
	jsonData, err := json.MarshalIndent(auditTrail, "", "  ")
	if err != nil {
		auditDBQueryTotal.WithLabelValues("export_user_audit_trail", "error").Inc()
		return nil, fmt.Errorf("marshal audit trail: %w", err)
	}

	auditDBQueryTotal.WithLabelValues("export_user_audit_trail", "success").Inc()
	return jsonData, nil
}

// handleError converts database errors to domain errors
func (r *auditRepository) handleError(err error, operation string) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			return fmt.Errorf("duplicate audit record: %w", err)
		case "23503": // foreign_key_violation
			return fmt.Errorf("foreign key violation: %w", err)
		case "23514": // check_violation
			return fmt.Errorf("check constraint violation: %w", err)
		}
	}
	return fmt.Errorf("%s failed: %w", operation, err)
}

// Helper mapping functions

func (r *auditRepository) mapUserActivityFromRow(a sqlc.UserActivity) core.UserActivity {
	activity := core.UserActivity{
		ID:           pgtypeUUIDToUUID(a.ID),
		ActivityType: a.ActivityType,
		PerformedAt:  a.PerformedAt.Time,
	}

	if a.UserID.Valid {
		uid := pgtypeUUIDToUUID(a.UserID)
		activity.UserID = &uid
	}

	if len(a.ActivityDetails) > 0 {
		var details map[string]interface{}
		if err := json.Unmarshal(a.ActivityDetails, &details); err == nil {
			activity.ActivityDetails = details
		}
	}

	if a.IpAddress != nil {
		ipStr := a.IpAddress.String()
		activity.IPAddress = &ipStr
	}

	if a.UserAgent.Valid {
		activity.UserAgent = &a.UserAgent.String
	}

	if a.DeviceType.Valid {
		activity.DeviceType = &a.DeviceType.String
	}

	if a.DeviceID.Valid {
		activity.DeviceID = &a.DeviceID.String
	}

	if len(a.Location) > 0 {
		var loc map[string]interface{}
		if err := json.Unmarshal(a.Location, &loc); err == nil {
			activity.Location = loc
		}
	}

	if a.ResourceType.Valid {
		activity.ResourceType = &a.ResourceType.String
	}

	if a.ResourceID.Valid {
		rid := pgtypeUUIDToUUID(a.ResourceID)
		activity.ResourceID = &rid
	}

	return activity
}

func (r *auditRepository) mapDataAccessLogFromRow(l sqlc.DataAccessLog) core.DataAccessLog {
	log := core.DataAccessLog{
		ID:         pgtypeUUIDToUUID(l.ID),
		AccessType: pgtypeTextToString(l.AccessType),
		AccessedAt: l.AccessedAt.Time,
	}

	if l.AccessedByUserID.Valid {
		uid := pgtypeUUIDToUUID(l.AccessedByUserID)
		log.AccessedByUserID = &uid
	}

	if l.AccessedByRole.Valid {
		log.AccessedByRole = &l.AccessedByRole.String
	}

	if l.AccessedUserID.Valid {
		log.AccessedUserID = pgtypeUUIDToUUID(l.AccessedUserID)
	}

	if l.AccessedResourceType.Valid {
		log.AccessedResourceType = &l.AccessedResourceType.String
	}

	if l.AccessedResourceID.Valid {
		rid := pgtypeUUIDToUUID(l.AccessedResourceID)
		log.AccessedResourceID = &rid
	}

	if l.AccessReason.Valid {
		log.AccessReason = &l.AccessReason.String
	}

	if l.IsEmergencyAccess.Valid {
		log.IsEmergencyAccess = l.IsEmergencyAccess.Bool
	}

	if l.IpAddress != nil {
		ipStr := l.IpAddress.String()
		log.IPAddress = &ipStr
	}

	if l.UserAgent.Valid {
		log.UserAgent = &l.UserAgent.String
	}

	if len(l.Location) > 0 {
		var loc map[string]interface{}
		if err := json.Unmarshal(l.Location, &loc); err == nil {
			log.Location = loc
		}
	}

	return log
}
