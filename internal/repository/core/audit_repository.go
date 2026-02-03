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

func NewAuditRepository(pool *pgxpool.Pool) repository.AuditRepository {
	return NewAuditRepositoryWithQuerier(sqlc.New(pool))
}

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

	activityDetails, err := json.Marshal(activity.ActivityDetails)
	if err != nil {
		auditDBQueryTotal.WithLabelValues("log_user_activity", "error").Inc()
		return fmt.Errorf("marshal activity details: %w", err)
	}
	location, err := json.Marshal(activity.Location)
	if err != nil {
		auditDBQueryTotal.WithLabelValues("log_user_activity", "error").Inc()
		return fmt.Errorf("marshal location: %w", err)
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
		result[i] = r.mapToUserActivity(a)
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
		result[i] = r.mapToUserActivity(a)
	}
	return result, nil
}

func (r *auditRepository) GetActivitiesByResource(ctx context.Context, resourceType string, resourceID uuid.UUID) ([]core.UserActivity, error) {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	activities, err := r.querier.GetActivitiesByResource(ctx, sqlc.GetActivitiesByResourceParams{
		ResourceType: pgtype.Text{String: resourceType, Valid: true},
		ResourceID:   uuidToPgtypeUUID(resourceID),
	})
	if err != nil {
		auditDBQueryTotal.WithLabelValues("get_activities_by_resource", "error").Inc()
		return nil, r.handleError(err, "get activities by resource")
	}

	auditDBQueryTotal.WithLabelValues("get_activities_by_resource", "success").Inc()

	result := make([]core.UserActivity, len(activities))
	for i, a := range activities {
		result[i] = r.mapToUserActivity(a)
	}
	return result, nil
}

func (r *auditRepository) LogDataAccess(ctx context.Context, access core.DataAccessLog) error {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	location, err := json.Marshal(access.Location)
	if err != nil {
		auditDBQueryTotal.WithLabelValues("log_data_access", "error").Inc()
		return fmt.Errorf("marshal location: %w", err)
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
		IsEmergencyAccess:    boolToPgtypeBool(access.IsEmergencyAccess),
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
		result[i] = r.mapToDataAccessLog(l)
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
		result[i] = r.mapToDataAccessLog(l)
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
		result[i] = r.mapToDataAccessLog(l)
	}
	return result, nil
}

func (r *auditRepository) GetAccessLogsByResourceType(ctx context.Context, resourceType string, startDate, endDate time.Time) ([]core.DataAccessLog, error) {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.SearchDataAccessLogsParams{
		Column4: resourceType,
		Column6: timeToPgtypeTimestamp(startDate),
		Column7: timeToPgtypeTimestamp(endDate),
		Limit:   10000, // high limit to get all
		Offset:  0,
	}
	logs, err := r.querier.SearchDataAccessLogs(ctx, params)
	if err != nil {
		auditDBQueryTotal.WithLabelValues("get_access_logs_by_resource_type", "error").Inc()
		return nil, r.handleError(err, "get access logs by resource type")
	}

	auditDBQueryTotal.WithLabelValues("get_access_logs_by_resource_type", "success").Inc()

	result := make([]core.DataAccessLog, len(logs))
	for i, l := range logs {
		result[i] = r.mapToDataAccessLog(l)
	}
	return result, nil
}

func (r *auditRepository) GetSuspiciousActivities(ctx context.Context, threshold int) ([]core.UserActivity, error) {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Assuming suspicious is a type, or use recent
	activities, err := r.querier.GetRecentActivities(ctx, sqlc.GetRecentActivitiesParams{
		PerformedAt: timeToPgtypeTimestamp(time.Now().Add(-24 * time.Hour)),
		Limit:       int32(threshold),
		Offset:      0,
	})
	if err != nil {
		auditDBQueryTotal.WithLabelValues("get_suspicious_activities", "error").Inc()
		return nil, r.handleError(err, "get suspicious activities")
	}

	auditDBQueryTotal.WithLabelValues("get_suspicious_activities", "success").Inc()

	result := make([]core.UserActivity, len(activities))
	for i, a := range activities {
		result[i] = r.mapToUserActivity(a)
	}
	return result, nil
}

func (r *auditRepository) GetFailedLoginAttempts(ctx context.Context, userID *uuid.UUID, within time.Duration) ([]core.UserActivity, error) {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	fromDate := time.Now().Add(-within)
	var pgUserID pgtype.UUID
	if userID != nil {
		pgUserID = uuidToPgtypeUUID(*userID)
	}

	params := sqlc.SearchUserActivitiesParams{
		Column1: pgUserID,
		Column2: "login_failure", // assume type
		Column4: timeToPgtypeTimestamp(fromDate),
		Column5: timeToPgtypeTimestamp(time.Now()),
		Limit:   1000,
		Offset:  0,
	}
	activities, err := r.querier.SearchUserActivities(ctx, params)
	if err != nil {
		auditDBQueryTotal.WithLabelValues("get_failed_login_attempts", "error").Inc()
		return nil, r.handleError(err, "get failed login attempts")
	}

	auditDBQueryTotal.WithLabelValues("get_failed_login_attempts", "success").Inc()

	result := make([]core.UserActivity, len(activities))
	for i, a := range activities {
		result[i] = r.mapToUserActivity(a)
	}
	return result, nil
}

func (r *auditRepository) GetUnauthorizedAccessAttempts(ctx context.Context, within time.Duration) ([]core.DataAccessLog, error) {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	fromDate := time.Now().Add(-within)

	params := sqlc.SearchDataAccessLogsParams{
		Column3: "unauthorized", // assume access_type
		Column6: timeToPgtypeTimestamp(fromDate),
		Column7: timeToPgtypeTimestamp(time.Now()),
		Limit:   1000,
		Offset:  0,
	}
	logs, err := r.querier.SearchDataAccessLogs(ctx, params)
	if err != nil {
		auditDBQueryTotal.WithLabelValues("get_unauthorized_access_attempts", "error").Inc()
		return nil, r.handleError(err, "get unauthorized access attempts")
	}

	auditDBQueryTotal.WithLabelValues("get_unauthorized_access_attempts", "success").Inc()

	result := make([]core.DataAccessLog, len(logs))
	for i, l := range logs {
		result[i] = r.mapToDataAccessLog(l)
	}
	return result, nil
}

func (r *auditRepository) ArchiveOldLogs(ctx context.Context, olderThan time.Duration) error {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	before := time.Now().Add(-olderThan)
	err := r.querier.DeleteOldDataAccessLogs(ctx, timeToPgtypeTimestamp(before))
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

	before := time.Now().Add(-olderThan)
	err := r.querier.DeleteOldDataAccessLogs(ctx, timeToPgtypeTimestamp(before))
	if err != nil {
		auditDBQueryTotal.WithLabelValues("delete_archived_logs", "error").Inc()
		return r.handleError(err, "delete archived logs")
	}

	auditDBQueryTotal.WithLabelValues("delete_archived_logs", "success").Inc()
	return nil
}

func (r *auditRepository) ArchiveOldActivities(ctx context.Context, olderThan time.Duration) error {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	before := time.Now().Add(-olderThan)
	err := r.querier.DeleteOldUserActivities(ctx, timeToPgtypeTimestamp(before))
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

	auditDBQueryTotal.WithLabelValues("generate_access_report", "success").Inc()

	result := make([]core.DataAccessLog, len(logs))
	for i, l := range logs {
		result[i] = r.mapToDataAccessLog(l)
	}
	return result, nil
}

func (r *auditRepository) GenerateActivityReport(ctx context.Context, startDate, endDate time.Time) (interface{}, error) {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.SearchUserActivitiesParams{
		Column4: timeToPgtypeTimestamp(startDate),
		Column5: timeToPgtypeTimestamp(endDate),
		Limit:   10000,
		Offset:  0,
	}
	activities, err := r.querier.SearchUserActivities(ctx, params)
	if err != nil {
		auditDBQueryTotal.WithLabelValues("generate_activity_report", "error").Inc()
		return nil, r.handleError(err, "generate activity report")
	}

	auditDBQueryTotal.WithLabelValues("generate_activity_report", "success").Inc()

	result := make([]core.UserActivity, len(activities))
	for i, a := range activities {
		result[i] = r.mapToUserActivity(a)
	}
	return result, nil
}

func (r *auditRepository) ExportUserAuditTrail(ctx context.Context, userID uuid.UUID) ([]byte, error) {
	start := time.Now()
	defer func() {
		auditDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	fromDate := time.Time{} // beginning
	toDate := time.Now()

	activities, err := r.querier.ExportUserActivities(ctx, sqlc.ExportUserActivitiesParams{
		UserID:        uuidToPgtypeUUID(userID),
		PerformedAt:   timeToPgtypeTimestamp(fromDate),
		PerformedAt_2: timeToPgtypeTimestamp(toDate),
	})
	if err != nil {
		auditDBQueryTotal.WithLabelValues("export_user_audit_trail", "error").Inc()
		return nil, r.handleError(err, "export user activities for audit trail")
	}

	logs, err := r.querier.ExportDataAccessLogs(ctx, sqlc.ExportDataAccessLogsParams{
		AccessedUserID: uuidToPgtypeUUID(userID),
		AccessedAt:     timeToPgtypeTimestamp(fromDate),
		AccessedAt_2:   timeToPgtypeTimestamp(toDate),
	})
	if err != nil {
		auditDBQueryTotal.WithLabelValues("export_user_audit_trail", "error").Inc()
		return nil, r.handleError(err, "export data access logs for audit trail")
	}

	auditTrail := struct {
		UserActivities []core.UserActivity  `json:"user_activities"`
		DataAccessLogs []core.DataAccessLog `json:"data_access_logs"`
	}{
		UserActivities: make([]core.UserActivity, len(activities)),
		DataAccessLogs: make([]core.DataAccessLog, len(logs)),
	}

	for i, a := range activities {
		auditTrail.UserActivities[i] = r.mapToUserActivity(a)
	}

	for i, l := range logs {
		auditTrail.DataAccessLogs[i] = r.mapToDataAccessLog(l)
	}

	jsonData, err := json.Marshal(auditTrail)
	if err != nil {
		auditDBQueryTotal.WithLabelValues("export_user_audit_trail", "error").Inc()
		return nil, fmt.Errorf("marshal audit trail: %w", err)
	}

	auditDBQueryTotal.WithLabelValues("export_user_audit_trail", "success").Inc()
	return jsonData, nil
}

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

func (r *auditRepository) mapToUserActivity(a sqlc.UserActivity) core.UserActivity {
	var details map[string]interface{}
	if len(a.ActivityDetails) > 0 {
		_ = json.Unmarshal(a.ActivityDetails, &details)
	}

	var loc map[string]interface{}
	if len(a.Location) > 0 {
		_ = json.Unmarshal(a.Location, &loc)
	}

	var ipStr *string
	if a.IpAddress != nil {
		s := a.IpAddress.String()
		ipStr = &s
	}

	var uid *uuid.UUID
	if a.UserID.Valid {
		u := pgtypeUUIDToUUID(a.UserID)
		uid = &u
	}

	var rid *uuid.UUID
	if a.ResourceID.Valid {
		ru := pgtypeUUIDToUUID(a.ResourceID)
		rid = &ru
	}

	return core.UserActivity{
		ID:              pgtypeUUIDToUUID(a.ID),
		UserID:          uid,
		ActivityType:    a.ActivityType,
		ActivityDetails: details,
		IPAddress:       ipStr,
		UserAgent:       pgtypeTextToStringPtr(a.UserAgent),
		DeviceType:      pgtypeTextToStringPtr(a.DeviceType),
		DeviceID:        pgtypeTextToStringPtr(a.DeviceID),
		Location:        loc,
		ResourceType:    pgtypeTextToStringPtr(a.ResourceType),
		ResourceID:      rid,
		PerformedAt:     a.PerformedAt.Time,
	}
}

func (r *auditRepository) mapToDataAccessLog(l sqlc.DataAccessLog) core.DataAccessLog {
	var loc map[string]interface{}
	if len(l.Location) > 0 {
		_ = json.Unmarshal(l.Location, &loc)
	}

	var ipStr *string
	if l.IpAddress != nil {
		s := l.IpAddress.String()
		ipStr = &s
	}

	var abuid *uuid.UUID
	if l.AccessedByUserID.Valid {
		u := pgtypeUUIDToUUID(l.AccessedByUserID)
		abuid = &u
	}

	var arid *uuid.UUID
	if l.AccessedResourceID.Valid {
		ru := pgtypeUUIDToUUID(l.AccessedResourceID)
		arid = &ru
	}

	return core.DataAccessLog{
		ID:                   pgtypeUUIDToUUID(l.ID),
		AccessedByUserID:     abuid,
		AccessedByRole:       pgtypeTextToStringPtr(l.AccessedByRole),
		AccessedUserID:       pgtypeUUIDToUUID(l.AccessedUserID),
		AccessedResourceType: pgtypeTextToStringPtr(l.AccessedResourceType),
		AccessedResourceID:   arid,
		AccessType:           pgtypeTextToString(l.AccessType),
		AccessReason:         pgtypeTextToStringPtr(l.AccessReason),
		IsEmergencyAccess:    pgtypeBoolToBool(l.IsEmergencyAccess),
		IPAddress:            ipStr,
		UserAgent:            pgtypeTextToStringPtr(l.UserAgent),
		Location:             loc,
		AccessedAt:           l.AccessedAt.Time,
	}
}
