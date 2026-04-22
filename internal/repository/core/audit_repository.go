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
		UserID:       uuidPtrToPgtypeUUID(activity.UserID),
		ActivityType: activity.ActivityType,
		Column3:      activityDetails,
		IpAddress:    ipAddr,
		UserAgent:    pgtypeTextFromStringPtr(activity.UserAgent),
		DeviceType:   pgtypeTextFromStringPtr(activity.DeviceType),
		DeviceID:     pgtypeTextFromStringPtr(activity.DeviceID),
		Column8:      location,
		ResourceType: pgtypeTextFromStringPtr(activity.ResourceType),
		ResourceID:   uuidPtrToPgtypeUUID(activity.ResourceID),
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
