package admin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/admin"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	systemAdminDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "system_admin_db_query_duration_seconds",
			Help:    "System admin database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	systemAdminDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "system_admin_db_query_total",
			Help: "Total number of system admin database queries",
		},
		[]string{"operation", "status"},
	)
)

type systemAdminRepository struct {
	querier sqlc.Querier
}

func NewSystemAdminRepository(pool *pgxpool.Pool) repository.SystemAdminRepository {
	return NewSystemAdminRepositoryWithQuerier(sqlc.New(pool))
}

func NewSystemAdminRepositoryWithQuerier(querier sqlc.Querier) repository.SystemAdminRepository {
	return &systemAdminRepository{
		querier: querier,
	}
}

// ===== Core CRUD Operations =====

func (r *systemAdminRepository) CreateSystemAdmin(ctx context.Context, sysAdmin admin.SystemAdmin) (admin.SystemAdmin, error) {
	start := time.Now()
	defer func() {
		systemAdminDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// After sqlc regeneration with json.RawMessage override:
	// The field will be named "Permissions" and expect json.RawMessage
	created, err := r.querier.CreateSystemAdmin(ctx, sqlc.CreateSystemAdminParams{
		UserID:           uuidToPgtypeUUID(sysAdmin.UserID),
		AdminLevel:       sysAdmin.AdminLevel,
		AssignedRegions:  sysAdmin.AssignedRegions,
		Department:       pgtypeTextFromStringPtr(sysAdmin.Department),
		Column5:          interfaceToJSONRawMessage(sysAdmin.Permissions), // Use json.RawMessage helper
		CanManageUsers:   pgtype.Bool{Bool: sysAdmin.CanManageUsers, Valid: true},
		CanManageClinics: pgtype.Bool{Bool: sysAdmin.CanManageClinics, Valid: true},
		CanManageContent: pgtype.Bool{Bool: sysAdmin.CanManageContent, Valid: true},
		CanViewAnalytics: pgtype.Bool{Bool: sysAdmin.CanViewAnalytics, Valid: true},
		CanManageSystem:  pgtype.Bool{Bool: sysAdmin.CanManageSystem, Valid: true},
		WorkPhone:        pgtypeTextFromStringPtr(sysAdmin.WorkPhone),
		Extension:        pgtypeTextFromStringPtr(sysAdmin.Extension),
	})
	if err != nil {
		systemAdminDBQueryTotal.WithLabelValues("create_system_admin", "error").Inc()
		return admin.SystemAdmin{}, r.handleError(err, "create system admin")
	}

	systemAdminDBQueryTotal.WithLabelValues("create_system_admin", "success").Inc()
	return r.mapToSystemAdmin(created), nil
}

func (r *systemAdminRepository) GetSystemAdminByUserID(ctx context.Context, userID uuid.UUID) (admin.SystemAdmin, error) {
	start := time.Now()
	defer func() {
		systemAdminDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	row, err := r.querier.GetSystemAdminByUserID(ctx, uuidToPgtypeUUID(userID))
	if err != nil {
		systemAdminDBQueryTotal.WithLabelValues("get_system_admin_by_user_id", "error").Inc()
		return admin.SystemAdmin{}, r.handleError(err, "get system admin by user id")
	}

	systemAdminDBQueryTotal.WithLabelValues("get_system_admin_by_user_id", "success").Inc()
	return r.mapToSystemAdmin(row), nil
}

// ===== Helper Functions =====

func (r *systemAdminRepository) mapToSystemAdmin(row sqlc.SystemAdmin) admin.SystemAdmin {
	return admin.SystemAdmin{
		ID:               pgtypeUUIDToUUID(row.ID),
		UserID:           pgtypeUUIDToUUID(row.UserID),
		AdminLevel:       row.AdminLevel,
		AssignedRegions:  row.AssignedRegions,
		Department:       pgtypeTextToStringPtr(row.Department),
		Permissions:      jsonRawMessageToInterface(row.Permissions), // Use json.RawMessage helper
		CanManageUsers:   pgtypeBoolToBool(row.CanManageUsers),
		CanManageClinics: pgtypeBoolToBool(row.CanManageClinics),
		CanManageContent: pgtypeBoolToBool(row.CanManageContent),
		CanViewAnalytics: pgtypeBoolToBool(row.CanViewAnalytics),
		CanManageSystem:  pgtypeBoolToBool(row.CanManageSystem),
		WorkPhone:        pgtypeTextToStringPtr(row.WorkPhone),
		Extension:        pgtypeTextToStringPtr(row.Extension),
		CreatedAt:        row.CreatedAt.Time,
		UpdatedAt:        row.UpdatedAt.Time,
	}
}

func (r *systemAdminRepository) handleError(err error, operation string) error {
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	return fmt.Errorf("%s: %w", operation, err)
}
