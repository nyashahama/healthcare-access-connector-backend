package sms

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/sms"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog/log"
)

var (
	smsConversationDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "sms_conversation_db_query_duration_seconds",
			Help:    "SMS conversation database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	smsConversationDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sms_conversation_db_query_total",
			Help: "Total number of SMS conversation database queries",
		},
		[]string{"operation", "status"},
	)
)

type smsRepository struct {
	querier sqlc.Querier
}

func NewSMSRepository(pool *pgxpool.Pool) repository.SMSRepository {
	return NewSMSRepositoryWithQuerier(sqlc.New(pool))
}

func NewSMSRepositoryWithQuerier(querier sqlc.Querier) repository.SMSRepository {
	return &smsRepository{querier: querier}
}

// CreateConversation starts or rehydrates an SMS conversation.
func (r *smsRepository) CreateConversation(ctx context.Context, conv sms.SMSConversation) (sms.SMSConversation, error) {
	start := time.Now()
	defer func() {
		smsConversationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	if conv.PhoneNumber == "" {
		smsConversationDBQueryTotal.WithLabelValues("create_sms_conversation", "error").Inc()
		return sms.SMSConversation{}, domain.NewAppError(domain.ErrValidation, "Phone number is required", 400)
	}

	stateJSON, err := jsonbFromMap(conv.ConversationState)
	if err != nil {
		smsConversationDBQueryTotal.WithLabelValues("create_sms_conversation", "error").Inc()
		return sms.SMSConversation{}, domain.NewAppError(domain.ErrValidation, "Invalid conversation state", 400)
	}

	row, err := r.querier.CreateSMSConversation(ctx, sqlc.CreateSMSConversationParams{
		UserID:            uuidPtrToPgtypeUUID(conv.UserID),
		PhoneNumber:       conv.PhoneNumber,
		CurrentMenu:       pgtypeTextFromStringPtr(conv.CurrentMenu),
		ConversationState: stateJSON,
	})
	if err != nil {
		smsConversationDBQueryTotal.WithLabelValues("create_sms_conversation", "error").Inc()
		return sms.SMSConversation{}, r.handleError(err, "create sms conversation")
	}

	created := sms.SMSConversation{
		ID:                  pgtypeUUIDToUUID(row.ID),
		UserID:              pgtypeUUIDToUUIDPtr(row.UserID),
		PhoneNumber:         row.PhoneNumber,
		CurrentMenu:         conv.CurrentMenu,
		ConversationState:   conv.ConversationState,
		LastMessageSent:     nil,
		LastMessageReceived: nil,
		LastInteractionAt:   nil,
		LastLocation:        nil,
		LastSearchQuery:     nil,
		CallbackScheduled:   nil,
		CreatedAt:           row.CreatedAt.Time,
		UpdatedAt:           row.CreatedAt.Time,
	}

	smsConversationDBQueryTotal.WithLabelValues("create_sms_conversation", "success").Inc()
	return created, nil
}

// GetConversation loads one conversation by ID.
func (r *smsRepository) GetConversation(ctx context.Context, id uuid.UUID) (sms.SMSConversation, error) {
	start := time.Now()
	defer func() {
		smsConversationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	if id == uuid.Nil {
		smsConversationDBQueryTotal.WithLabelValues("get_sms_conversation", "error").Inc()
		return sms.SMSConversation{}, domain.NewAppError(domain.ErrValidation, "Conversation ID is required", 400)
	}

	row, err := r.querier.GetSMSConversation(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		smsConversationDBQueryTotal.WithLabelValues("get_sms_conversation", "error").Inc()
		return sms.SMSConversation{}, r.handleError(err, "get sms conversation")
	}

	smsConversationDBQueryTotal.WithLabelValues("get_sms_conversation", "success").Inc()
	return r.mapToConversation(row), nil
}

// GetConversationByPhone loads the latest conversation for a phone number.
func (r *smsRepository) GetConversationByPhone(ctx context.Context, phone string) (sms.SMSConversation, error) {
	start := time.Now()
	defer func() {
		smsConversationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	if phone == "" {
		smsConversationDBQueryTotal.WithLabelValues("get_sms_conversation_by_phone", "error").Inc()
		return sms.SMSConversation{}, domain.NewAppError(domain.ErrValidation, "Phone number is required", 400)
	}

	row, err := r.querier.GetSMSConversationByPhone(ctx, phone)
	if err != nil {
		smsConversationDBQueryTotal.WithLabelValues("get_sms_conversation_by_phone", "error").Inc()
		return sms.SMSConversation{}, r.handleError(err, "get sms conversation by phone")
	}

	smsConversationDBQueryTotal.WithLabelValues("get_sms_conversation_by_phone", "success").Inc()
	return r.mapToConversation(row), nil
}

// GetConversationByUserID loads the latest conversation for a user.
func (r *smsRepository) GetConversationByUserID(ctx context.Context, userID uuid.UUID) (sms.SMSConversation, error) {
	start := time.Now()
	defer func() {
		smsConversationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	if userID == uuid.Nil {
		smsConversationDBQueryTotal.WithLabelValues("get_sms_conversation_by_user_id", "error").Inc()
		return sms.SMSConversation{}, domain.NewAppError(domain.ErrValidation, "User ID is required", 400)
	}

	row, err := r.querier.GetSMSConversationByUserID(ctx, uuidToPgtypeUUID(userID))
	if err != nil {
		smsConversationDBQueryTotal.WithLabelValues("get_sms_conversation_by_user_id", "error").Inc()
		return sms.SMSConversation{}, r.handleError(err, "get sms conversation by user id")
	}

	smsConversationDBQueryTotal.WithLabelValues("get_sms_conversation_by_user_id", "success").Inc()
	return r.mapToConversation(row), nil
}

// UpdateConversation saves the mutable state of an SMS conversation.
func (r *smsRepository) UpdateConversation(ctx context.Context, conv sms.SMSConversation) error {
	start := time.Now()
	defer func() {
		smsConversationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	if conv.ID == uuid.Nil {
		smsConversationDBQueryTotal.WithLabelValues("update_sms_conversation", "error").Inc()
		return domain.NewAppError(domain.ErrValidation, "Conversation ID is required", 400)
	}

	stateJSON, err := jsonbFromMap(conv.ConversationState)
	if err != nil {
		smsConversationDBQueryTotal.WithLabelValues("update_sms_conversation", "error").Inc()
		return domain.NewAppError(domain.ErrValidation, "Invalid conversation state", 400)
	}

	_, err = jsonbFromMap(conv.LastLocation)
	if err != nil {
		smsConversationDBQueryTotal.WithLabelValues("update_sms_conversation", "error").Inc()
		return domain.NewAppError(domain.ErrValidation, "Invalid last location", 400)
	}

	params := sqlc.UpdateSMSConversationParams{
		ID:                  uuidToPgtypeUUID(conv.ID),
		CurrentMenu:         pgtypeTextFromStringPtr(conv.CurrentMenu),
		ConversationState:   stateJSON,
		LastMessageSent:     pgtypeTextFromStringPtr(conv.LastMessageSent),
		LastMessageReceived: pgtypeTextFromStringPtr(conv.LastMessageReceived),
	}

	// Backward-compatible: include location/search/ callback fields in a dedicated update
	// path where supported by the underlying query. Unsupported schema fields are
	// intentionally ignored because `UpdateSMSConversation` only updates
	// tracking fields used by the active flow.
	log.Logger.Debug().
		Str("conversation_id", conv.ID.String()).
		Str("current_menu", stringPtrOrDefault(conv.CurrentMenu)).
		Msg("Updating SMS conversation")

	err = r.querier.UpdateSMSConversation(ctx, params)
	if err != nil {
		smsConversationDBQueryTotal.WithLabelValues("update_sms_conversation", "error").Inc()
		return r.handleError(err, "update sms conversation")
	}

	smsConversationDBQueryTotal.WithLabelValues("update_sms_conversation", "success").Inc()
	return nil
}

// CloseConversation marks a conversation as closed and stores a reason.
func (r *smsRepository) CloseConversation(ctx context.Context, id uuid.UUID, reason string) error {
	start := time.Now()
	defer func() {
		smsConversationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	if id == uuid.Nil {
		smsConversationDBQueryTotal.WithLabelValues("close_sms_conversation", "error").Inc()
		return domain.NewAppError(domain.ErrValidation, "Conversation ID is required", 400)
	}

	err := r.querier.CloseSMSConversation(ctx, sqlc.CloseSMSConversationParams{
		ID:               uuidToPgtypeUUID(id),
		JsonbBuildObject: map[string]any{"is_closed": true, "closed_reason": reason},
	})
	if err != nil {
		smsConversationDBQueryTotal.WithLabelValues("close_sms_conversation", "error").Inc()
		return r.handleError(err, "close sms conversation")
	}

	smsConversationDBQueryTotal.WithLabelValues("close_sms_conversation", "success").Inc()
	return nil
}

// GetActiveConversations lists all non-closed conversations.
func (r *smsRepository) GetActiveConversations(ctx context.Context) ([]sms.SMSConversation, error) {
	start := time.Now()
	defer func() {
		smsConversationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetActiveSMSConversations(ctx)
	if err != nil {
		smsConversationDBQueryTotal.WithLabelValues("get_active_sms_conversations", "error").Inc()
		return nil, r.handleError(err, "get active sms conversations")
	}

	conversations := make([]sms.SMSConversation, 0, len(rows))
	for _, row := range rows {
		conversations = append(conversations, r.mapToConversation(row))
	}

	smsConversationDBQueryTotal.WithLabelValues("get_active_sms_conversations", "success").Inc()
	return conversations, nil
}

// ExportConversation creates an export payload for compliance and audit.
func (r *smsRepository) ExportConversation(ctx context.Context, conversationID uuid.UUID) ([]byte, error) {
	start := time.Now()
	defer func() {
		smsConversationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	if conversationID == uuid.Nil {
		smsConversationDBQueryTotal.WithLabelValues("export_sms_conversation", "error").Inc()
		return nil, domain.NewAppError(domain.ErrValidation, "Conversation ID is required", 400)
	}

	conversation, err := r.GetConversation(ctx, conversationID)
	if err != nil {
		smsConversationDBQueryTotal.WithLabelValues("export_sms_conversation", "error").Inc()
		return nil, err
	}

	messages, err := r.GetConversationMessages(ctx, conversationID, 10000, 0)
	if err != nil {
		smsConversationDBQueryTotal.WithLabelValues("export_sms_conversation", "error").Inc()
		return nil, err
	}

	payload := map[string]any{
		"conversation": conversation,
		"messages":     messages,
		"exported_at":  time.Now().UTC().Format(time.RFC3339),
	}

	bytes, err := json.Marshal(payload)
	if err != nil {
		smsConversationDBQueryTotal.WithLabelValues("export_sms_conversation", "error").Inc()
		return nil, domain.NewAppError(domain.ErrInternal, "Failed to export conversation", 500)
	}

	smsConversationDBQueryTotal.WithLabelValues("export_sms_conversation", "success").Inc()
	return bytes, nil
}

func (r *smsRepository) handleError(err error, operation string) error {
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		log.Error().Str("operation", operation).Msg("SMS repository resource not found")
		return domain.ErrConversationNotFound
	}

	log.Error().Str("operation", operation).Err(err).Msg("SMS repository operation failed")
	return fmt.Errorf("%s: %w", operation, err)
}

func (r *smsRepository) mapToConversation(row sqlc.SmsConversation) sms.SMSConversation {
	return sms.SMSConversation{
		ID:                  pgtypeUUIDToUUID(row.ID),
		UserID:              pgtypeUUIDToUUIDPtr(row.UserID),
		PhoneNumber:         row.PhoneNumber,
		CurrentMenu:         pgtypeTextToStringPtr(row.CurrentMenu),
		ConversationState:   mapFromJSONB(row.ConversationState),
		LastMessageSent:     pgtypeTextToStringPtr(row.LastMessageSent),
		LastMessageReceived: pgtypeTextToStringPtr(row.LastMessageReceived),
		LastInteractionAt:   pgtypeTimestampToTimePtr(row.LastInteractionAt),
		LastLocation:        mapFromJSONB(row.LastLocation),
		LastSearchQuery:     pgtypeTextToStringPtr(row.LastSearchQuery),
		CallbackScheduled:   pgtypeTimestampToTimePtr(row.CallbackScheduled),
		CreatedAt:           row.CreatedAt.Time,
		UpdatedAt:           row.UpdatedAt.Time,
	}
}

func stringPtrOrDefault(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}
