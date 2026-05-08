package sms

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/sms"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	smsMessageDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "sms_message_db_query_duration_seconds",
			Help:    "SMS message database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	smsMessageDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sms_message_db_query_total",
			Help: "Total number of SMS message database queries",
		},
		[]string{"operation", "status"},
	)
)

// NewSMSRepository and NewSMSRepositoryWithQuerier are defined in conversation_repository.go.

// LogMessage writes a message record for a conversation.
func (r *smsRepository) LogMessage(ctx context.Context, msg sms.SMSMessage) (sms.SMSMessage, error) {
	start := time.Now()
	defer func() {
		smsMessageDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	if msg.ConversationID == uuid.Nil {
		smsMessageDBQueryTotal.WithLabelValues("log_sms_message", "error").Inc()
		return sms.SMSMessage{}, domain.NewAppError(domain.ErrValidation, "Conversation ID is required", 400)
	}

	if msg.Direction == "" {
		smsMessageDBQueryTotal.WithLabelValues("log_sms_message", "error").Inc()
		return sms.SMSMessage{}, domain.NewAppError(domain.ErrValidation, "Direction is required", 400)
	}

	if msg.MessageBody == "" {
		smsMessageDBQueryTotal.WithLabelValues("log_sms_message", "error").Inc()
		return sms.SMSMessage{}, domain.NewAppError(domain.ErrValidation, "Message body is required", 400)
	}

	segments := msg.Segments
	if segments <= 0 {
		segments = 1
	}

	row, err := r.querier.LogSMSMessage(ctx, sqlc.LogSMSMessageParams{
		ConversationID:  uuidToPgtypeUUID(msg.ConversationID),
		Direction:       msg.Direction,
		MessageBody:     msg.MessageBody,
		TwilioMessageID: pgtypeTextFromStringPtr(msg.TwilioMessageID),
		TwilioStatus:    pgtypeTextFromStringPtr(msg.TwilioStatus),
		Segments:        intToPgtypeInt4(segments),
		Cost:            float64PtrToPgtypeNumeric(msg.Cost),
		CostCurrency:    pgtypeTextFromString(msg.CostCurrency),
	})
	if err != nil {
		smsMessageDBQueryTotal.WithLabelValues("log_sms_message", "error").Inc()
		return sms.SMSMessage{}, r.handleMessageError(err, "log sms message")
	}

	smsMessageDBQueryTotal.WithLabelValues("log_sms_message", "success").Inc()
	return r.mapToSMSMessageFromLogRow(row), nil
}

// GetMessage fetches a single message by its ID.
func (r *smsRepository) GetMessage(ctx context.Context, id uuid.UUID) (sms.SMSMessage, error) {
	start := time.Now()
	defer func() {
		smsMessageDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	if id == uuid.Nil {
		smsMessageDBQueryTotal.WithLabelValues("get_sms_message", "error").Inc()
		return sms.SMSMessage{}, domain.NewAppError(domain.ErrValidation, "Message ID is required", 400)
	}

	row, err := r.querier.GetMessage(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		smsMessageDBQueryTotal.WithLabelValues("get_sms_message", "error").Inc()
		return sms.SMSMessage{}, r.handleMessageError(err, "get sms message")
	}

	smsMessageDBQueryTotal.WithLabelValues("get_sms_message", "success").Inc()
	return r.mapToSMSMessage(row), nil
}

// GetConversationMessages fetches a paginated list of messages for a conversation.
func (r *smsRepository) GetConversationMessages(ctx context.Context, conversationID uuid.UUID, limit, offset int) ([]sms.SMSMessage, error) {
	start := time.Now()
	defer func() {
		smsMessageDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	if conversationID == uuid.Nil {
		smsMessageDBQueryTotal.WithLabelValues("get_conversation_messages", "error").Inc()
		return nil, domain.NewAppError(domain.ErrValidation, "Conversation ID is required", 400)
	}

	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}

	rows, err := r.querier.GetConversationMessages(ctx, sqlc.GetConversationMessagesParams{
		ConversationID: uuidToPgtypeUUID(conversationID),
		Limit:          int32(limit),
		Offset:         int32(offset),
	})
	if err != nil {
		smsMessageDBQueryTotal.WithLabelValues("get_conversation_messages", "error").Inc()
		return nil, r.handleMessageError(err, "get conversation messages")
	}

	messages := make([]sms.SMSMessage, 0, len(rows))
	for _, row := range rows {
		messages = append(messages, r.mapToSMSMessageFromConversationRow(row))
	}

	smsMessageDBQueryTotal.WithLabelValues("get_conversation_messages", "success").Inc()
	return messages, nil
}

// GetFailedMessages fetches messages that failed delivery in a given time window.
func (r *smsRepository) GetFailedMessages(ctx context.Context, startDate, endDate time.Time) ([]sms.SMSMessage, error) {
	start := time.Now()
	defer func() {
		smsMessageDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	if startDate.IsZero() {
		smsMessageDBQueryTotal.WithLabelValues("get_failed_messages", "error").Inc()
		return nil, domain.NewAppError(domain.ErrValidation, "start_date is required", 400)
	}
	if endDate.IsZero() {
		endDate = time.Now().UTC()
	}
	if endDate.Before(startDate) {
		smsMessageDBQueryTotal.WithLabelValues("get_failed_messages", "error").Inc()
		return nil, domain.NewAppError(domain.ErrValidation, "end_date must be after start_date", 400)
	}

	rows, err := r.querier.GetFailedMessages(ctx, sqlc.GetFailedMessagesParams{
		CreatedAt:   pgtype.Timestamp{Time: startDate, Valid: true},
		CreatedAt_2: pgtype.Timestamp{Time: endDate, Valid: true},
	})
	if err != nil {
		smsMessageDBQueryTotal.WithLabelValues("get_failed_messages", "error").Inc()
		return nil, r.handleMessageError(err, "get failed messages")
	}

	messages := make([]sms.SMSMessage, 0, len(rows))
	for _, row := range rows {
		messages = append(messages, r.mapToSMSMessage(row))
	}

	smsMessageDBQueryTotal.WithLabelValues("get_failed_messages", "success").Inc()
	return messages, nil
}

// ArchiveOldMessages removes old SMS message records before retention cutoff.
func (r *smsRepository) ArchiveOldMessages(ctx context.Context, olderThan time.Duration) error {
	start := time.Now()
	defer func() {
		smsMessageDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	if olderThan <= 0 {
		smsMessageDBQueryTotal.WithLabelValues("archive_old_messages", "error").Inc()
		return domain.NewAppError(domain.ErrValidation, "older_than must be greater than zero", 400)
	}

	secs := int64(olderThan.Seconds())
	if secs < 1 {
		secs = 1
	}

	err := r.querier.ArchiveOldSMSMessages(ctx, float64(secs))
	if err != nil {
		smsMessageDBQueryTotal.WithLabelValues("archive_old_messages", "error").Inc()
		return r.handleMessageError(err, "archive old messages")
	}

	smsMessageDBQueryTotal.WithLabelValues("archive_old_messages", "success").Inc()
	return nil
}

// ---- Mapping helpers -------------------------------------------------------

func (r *smsRepository) mapToSMSMessage(row sqlc.SmsMessage) sms.SMSMessage {
	return sms.SMSMessage{
		ID:              pgtypeUUIDToUUID(row.ID),
		ConversationID:  pgtypeUUIDToUUID(row.ConversationID),
		Direction:       row.Direction,
		MessageBody:     row.MessageBody,
		TwilioMessageID: pgtypeTextToStringPtr(row.TwilioMessageID),
		TwilioStatus:    pgtypeTextToStringPtr(row.TwilioStatus),
		SentAt:          pgtypeTimestampToTimePtr(row.SentAt),
		DeliveredAt:     pgtypeTimestampToTimePtr(row.DeliveredAt),
		Segments:        intFromPgtypeInt4(row.Segments),
		Cost:            pgtypeNumericToFloat64Ptr(row.Cost),
		CostCurrency:    pgtypeTextToString(row.CostCurrency),
		CreatedAt:       row.CreatedAt.Time,
	}
}

func (r *smsRepository) mapToSMSMessageFromConversationRow(row sqlc.SmsMessage) sms.SMSMessage {
	msg := sms.SMSMessage{
		ID:              pgtypeUUIDToUUID(row.ID),
		ConversationID:  pgtypeUUIDToUUID(row.ConversationID),
		Direction:       row.Direction,
		MessageBody:     row.MessageBody,
		TwilioMessageID: pgtypeTextToStringPtr(row.TwilioMessageID),
		TwilioStatus:    pgtypeTextToStringPtr(row.TwilioStatus),
		SentAt:          pgtypeTimestampToTimePtr(row.SentAt),
		DeliveredAt:     pgtypeTimestampToTimePtr(row.DeliveredAt),
		Segments:        intFromPgtypeInt4(row.Segments),
		Cost:            pgtypeNumericToFloat64Ptr(row.Cost),
		CostCurrency:    pgtypeTextToString(row.CostCurrency),
		CreatedAt:       row.CreatedAt.Time,
	}

	if msg.CostCurrency == "" && !row.CostCurrency.Valid {
		msg.CostCurrency = ""
	}
	return msg
}

func (r *smsRepository) mapToSMSMessageFromLogRow(row sqlc.SmsMessage) sms.SMSMessage {
	msg := sms.SMSMessage{
		ID:              pgtypeUUIDToUUID(row.ID),
		ConversationID:  pgtypeUUIDToUUID(row.ConversationID),
		Direction:       row.Direction,
		MessageBody:     row.MessageBody,
		TwilioMessageID: pgtypeTextToStringPtr(row.TwilioMessageID),
		TwilioStatus:    pgtypeTextToStringPtr(row.TwilioStatus),
		SentAt:          pgtypeTimestampToTimePtr(row.SentAt),
		DeliveredAt:     pgtypeTimestampToTimePtr(row.DeliveredAt),
		Segments:        intFromPgtypeInt4(row.Segments),
		Cost:            pgtypeNumericToFloat64Ptr(row.Cost),
		CreatedAt:       row.CreatedAt.Time,
	}
	if row.CostCurrency.Valid {
		msg.CostCurrency = row.CostCurrency.String
	}
	return msg
}

func (r *smsRepository) handleMessageError(err error, operation string) error {
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func intFromPgtypeInt4(v pgtype.Int4) int {
	if !v.Valid {
		return 0
	}
	return int(v.Int32)
}
