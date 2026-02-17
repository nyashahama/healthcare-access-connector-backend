package telemedicine

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/telemedicine"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	messagesDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "consultation_messages_db_query_duration_seconds",
			Help:    "Consultation messages database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	messagesDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "consultation_messages_db_query_total",
			Help: "Total number of consultation messages database queries",
		},
		[]string{"operation", "status"},
	)
)

type consultationMessagesRepository struct {
	querier sqlc.Querier
}

func NewConsultationMessagesRepository(pool *pgxpool.Pool) repository.ConsultationMessagesRepository {
	return NewConsultationMessagesRepositoryWithQuerier(sqlc.New(pool))
}

func NewConsultationMessagesRepositoryWithQuerier(querier sqlc.Querier) repository.ConsultationMessagesRepository {
	return &consultationMessagesRepository{querier: querier}
}

// ─── Core Write Operations ────────────────────────────────────────────────────

// InsertMessage persists a new message to a consultation thread.
func (r *consultationMessagesRepository) InsertMessage(ctx context.Context, msg telemedicine.ConsultationMessage) (telemedicine.ConsultationMessage, error) {
	start := time.Now()
	defer func() { messagesDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	row, err := r.querier.InsertMessage(ctx, sqlc.InsertMessageParams{
		ConsultationID:     uuidToPgtypeUUID(msg.ConsultationID),
		SenderUserID:       uuidToPgtypeUUID(msg.SenderUserID),
		SenderRole:         string(msg.SenderRole),
		MessageType:        string(msg.MessageType),
		Content:            pgtypeTextFromStringPtr(msg.Content),
		AttachmentUrl:      pgtypeTextFromStringPtr(msg.AttachmentURL),
		AttachmentType:     pgtypeTextFromStringPtr(attachmentTypeToStringPtr(msg.AttachmentType)),
		AttachmentFilename: pgtypeTextFromStringPtr(msg.AttachmentFilename),
		Column9:            interfaceToJSONRawMessage(msg.Metadata),
	})
	if err != nil {
		messagesDBQueryTotal.WithLabelValues("insert_message", "error").Inc()
		return telemedicine.ConsultationMessage{}, r.handleError(err, "insert message")
	}
	messagesDBQueryTotal.WithLabelValues("insert_message", "success").Inc()
	return r.mapToMessage(row), nil
}

// SoftDeleteMessage hides content from both parties while preserving the audit record.
func (r *consultationMessagesRepository) SoftDeleteMessage(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() { messagesDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	err := r.querier.SoftDeleteMessage(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		messagesDBQueryTotal.WithLabelValues("soft_delete_message", "error").Inc()
		return r.handleError(err, "soft delete message")
	}
	messagesDBQueryTotal.WithLabelValues("soft_delete_message", "success").Inc()
	return nil
}

// ─── Read Operations ──────────────────────────────────────────────────────────

// GetMessageByID fetches a single non-deleted message by primary key.
func (r *consultationMessagesRepository) GetMessageByID(ctx context.Context, id uuid.UUID) (telemedicine.ConsultationMessage, error) {
	start := time.Now()
	defer func() { messagesDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	row, err := r.querier.GetMessageByID(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		messagesDBQueryTotal.WithLabelValues("get_message_by_id", "error").Inc()
		return telemedicine.ConsultationMessage{}, r.handleError(err, "get message by id")
	}
	messagesDBQueryTotal.WithLabelValues("get_message_by_id", "success").Inc()
	return r.mapToMessage(row), nil
}

// GetConsultationMessages returns the full paginated message thread for a consultation.
// Used on initial chat load.
func (r *consultationMessagesRepository) GetConsultationMessages(ctx context.Context, consultationID uuid.UUID, limit, offset int) ([]telemedicine.ConsultationMessage, error) {
	start := time.Now()
	defer func() { messagesDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	rows, err := r.querier.GetConsultationMessages(ctx, sqlc.GetConsultationMessagesParams{
		ConsultationID: uuidToPgtypeUUID(consultationID),
		Limit:          int32(limit),
		Offset:         int32(offset),
	})
	if err != nil {
		messagesDBQueryTotal.WithLabelValues("get_consultation_messages", "error").Inc()
		return nil, r.handleError(err, "get consultation messages")
	}
	messagesDBQueryTotal.WithLabelValues("get_consultation_messages", "success").Inc()
	return r.mapToMessages(rows), nil
}

// GetMessagesAfterCursor returns all non-deleted messages newer than a given timestamp.
// Used for polling / WebSocket catch-up.
func (r *consultationMessagesRepository) GetMessagesAfterCursor(ctx context.Context, consultationID uuid.UUID, cursor time.Time) ([]telemedicine.MessageAfterCursor, error) {
	start := time.Now()
	defer func() { messagesDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	rows, err := r.querier.GetMessagesAfterCursor(ctx, sqlc.GetMessagesAfterCursorParams{
		ConsultationID: uuidToPgtypeUUID(consultationID),
		SentAt:         pgtype.Timestamp{Time: cursor, Valid: true},
	})
	if err != nil {
		messagesDBQueryTotal.WithLabelValues("get_messages_after_cursor", "error").Inc()
		return nil, r.handleError(err, "get messages after cursor")
	}
	messagesDBQueryTotal.WithLabelValues("get_messages_after_cursor", "success").Inc()
	return r.mapToMessagesAfterCursor(rows), nil
}

// GetLastMessage returns the most recent non-deleted message for a consultation.
// Used in consultation list card previews. Returns domain.ErrNotFound when the
// thread is empty.
func (r *consultationMessagesRepository) GetLastMessage(ctx context.Context, consultationID uuid.UUID) (telemedicine.LastMessagePreview, error) {
	start := time.Now()
	defer func() { messagesDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	row, err := r.querier.GetLastMessage(ctx, uuidToPgtypeUUID(consultationID))
	if err != nil {
		messagesDBQueryTotal.WithLabelValues("get_last_message", "error").Inc()
		return telemedicine.LastMessagePreview{}, r.handleError(err, "get last message")
	}
	messagesDBQueryTotal.WithLabelValues("get_last_message", "success").Inc()
	return telemedicine.LastMessagePreview{
		ID:             pgtypeUUIDToUUID(row.ID),
		SenderRole:     telemedicine.SenderRole(row.SenderRole),
		MessageType:    telemedicine.MessageType(row.MessageType),
		Content:        pgtypeTextToStringPtr(row.Content),
		AttachmentType: attachmentTypePtr(pgtypeTextToStringPtr(row.AttachmentType)),
		SentAt:         row.SentAt.Time,
	}, nil
}

// ─── Read Receipts ────────────────────────────────────────────────────────────

// MarkMessageRead marks a single message as read.
func (r *consultationMessagesRepository) MarkMessageRead(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() { messagesDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	err := r.querier.MarkMessageRead(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		messagesDBQueryTotal.WithLabelValues("mark_message_read", "error").Inc()
		return r.handleError(err, "mark message read")
	}
	messagesDBQueryTotal.WithLabelValues("mark_message_read", "success").Inc()
	return nil
}

// MarkAllProviderMessagesRead marks all unread provider messages as read.
// Called when the patient opens the chat screen.
func (r *consultationMessagesRepository) MarkAllProviderMessagesRead(ctx context.Context, consultationID uuid.UUID) error {
	start := time.Now()
	defer func() { messagesDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	err := r.querier.MarkAllProviderMessagesRead(ctx, uuidToPgtypeUUID(consultationID))
	if err != nil {
		messagesDBQueryTotal.WithLabelValues("mark_all_provider_messages_read", "error").Inc()
		return r.handleError(err, "mark all provider messages read")
	}
	messagesDBQueryTotal.WithLabelValues("mark_all_provider_messages_read", "success").Inc()
	return nil
}

// MarkAllPatientMessagesRead marks all unread patient messages as read.
// Called when the provider opens the chat screen.
func (r *consultationMessagesRepository) MarkAllPatientMessagesRead(ctx context.Context, consultationID uuid.UUID) error {
	start := time.Now()
	defer func() { messagesDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	err := r.querier.MarkAllPatientMessagesRead(ctx, uuidToPgtypeUUID(consultationID))
	if err != nil {
		messagesDBQueryTotal.WithLabelValues("mark_all_patient_messages_read", "error").Inc()
		return r.handleError(err, "mark all patient messages read")
	}
	messagesDBQueryTotal.WithLabelValues("mark_all_patient_messages_read", "success").Inc()
	return nil
}

// CountUnreadMessages returns the unread badge count for a given party.
// Pass the sender_role of the OTHER party (i.e. patient calls with "provider").
func (r *consultationMessagesRepository) CountUnreadMessages(ctx context.Context, consultationID uuid.UUID, senderRole telemedicine.SenderRole) (telemedicine.UnreadCount, error) {
	start := time.Now()
	defer func() { messagesDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	count, err := r.querier.CountUnreadMessages(ctx, sqlc.CountUnreadMessagesParams{
		ConsultationID: uuidToPgtypeUUID(consultationID),
		SenderRole:     string(senderRole),
	})
	if err != nil {
		messagesDBQueryTotal.WithLabelValues("count_unread_messages", "error").Inc()
		return telemedicine.UnreadCount{}, r.handleError(err, "count unread messages")
	}
	messagesDBQueryTotal.WithLabelValues("count_unread_messages", "success").Inc()
	return telemedicine.UnreadCount{Count: count}, nil
}

// ─── System / Special Message Helpers ────────────────────────────────────────

// InsertSystemEvent inserts a system-generated event message (call start, file shared, etc.).
// systemUserID should be a fixed UUID from application config.
func (r *consultationMessagesRepository) InsertSystemEvent(ctx context.Context, consultationID uuid.UUID, systemUserID uuid.UUID, label string, metadata map[string]interface{}) (telemedicine.ConsultationMessage, error) {
	start := time.Now()
	defer func() { messagesDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	row, err := r.querier.InsertSystemEvent(ctx, sqlc.InsertSystemEventParams{
		ConsultationID: uuidToPgtypeUUID(consultationID),
		SenderUserID:   uuidToPgtypeUUID(systemUserID),
		Content:        pgtypeTextFromString(label),
		Column4:        interfaceToJSONRawMessage(metadata),
	})
	if err != nil {
		messagesDBQueryTotal.WithLabelValues("insert_system_event", "error").Inc()
		return telemedicine.ConsultationMessage{}, r.handleError(err, "insert system event")
	}
	messagesDBQueryTotal.WithLabelValues("insert_system_event", "success").Inc()
	return r.mapToMessage(row), nil
}

// GetSystemEvents retrieves all system events for a consultation, ordered by time.
// Used by the call log panel.
func (r *consultationMessagesRepository) GetSystemEvents(ctx context.Context, consultationID uuid.UUID) ([]telemedicine.SystemEvent, error) {
	start := time.Now()
	defer func() { messagesDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	rows, err := r.querier.GetSystemEvents(ctx, uuidToPgtypeUUID(consultationID))
	if err != nil {
		messagesDBQueryTotal.WithLabelValues("get_system_events", "error").Inc()
		return nil, r.handleError(err, "get system events")
	}
	messagesDBQueryTotal.WithLabelValues("get_system_events", "success").Inc()
	return r.mapToSystemEvents(rows), nil
}

// ─── Attachments ─────────────────────────────────────────────────────────────

// GetConsultationAttachments returns all non-deleted attachment messages for a consultation.
func (r *consultationMessagesRepository) GetConsultationAttachments(ctx context.Context, consultationID uuid.UUID) ([]telemedicine.AttachmentEntry, error) {
	start := time.Now()
	defer func() { messagesDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	rows, err := r.querier.GetConsultationAttachments(ctx, uuidToPgtypeUUID(consultationID))
	if err != nil {
		messagesDBQueryTotal.WithLabelValues("get_consultation_attachments", "error").Inc()
		return nil, r.handleError(err, "get consultation attachments")
	}
	messagesDBQueryTotal.WithLabelValues("get_consultation_attachments", "success").Inc()
	return r.mapToAttachmentEntries(rows), nil
}

// ─── Mapping helpers ─────────────────────────────────────────────────────────

func (r *consultationMessagesRepository) mapToMessage(row sqlc.ConsultationMessage) telemedicine.ConsultationMessage {
	return telemedicine.ConsultationMessage{
		ID:                 pgtypeUUIDToUUID(row.ID),
		ConsultationID:     pgtypeUUIDToUUID(row.ConsultationID),
		SenderUserID:       pgtypeUUIDToUUID(row.SenderUserID),
		SenderRole:         telemedicine.SenderRole(row.SenderRole),
		MessageType:        telemedicine.MessageType(row.MessageType),
		Content:            pgtypeTextToStringPtr(row.Content),
		AttachmentURL:      pgtypeTextToStringPtr(row.AttachmentUrl),
		AttachmentType:     attachmentTypePtr(pgtypeTextToStringPtr(row.AttachmentType)),
		AttachmentFilename: pgtypeTextToStringPtr(row.AttachmentFilename),
		IsRead:             row.IsRead,
		ReadAt:             pgtypeTimestampToTimePtr(row.ReadAt),
		IsDeleted:          row.IsDeleted,
		Metadata:           mapFromJSONB(row.Metadata),
		SentAt:             row.SentAt.Time,
	}
}

func (r *consultationMessagesRepository) mapToMessages(rows []sqlc.GetConsultationMessagesRow) []telemedicine.ConsultationMessage {
	result := make([]telemedicine.ConsultationMessage, len(rows))
	for i, row := range rows {
		result[i] = telemedicine.ConsultationMessage{
			ID:                 pgtypeUUIDToUUID(row.ID),
			ConsultationID:     pgtypeUUIDToUUID(row.ConsultationID),
			SenderUserID:       pgtypeUUIDToUUID(row.SenderUserID),
			SenderRole:         telemedicine.SenderRole(row.SenderRole),
			MessageType:        telemedicine.MessageType(row.MessageType),
			Content:            pgtypeTextToStringPtr(row.Content),
			AttachmentURL:      pgtypeTextToStringPtr(row.AttachmentUrl),
			AttachmentType:     attachmentTypePtr(pgtypeTextToStringPtr(row.AttachmentType)),
			AttachmentFilename: pgtypeTextToStringPtr(row.AttachmentFilename),
			IsRead:             row.IsRead,
			ReadAt:             pgtypeTimestampToTimePtr(row.ReadAt),
			Metadata:           mapFromJSONB(row.Metadata),
			SentAt:             row.SentAt.Time,
		}
	}
	return result
}

func (r *consultationMessagesRepository) mapToMessagesAfterCursor(rows []sqlc.GetMessagesAfterCursorRow) []telemedicine.MessageAfterCursor {
	result := make([]telemedicine.MessageAfterCursor, len(rows))
	for i, row := range rows {
		result[i] = telemedicine.MessageAfterCursor{
			ID:                 pgtypeUUIDToUUID(row.ID),
			SenderUserID:       pgtypeUUIDToUUID(row.SenderUserID),
			SenderRole:         telemedicine.SenderRole(row.SenderRole),
			MessageType:        telemedicine.MessageType(row.MessageType),
			Content:            pgtypeTextToStringPtr(row.Content),
			AttachmentURL:      pgtypeTextToStringPtr(row.AttachmentUrl),
			AttachmentType:     attachmentTypePtr(pgtypeTextToStringPtr(row.AttachmentType)),
			AttachmentFilename: pgtypeTextToStringPtr(row.AttachmentFilename),
			IsRead:             row.IsRead,
			Metadata:           mapFromJSONB(row.Metadata),
			SentAt:             row.SentAt.Time,
		}
	}
	return result
}

func (r *consultationMessagesRepository) mapToSystemEvents(rows []sqlc.GetSystemEventsRow) []telemedicine.SystemEvent {
	result := make([]telemedicine.SystemEvent, len(rows))
	for i, row := range rows {
		result[i] = telemedicine.SystemEvent{
			ID:       pgtypeUUIDToUUID(row.ID),
			Content:  pgtypeTextToStringPtr(row.Content),
			Metadata: mapFromJSONB(row.Metadata),
			SentAt:   row.SentAt.Time,
		}
	}
	return result
}

func (r *consultationMessagesRepository) mapToAttachmentEntries(rows []sqlc.GetConsultationAttachmentsRow) []telemedicine.AttachmentEntry {
	result := make([]telemedicine.AttachmentEntry, len(rows))
	for i, row := range rows {
		result[i] = telemedicine.AttachmentEntry{
			ID:                 pgtypeUUIDToUUID(row.ID),
			SenderUserID:       pgtypeUUIDToUUID(row.SenderUserID),
			SenderRole:         telemedicine.SenderRole(row.SenderRole),
			AttachmentURL:      pgtypeTextToString(row.AttachmentUrl),
			AttachmentType:     telemedicine.AttachmentType(pgtypeTextToString(row.AttachmentType)),
			AttachmentFilename: pgtypeTextToStringPtr(row.AttachmentFilename),
			SentAt:             row.SentAt.Time,
		}
	}
	return result
}

// ─── Local conversion helpers ─────────────────────────────────────────────────

// attachmentTypePtr converts a *string to a typed *AttachmentType.
func attachmentTypePtr(s *string) *telemedicine.AttachmentType {
	if s == nil {
		return nil
	}
	v := telemedicine.AttachmentType(*s)
	return &v
}

// attachmentTypeToStringPtr converts a typed *AttachmentType to *string for pgtype helpers.
func attachmentTypeToStringPtr(at *telemedicine.AttachmentType) *string {
	if at == nil {
		return nil
	}
	s := string(*at)
	return &s
}

// ─── Error handling ───────────────────────────────────────────────────────────

func (r *consultationMessagesRepository) handleError(err error, operation string) error {
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	return fmt.Errorf("%s: %w", operation, err)
}
