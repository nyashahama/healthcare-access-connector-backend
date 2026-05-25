// Package telemedicine implements the consultation messages service
package telemedicine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/telemedicine"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
)

// cache TTLs
const (
	messageThreadCacheTTL = 30 * time.Second // messages change frequently; keep very short
	unreadCountCacheTTL   = 15 * time.Second
	messageThreadIndexTTL = 5 * time.Minute
)

type consultationMessagesService struct {
	messagesRepo     repository.ConsultationMessagesRepository
	consultationRepo repository.ConsultationRepository
	cache            cache.Service
	logger           *zerolog.Logger
}

// NewConsultationMessagesService creates a new consultation messages service.
func NewConsultationMessagesService(
	messagesRepo repository.ConsultationMessagesRepository,
	consultationRepo repository.ConsultationRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) service.ConsultationMessagesService {
	return &consultationMessagesService{
		messagesRepo:     messagesRepo,
		consultationRepo: consultationRepo,
		cache:            cache,
		logger:           logger,
	}
}

// ─── Write Operations ─────────────────────────────────────────────────────────

// SendMessage validates and persists a new message from a patient or provider.
// It also ensures the consultation is in an active state before accepting the message.
func (s *consultationMessagesService) SendMessage(ctx context.Context, msg telemedicine.ConsultationMessage) (telemedicine.ConsultationMessage, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().Dur("duration_ms", time.Since(start)).Str("consultation_id", msg.ConsultationID.String()).Msg("SendMessage completed")
	}()

	// Normalize "provider_staff" → "provider" so the value always matches the
	// DB check constraint (valid_sender_role: patient | provider | system).
	// The JWT role and WS payload use "provider_staff"; the messages table does
	// not. Both the HTTP handler path and the WebSocket path call SendMessage,
	// so normalizing here covers both in a single place.
	if msg.SenderRole == "provider_staff" {
		msg.SenderRole = "provider"
	}

	// Validate required fields
	if msg.ConsultationID == uuid.Nil {
		return telemedicine.ConsultationMessage{}, domain.NewAppError(domain.ErrValidation, "consultation_id is required", 400)
	}
	if msg.SenderUserID == uuid.Nil {
		return telemedicine.ConsultationMessage{}, domain.NewAppError(domain.ErrValidation, "sender_user_id is required", 400)
	}
	if msg.SenderRole == "" {
		return telemedicine.ConsultationMessage{}, domain.NewAppError(domain.ErrValidation, "sender_role is required", 400)
	}
	if msg.MessageType == "" {
		return telemedicine.ConsultationMessage{}, domain.NewAppError(domain.ErrValidation, "message_type is required", 400)
	}

	// Validate content vs attachment based on message type
	switch msg.MessageType {
	case telemedicine.MessageTypeText, telemedicine.MessageTypeSystemEvent, telemedicine.MessageTypePrescription:
		if msg.Content == nil || *msg.Content == "" {
			return telemedicine.ConsultationMessage{}, domain.NewAppError(domain.ErrValidation, "content is required for this message type", 400)
		}
	case telemedicine.MessageTypeAttachment:
		if msg.AttachmentURL == nil || *msg.AttachmentURL == "" {
			return telemedicine.ConsultationMessage{}, domain.NewAppError(domain.ErrValidation, "attachment_url is required for attachment messages", 400)
		}
		if msg.AttachmentType == nil {
			return telemedicine.ConsultationMessage{}, domain.NewAppError(domain.ErrValidation, "attachment_type is required for attachment messages", 400)
		}
	default:
		return telemedicine.ConsultationMessage{}, domain.NewAppError(domain.ErrValidation, "unknown message_type", 400)
	}

	// Ensure the consultation is active
	consultation, err := s.consultationRepo.GetConsultationByID(ctx, msg.ConsultationID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return telemedicine.ConsultationMessage{}, domain.NewAppError(err, "consultation not found", 404)
		}
		return telemedicine.ConsultationMessage{}, domain.NewAppError(err, "failed to validate consultation", 500)
	}

	if consultation.Status != telemedicine.ConsultationStatusAccepted &&
		consultation.Status != telemedicine.ConsultationStatusInProgress {
		return telemedicine.ConsultationMessage{}, domain.NewAppError(domain.ErrValidation,
			fmt.Sprintf("cannot send messages to a consultation with status '%s'", consultation.Status), 400)
	}

	created, err := s.messagesRepo.InsertMessage(ctx, msg)
	if err != nil {
		s.logger.Error().Err(err).Str("consultation_id", msg.ConsultationID.String()).Msg("Failed to insert message")
		return telemedicine.ConsultationMessage{}, domain.NewAppError(err, "failed to send message", 500)
	}

	// Invalidate the thread cache so the next poll gets fresh data
	s.invalidateThreadCache(ctx, msg.ConsultationID)
	s.invalidateUnreadCache(ctx, msg.ConsultationID, msg.SenderRole)

	return created, nil
}

// DeleteMessage soft-deletes a message. Only the original sender may delete their own messages.
// System messages and already-deleted messages cannot be deleted.
func (s *consultationMessagesService) DeleteMessage(ctx context.Context, id uuid.UUID, requestingUserID uuid.UUID) error {
	msg, err := s.messagesRepo.GetMessageByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(err, "message not found", 404)
		}
		return domain.NewAppError(err, "failed to retrieve message", 500)
	}

	if msg.IsDeleted {
		return domain.NewAppError(domain.ErrConflict, "message is already deleted", 409)
	}
	if msg.MessageType == telemedicine.MessageTypeSystemEvent {
		return domain.NewAppError(domain.ErrValidation, "system messages cannot be deleted", 400)
	}
	if msg.SenderUserID != requestingUserID {
		return domain.NewAppError(domain.ErrForbidden, "you may only delete your own messages", 403)
	}

	if err := s.messagesRepo.SoftDeleteMessage(ctx, id); err != nil {
		s.logger.Error().Err(err).Str("message_id", id.String()).Msg("Failed to soft delete message")
		return domain.NewAppError(err, "failed to delete message", 500)
	}

	s.invalidateThreadCache(ctx, msg.ConsultationID)
	s.invalidateUnreadCache(ctx, msg.ConsultationID, msg.SenderRole)
	return nil
}

// InsertSystemEvent emits a system-generated event into a consultation's message thread.
func (s *consultationMessagesService) InsertSystemEvent(ctx context.Context, consultationID uuid.UUID, systemUserID uuid.UUID, label string, metadata map[string]interface{}) (telemedicine.ConsultationMessage, error) {
	if consultationID == uuid.Nil {
		return telemedicine.ConsultationMessage{}, domain.NewAppError(domain.ErrValidation, "consultation_id is required", 400)
	}
	if label == "" {
		return telemedicine.ConsultationMessage{}, domain.NewAppError(domain.ErrValidation, "label is required", 400)
	}

	msg, err := s.messagesRepo.InsertSystemEvent(ctx, consultationID, systemUserID, label, metadata)
	if err != nil {
		s.logger.Error().Err(err).Str("consultation_id", consultationID.String()).Str("label", label).Msg("Failed to insert system event")
		return telemedicine.ConsultationMessage{}, domain.NewAppError(err, "failed to insert system event", 500)
	}

	s.invalidateThreadCache(ctx, consultationID)
	return msg, nil
}

// ─── Read Operations ──────────────────────────────────────────────────────────

// GetConsultationMessages returns a paginated message thread for initial chat load.
func (s *consultationMessagesService) GetConsultationMessages(ctx context.Context, consultationID uuid.UUID, limit, offset int) ([]telemedicine.ConsultationMessage, error) {
	limit, offset = clampPagination(limit, offset)

	// Only cache the first page; subsequent pages are rarely repeated
	if offset == 0 && s.cache != nil && s.cache.IsAvailable() {
		cacheKey := messageThreadCacheKey(consultationID, limit)
		var cached []telemedicine.ConsultationMessage
		if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
			return cached, nil
		}
	}

	msgs, err := s.messagesRepo.GetConsultationMessages(ctx, consultationID, limit, offset)
	if err != nil {
		s.logger.Error().Err(err).Str("consultation_id", consultationID.String()).Msg("Failed to get messages")
		return nil, domain.NewAppError(err, "failed to retrieve messages", 500)
	}

	if offset == 0 && s.cache != nil && s.cache.IsAvailable() {
		cacheKey := messageThreadCacheKey(consultationID, limit)
		if err := s.cache.Set(ctx, cacheKey, msgs, messageThreadCacheTTL); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache message thread")
		} else {
			s.registerThreadCacheKey(ctx, consultationID, cacheKey)
		}
	}

	return msgs, nil
}

// GetMessagesAfterCursor returns all messages newer than a timestamp for polling/catch-up.
func (s *consultationMessagesService) GetMessagesAfterCursor(ctx context.Context, consultationID uuid.UUID, cursor time.Time) ([]telemedicine.MessageAfterCursor, error) {
	msgs, err := s.messagesRepo.GetMessagesAfterCursor(ctx, consultationID, cursor)
	if err != nil {
		s.logger.Error().Err(err).Str("consultation_id", consultationID.String()).Msg("Failed to get messages after cursor")
		return nil, domain.NewAppError(err, "failed to retrieve new messages", 500)
	}
	return msgs, nil
}

// GetLastMessage returns the most recent message for a consultation card preview.
func (s *consultationMessagesService) GetLastMessage(ctx context.Context, consultationID uuid.UUID) (telemedicine.LastMessagePreview, error) {
	msg, err := s.messagesRepo.GetLastMessage(ctx, consultationID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return telemedicine.LastMessagePreview{}, domain.NewAppError(err, "no messages found", 404)
		}
		s.logger.Error().Err(err).Str("consultation_id", consultationID.String()).Msg("Failed to get last message")
		return telemedicine.LastMessagePreview{}, domain.NewAppError(err, "failed to retrieve last message", 500)
	}
	return msg, nil
}

// GetSystemEvents returns all system-generated events for the call log panel.
func (s *consultationMessagesService) GetSystemEvents(ctx context.Context, consultationID uuid.UUID) ([]telemedicine.SystemEvent, error) {
	events, err := s.messagesRepo.GetSystemEvents(ctx, consultationID)
	if err != nil {
		s.logger.Error().Err(err).Str("consultation_id", consultationID.String()).Msg("Failed to get system events")
		return nil, domain.NewAppError(err, "failed to retrieve system events", 500)
	}
	return events, nil
}

// GetConsultationAttachments returns all shared files for the attachment panel.
func (s *consultationMessagesService) GetConsultationAttachments(ctx context.Context, consultationID uuid.UUID) ([]telemedicine.AttachmentEntry, error) {
	attachments, err := s.messagesRepo.GetConsultationAttachments(ctx, consultationID)
	if err != nil {
		s.logger.Error().Err(err).Str("consultation_id", consultationID.String()).Msg("Failed to get attachments")
		return nil, domain.NewAppError(err, "failed to retrieve attachments", 500)
	}
	return attachments, nil
}

// ─── Read Receipts ────────────────────────────────────────────────────────────

// MarkMessageRead marks a single message as read.
func (s *consultationMessagesService) MarkMessageRead(ctx context.Context, id uuid.UUID) error {
	msg, err := s.messagesRepo.GetMessageByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(err, "message not found", 404)
		}
		s.logger.Error().Err(err).Str("message_id", id.String()).Msg("Failed to retrieve message before marking read")
		return domain.NewAppError(err, "failed to retrieve message", 500)
	}

	if err := s.messagesRepo.MarkMessageRead(ctx, id); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(err, "message not found", 404)
		}
		s.logger.Error().Err(err).Str("message_id", id.String()).Msg("Failed to mark message read")
		return domain.NewAppError(err, "failed to mark message as read", 500)
	}

	s.invalidateUnreadCache(ctx, msg.ConsultationID, msg.SenderRole)
	return nil
}

// MarkAllProviderMessagesRead marks all unread provider messages in a consultation as read.
// Called by the patient when they open the chat screen.
func (s *consultationMessagesService) MarkAllProviderMessagesRead(ctx context.Context, consultationID uuid.UUID) error {
	if err := s.messagesRepo.MarkAllProviderMessagesRead(ctx, consultationID); err != nil {
		s.logger.Error().Err(err).Str("consultation_id", consultationID.String()).Msg("Failed to mark provider messages read")
		return domain.NewAppError(err, "failed to mark messages as read", 500)
	}
	s.invalidateUnreadCache(ctx, consultationID, telemedicine.SenderRoleProvider)
	return nil
}

// MarkAllPatientMessagesRead marks all unread patient messages in a consultation as read.
// Called by the provider when they open the chat screen.
func (s *consultationMessagesService) MarkAllPatientMessagesRead(ctx context.Context, consultationID uuid.UUID) error {
	if err := s.messagesRepo.MarkAllPatientMessagesRead(ctx, consultationID); err != nil {
		s.logger.Error().Err(err).Str("consultation_id", consultationID.String()).Msg("Failed to mark patient messages read")
		return domain.NewAppError(err, "failed to mark messages as read", 500)
	}
	s.invalidateUnreadCache(ctx, consultationID, telemedicine.SenderRolePatient)
	return nil
}

// CountUnreadMessages returns the unread badge count for a given sender role.
func (s *consultationMessagesService) CountUnreadMessages(ctx context.Context, consultationID uuid.UUID, senderRole telemedicine.SenderRole) (telemedicine.UnreadCount, error) {
	cacheKey := unreadCountCacheKey(consultationID, senderRole)
	if s.cache != nil && s.cache.IsAvailable() {
		var cached telemedicine.UnreadCount
		if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
			return cached, nil
		}
	}

	count, err := s.messagesRepo.CountUnreadMessages(ctx, consultationID, senderRole)
	if err != nil {
		s.logger.Error().Err(err).Str("consultation_id", consultationID.String()).Msg("Failed to count unread messages")
		return telemedicine.UnreadCount{}, domain.NewAppError(err, "failed to count unread messages", 500)
	}

	if s.cache != nil && s.cache.IsAvailable() {
		if err := s.cache.Set(ctx, cacheKey, count, unreadCountCacheTTL); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache unread count")
		}
	}

	return count, nil
}

// ─── Cache helpers ─────────────────────────────────────────────────────────────

func (s *consultationMessagesService) invalidateThreadCache(ctx context.Context, consultationID uuid.UUID) {
	if s.cache == nil || !s.cache.IsAvailable() {
		return
	}
	keys := append(s.collectThreadCacheKeys(ctx, consultationID), messageThreadCacheKey(consultationID, 20), messageThreadIndexKey(consultationID))
	for _, key := range uniqueMessageCacheKeys(keys) {
		if err := s.cache.Delete(ctx, key); err != nil {
			s.logger.Warn().Err(err).Str("key", key).Msg("Failed to invalidate thread cache")
		}
	}
}

func (s *consultationMessagesService) invalidateUnreadCache(ctx context.Context, consultationID uuid.UUID, role telemedicine.SenderRole) {
	if s.cache == nil || !s.cache.IsAvailable() {
		return
	}
	key := unreadCountCacheKey(consultationID, role)
	if err := s.cache.Delete(ctx, key); err != nil {
		s.logger.Warn().Err(err).Str("key", key).Msg("Failed to invalidate unread count cache")
	}
}

// ─── Cache key builders ───────────────────────────────────────────────────────

func messageThreadCacheKey(consultationID uuid.UUID, limit int) string {
	return fmt.Sprintf("messages:thread:%s:limit:%d", consultationID.String(), limit)
}

func unreadCountCacheKey(consultationID uuid.UUID, role telemedicine.SenderRole) string {
	return fmt.Sprintf("messages:unread:%s:role:%s", consultationID.String(), string(role))
}

func messageThreadIndexKey(consultationID uuid.UUID) string {
	return fmt.Sprintf("messages:thread:index:%s", consultationID.String())
}

func (s *consultationMessagesService) registerThreadCacheKey(ctx context.Context, consultationID uuid.UUID, cacheKey string) {
	if s.cache == nil || !s.cache.IsAvailable() {
		return
	}

	keys := s.collectThreadCacheKeys(ctx, consultationID)
	keys = append(keys, cacheKey)
	if err := s.cache.Set(ctx, messageThreadIndexKey(consultationID), uniqueMessageCacheKeys(keys), messageThreadIndexTTL); err != nil {
		s.logger.Warn().Err(err).Str("consultation_id", consultationID.String()).Msg("Failed to update message thread cache index")
	}
}

func (s *consultationMessagesService) collectThreadCacheKeys(ctx context.Context, consultationID uuid.UUID) []string {
	if s.cache == nil || !s.cache.IsAvailable() {
		return nil
	}

	var keys []string
	if err := s.cache.Get(ctx, messageThreadIndexKey(consultationID), &keys); err != nil {
		return nil
	}
	return keys
}

func uniqueMessageCacheKeys(keys []string) []string {
	seen := make(map[string]struct{}, len(keys))
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, key)
	}
	return result
}
