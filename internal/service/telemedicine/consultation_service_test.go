package telemedicine

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/telemedicine"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockConsultationRepository struct {
	getConsultationByIDFunc            func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error)
	createConsultationFunc             func(ctx context.Context, c telemedicine.Consultation) (telemedicine.Consultation, error)
	getPatientActiveConsultationFunc   func(ctx context.Context, patientID uuid.UUID) (telemedicine.ActiveConsultationCheck, error)
	acceptConsultationFunc             func(ctx context.Context, id uuid.UUID, providerStaffID uuid.UUID, clinicID uuid.UUID) (telemedicine.Consultation, error)
	startConsultationFunc              func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error)
	completeConsultationFunc           func(ctx context.Context, id uuid.UUID, endedBy uuid.UUID) (telemedicine.Consultation, error)
	escalateConsultationFunc           func(ctx context.Context, id uuid.UUID, endedBy uuid.UUID) (telemedicine.Consultation, error)
	cancelConsultationFunc             func(ctx context.Context, id uuid.UUID, cancelledBy uuid.UUID) (telemedicine.Consultation, error)
	declineConsultationFunc            func(ctx context.Context, id uuid.UUID) error
	markNoShowFunc                     func(ctx context.Context, id uuid.UUID) error
	setConsultationFeeFunc             func(ctx context.Context, id uuid.UUID, fee float64) error
	updatePaymentStatusFunc            func(ctx context.Context, id uuid.UUID, status telemedicine.PaymentStatus, reference *string) error
	updateConsultationChannelFunc      func(ctx context.Context, id uuid.UUID, channel telemedicine.ConsultationChannel) error
	submitPatientRatingFunc            func(ctx context.Context, id uuid.UUID, rating int, feedback *string) error
	linkFollowUpAppointmentFunc         func(ctx context.Context, id uuid.UUID, appointmentID uuid.UUID) error
	getPatientConsultationsFunc        func(ctx context.Context, patientID uuid.UUID, limit, offset int) ([]telemedicine.PatientConsultationSummary, error)
	getProviderActiveConsultationsFunc func(ctx context.Context, providerStaffID uuid.UUID) ([]telemedicine.ProviderActiveConsultation, error)
	getWaitingRoomFunc                 func(ctx context.Context) ([]telemedicine.WaitingRoomEntry, error)
	getProviderConsultationHistoryFunc func(ctx context.Context, providerStaffID uuid.UUID, limit, offset int) ([]telemedicine.ProviderConsultationHistoryEntry, error)
	getConsultationWithDetailsFunc     func(ctx context.Context, id uuid.UUID) (telemedicine.ConsultationWithDetails, error)
}

func (m *mockConsultationRepository) CreateConsultation(ctx context.Context, c telemedicine.Consultation) (telemedicine.Consultation, error) {
	if m.createConsultationFunc != nil {
		return m.createConsultationFunc(ctx, c)
	}
	return c, nil
}

func (m *mockConsultationRepository) GetConsultationByID(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
	if m.getConsultationByIDFunc != nil {
		return m.getConsultationByIDFunc(ctx, id)
	}
	return telemedicine.Consultation{}, domain.ErrNotFound
}

func (m *mockConsultationRepository) GetConsultationWithDetails(ctx context.Context, id uuid.UUID) (telemedicine.ConsultationWithDetails, error) {
	if m.getConsultationWithDetailsFunc != nil {
		return m.getConsultationWithDetailsFunc(ctx, id)
	}
	return telemedicine.ConsultationWithDetails{}, domain.ErrNotFound
}

func (m *mockConsultationRepository) AcceptConsultation(ctx context.Context, id uuid.UUID, providerStaffID uuid.UUID, clinicID uuid.UUID) (telemedicine.Consultation, error) {
	if m.acceptConsultationFunc != nil {
		return m.acceptConsultationFunc(ctx, id, providerStaffID, clinicID)
	}
	return telemedicine.Consultation{}, domain.ErrNotFound
}

func (m *mockConsultationRepository) StartConsultation(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
	if m.startConsultationFunc != nil {
		return m.startConsultationFunc(ctx, id)
	}
	return telemedicine.Consultation{}, domain.ErrNotFound
}

func (m *mockConsultationRepository) CompleteConsultation(ctx context.Context, id uuid.UUID, endedBy uuid.UUID) (telemedicine.Consultation, error) {
	if m.completeConsultationFunc != nil {
		return m.completeConsultationFunc(ctx, id, endedBy)
	}
	return telemedicine.Consultation{}, domain.ErrNotFound
}

func (m *mockConsultationRepository) EscalateConsultation(ctx context.Context, id uuid.UUID, endedBy uuid.UUID) (telemedicine.Consultation, error) {
	if m.escalateConsultationFunc != nil {
		return m.escalateConsultationFunc(ctx, id, endedBy)
	}
	return telemedicine.Consultation{}, domain.ErrNotFound
}

func (m *mockConsultationRepository) CancelConsultation(ctx context.Context, id uuid.UUID, cancelledBy uuid.UUID) (telemedicine.Consultation, error) {
	if m.cancelConsultationFunc != nil {
		return m.cancelConsultationFunc(ctx, id, cancelledBy)
	}
	return telemedicine.Consultation{}, domain.ErrNotFound
}

func (m *mockConsultationRepository) DeclineConsultation(ctx context.Context, id uuid.UUID) error {
	if m.declineConsultationFunc != nil {
		return m.declineConsultationFunc(ctx, id)
	}
	return nil
}

func (m *mockConsultationRepository) MarkNoShow(ctx context.Context, id uuid.UUID) error {
	if m.markNoShowFunc != nil {
		return m.markNoShowFunc(ctx, id)
	}
	return nil
}

func (m *mockConsultationRepository) UpdateConsultationChannel(ctx context.Context, id uuid.UUID, channel telemedicine.ConsultationChannel) error {
	if m.updateConsultationChannelFunc != nil {
		return m.updateConsultationChannelFunc(ctx, id, channel)
	}
	return nil
}

func (m *mockConsultationRepository) UpdatePaymentStatus(ctx context.Context, id uuid.UUID, status telemedicine.PaymentStatus, reference *string) error {
	if m.updatePaymentStatusFunc != nil {
		return m.updatePaymentStatusFunc(ctx, id, status, reference)
	}
	return nil
}

func (m *mockConsultationRepository) SetConsultationFee(ctx context.Context, id uuid.UUID, fee float64) error {
	if m.setConsultationFeeFunc != nil {
		return m.setConsultationFeeFunc(ctx, id, fee)
	}
	return nil
}

func (m *mockConsultationRepository) SubmitPatientRating(ctx context.Context, id uuid.UUID, rating int, feedback *string) error {
	if m.submitPatientRatingFunc != nil {
		return m.submitPatientRatingFunc(ctx, id, rating, feedback)
	}
	return nil
}

func (m *mockConsultationRepository) LinkFollowUpAppointment(ctx context.Context, id uuid.UUID, appointmentID uuid.UUID) error {
	if m.linkFollowUpAppointmentFunc != nil {
		return m.linkFollowUpAppointmentFunc(ctx, id, appointmentID)
	}
	return nil
}

func (m *mockConsultationRepository) GetPatientConsultations(ctx context.Context, patientID uuid.UUID, limit, offset int) ([]telemedicine.PatientConsultationSummary, error) {
	if m.getPatientConsultationsFunc != nil {
		return m.getPatientConsultationsFunc(ctx, patientID, limit, offset)
	}
	return nil, nil
}

func (m *mockConsultationRepository) GetPatientActiveConsultation(ctx context.Context, patientID uuid.UUID) (telemedicine.ActiveConsultationCheck, error) {
	if m.getPatientActiveConsultationFunc != nil {
		return m.getPatientActiveConsultationFunc(ctx, patientID)
	}
	return telemedicine.ActiveConsultationCheck{}, domain.ErrNotFound
}

func (m *mockConsultationRepository) GetProviderActiveConsultations(ctx context.Context, providerStaffID uuid.UUID) ([]telemedicine.ProviderActiveConsultation, error) {
	if m.getProviderActiveConsultationsFunc != nil {
		return m.getProviderActiveConsultationsFunc(ctx, providerStaffID)
	}
	return nil, nil
}

func (m *mockConsultationRepository) GetWaitingRoom(ctx context.Context) ([]telemedicine.WaitingRoomEntry, error) {
	if m.getWaitingRoomFunc != nil {
		return m.getWaitingRoomFunc(ctx)
	}
	return nil, nil
}

func (m *mockConsultationRepository) GetProviderConsultationHistory(ctx context.Context, providerStaffID uuid.UUID, limit, offset int) ([]telemedicine.ProviderConsultationHistoryEntry, error) {
	if m.getProviderConsultationHistoryFunc != nil {
		return m.getProviderConsultationHistoryFunc(ctx, providerStaffID, limit, offset)
	}
	return nil, nil
}

type mockProviderAvailabilityRepository struct {
	upsertAvailabilityFunc            func(ctx context.Context, staffID uuid.UUID) (telemedicine.ProviderAvailability, error)
	goOnlineFunc                      func(ctx context.Context, staffID uuid.UUID) (telemedicine.ProviderAvailability, error)
	goOfflineFunc                     func(ctx context.Context, staffID uuid.UUID) error
	setAcceptingFunc                  func(ctx context.Context, staffID uuid.UUID, accepting bool, feeOverride *float64, waitMinutes *int) (telemedicine.ProviderAvailability, error)
	updateStatusFunc                 func(ctx context.Context, staffID uuid.UUID, status telemedicine.ProviderAvailabilityStatus, message *string) error
	updateHeartbeatFunc               func(ctx context.Context, staffID uuid.UUID) error
	updateWaitTimeFunc                func(ctx context.Context, staffID uuid.UUID, minutes int) error
	getAvailabilityByStaffIDFunc      func(ctx context.Context, staffID uuid.UUID) (telemedicine.ProviderAvailability, error)
	getAvailableProvidersFunc         func(ctx context.Context, clinicID *uuid.UUID) ([]telemedicine.AvailableProvider, error)
	getAvailableProvidersBySpecFunc   func(ctx context.Context, specialization string) ([]telemedicine.AvailableProviderBySpecialization, error)
	getStaleProvidersFunc             func(ctx context.Context) ([]telemedicine.StaleProvider, error)
	setStaleProvidersOfflineFunc      func(ctx context.Context) error
	incrementActiveConsultationsFunc  func(ctx context.Context, staffID uuid.UUID) (telemedicine.ProviderAvailability, error)
	decrementActiveConsultationsFunc  func(ctx context.Context, staffID uuid.UUID) error
	setMaxConcurrentFunc              func(ctx context.Context, staffID uuid.UUID, max int) error
}

type mockConsultationMessagesRepository struct {
	insertMessageFunc             func(ctx context.Context, msg telemedicine.ConsultationMessage) (telemedicine.ConsultationMessage, error)
	softDeleteMessageFunc         func(ctx context.Context, id uuid.UUID) error
	getMessageByIDFunc            func(ctx context.Context, id uuid.UUID) (telemedicine.ConsultationMessage, error)
	getConsultationMessagesFunc   func(ctx context.Context, consultationID uuid.UUID, limit, offset int) ([]telemedicine.ConsultationMessage, error)
	getMessagesAfterCursorFunc    func(ctx context.Context, consultationID uuid.UUID, cursor time.Time) ([]telemedicine.MessageAfterCursor, error)
	getLastMessageFunc            func(ctx context.Context, consultationID uuid.UUID) (telemedicine.LastMessagePreview, error)
	markMessageReadFunc           func(ctx context.Context, id uuid.UUID) error
	markAllProviderMessagesReadFunc func(ctx context.Context, consultationID uuid.UUID) error
	markAllPatientMessagesReadFunc  func(ctx context.Context, consultationID uuid.UUID) error
	countUnreadMessagesFunc       func(ctx context.Context, consultationID uuid.UUID, senderRole telemedicine.SenderRole) (telemedicine.UnreadCount, error)
	insertSystemEventFunc         func(ctx context.Context, consultationID uuid.UUID, systemUserID uuid.UUID, label string, metadata map[string]interface{}) (telemedicine.ConsultationMessage, error)
	getSystemEventsFunc           func(ctx context.Context, consultationID uuid.UUID) ([]telemedicine.SystemEvent, error)
	getConsultationAttachmentsFunc func(ctx context.Context, consultationID uuid.UUID) ([]telemedicine.AttachmentEntry, error)
}

type mockConsultationNotesRepository struct {
	createNoteFunc              func(ctx context.Context, consultationID uuid.UUID, authoredByStaffID uuid.UUID) (telemedicine.ConsultationNote, error)
	updateNoteFunc              func(ctx context.Context, id uuid.UUID, update telemedicine.ConsultationNote) (telemedicine.ConsultationNote, error)
	finaliseNoteFunc            func(ctx context.Context, id uuid.UUID) (telemedicine.ConsultationNote, error)
	finaliseNoteByConsultationFunc func(ctx context.Context, consultationID uuid.UUID) (telemedicine.ConsultationNote, error)
	getNoteByIDFunc             func(ctx context.Context, id uuid.UUID) (telemedicine.ConsultationNote, error)
	getNoteByConsultationIDFunc func(ctx context.Context, consultationID uuid.UUID) (telemedicine.ConsultationNote, error)
	getNoteWithProviderInfoFunc func(ctx context.Context, consultationID uuid.UUID) (telemedicine.ConsultationNoteWithProviderInfo, error)
	getProviderNoteHistoryFunc  func(ctx context.Context, staffID uuid.UUID, limit, offset int) ([]telemedicine.ProviderNoteHistoryEntry, error)
	getPatientNoteHistoryFunc   func(ctx context.Context, patientID uuid.UUID) ([]telemedicine.PatientNoteHistoryEntry, error)
	noteExistsForConsultationFunc func(ctx context.Context, consultationID uuid.UUID) (bool, error)
	isNoteFinalisedFunc         func(ctx context.Context, consultationID uuid.UUID) (bool, error)
}

func (m *mockConsultationNotesRepository) CreateNote(ctx context.Context, consultationID uuid.UUID, authoredByStaffID uuid.UUID) (telemedicine.ConsultationNote, error) {
	if m.createNoteFunc != nil {
		return m.createNoteFunc(ctx, consultationID, authoredByStaffID)
	}
	return telemedicine.ConsultationNote{}, nil
}

func (m *mockConsultationNotesRepository) UpdateNote(ctx context.Context, id uuid.UUID, update telemedicine.ConsultationNote) (telemedicine.ConsultationNote, error) {
	if m.updateNoteFunc != nil {
		return m.updateNoteFunc(ctx, id, update)
	}
	return telemedicine.ConsultationNote{}, nil
}

func (m *mockConsultationNotesRepository) FinaliseNote(ctx context.Context, id uuid.UUID) (telemedicine.ConsultationNote, error) {
	if m.finaliseNoteFunc != nil {
		return m.finaliseNoteFunc(ctx, id)
	}
	return telemedicine.ConsultationNote{}, nil
}

func (m *mockConsultationNotesRepository) FinaliseNoteByConsultation(ctx context.Context, consultationID uuid.UUID) (telemedicine.ConsultationNote, error) {
	if m.finaliseNoteByConsultationFunc != nil {
		return m.finaliseNoteByConsultationFunc(ctx, consultationID)
	}
	return telemedicine.ConsultationNote{}, nil
}

func (m *mockConsultationNotesRepository) GetNoteByID(ctx context.Context, id uuid.UUID) (telemedicine.ConsultationNote, error) {
	if m.getNoteByIDFunc != nil {
		return m.getNoteByIDFunc(ctx, id)
	}
	return telemedicine.ConsultationNote{}, domain.ErrNotFound
}

func (m *mockConsultationNotesRepository) GetNoteByConsultationID(ctx context.Context, consultationID uuid.UUID) (telemedicine.ConsultationNote, error) {
	if m.getNoteByConsultationIDFunc != nil {
		return m.getNoteByConsultationIDFunc(ctx, consultationID)
	}
	return telemedicine.ConsultationNote{}, domain.ErrNotFound
}

func (m *mockConsultationNotesRepository) GetNoteWithProviderInfo(ctx context.Context, consultationID uuid.UUID) (telemedicine.ConsultationNoteWithProviderInfo, error) {
	if m.getNoteWithProviderInfoFunc != nil {
		return m.getNoteWithProviderInfoFunc(ctx, consultationID)
	}
	return telemedicine.ConsultationNoteWithProviderInfo{}, domain.ErrNotFound
}

func (m *mockConsultationNotesRepository) GetProviderNoteHistory(ctx context.Context, staffID uuid.UUID, limit, offset int) ([]telemedicine.ProviderNoteHistoryEntry, error) {
	if m.getProviderNoteHistoryFunc != nil {
		return m.getProviderNoteHistoryFunc(ctx, staffID, limit, offset)
	}
	return nil, nil
}

func (m *mockConsultationNotesRepository) GetPatientNoteHistory(ctx context.Context, patientID uuid.UUID) ([]telemedicine.PatientNoteHistoryEntry, error) {
	if m.getPatientNoteHistoryFunc != nil {
		return m.getPatientNoteHistoryFunc(ctx, patientID)
	}
	return nil, nil
}

func (m *mockConsultationNotesRepository) NoteExistsForConsultation(ctx context.Context, consultationID uuid.UUID) (bool, error) {
	if m.noteExistsForConsultationFunc != nil {
		return m.noteExistsForConsultationFunc(ctx, consultationID)
	}
	return false, nil
}

func (m *mockConsultationNotesRepository) IsNoteFinalised(ctx context.Context, consultationID uuid.UUID) (bool, error) {
	if m.isNoteFinalisedFunc != nil {
		return m.isNoteFinalisedFunc(ctx, consultationID)
	}
	return false, nil
}

func (m *mockConsultationMessagesRepository) InsertMessage(ctx context.Context, msg telemedicine.ConsultationMessage) (telemedicine.ConsultationMessage, error) {
	if m.insertMessageFunc != nil {
		return m.insertMessageFunc(ctx, msg)
	}
	return msg, nil
}

func (m *mockConsultationMessagesRepository) SoftDeleteMessage(ctx context.Context, id uuid.UUID) error {
	if m.softDeleteMessageFunc != nil {
		return m.softDeleteMessageFunc(ctx, id)
	}
	return nil
}

func (m *mockConsultationMessagesRepository) GetMessageByID(ctx context.Context, id uuid.UUID) (telemedicine.ConsultationMessage, error) {
	if m.getMessageByIDFunc != nil {
		return m.getMessageByIDFunc(ctx, id)
	}
	return telemedicine.ConsultationMessage{}, domain.ErrNotFound
}

func (m *mockConsultationMessagesRepository) GetConsultationMessages(ctx context.Context, consultationID uuid.UUID, limit, offset int) ([]telemedicine.ConsultationMessage, error) {
	if m.getConsultationMessagesFunc != nil {
		return m.getConsultationMessagesFunc(ctx, consultationID, limit, offset)
	}
	return nil, nil
}

func (m *mockConsultationMessagesRepository) GetMessagesAfterCursor(ctx context.Context, consultationID uuid.UUID, cursor time.Time) ([]telemedicine.MessageAfterCursor, error) {
	if m.getMessagesAfterCursorFunc != nil {
		return m.getMessagesAfterCursorFunc(ctx, consultationID, cursor)
	}
	return nil, nil
}

func (m *mockConsultationMessagesRepository) GetLastMessage(ctx context.Context, consultationID uuid.UUID) (telemedicine.LastMessagePreview, error) {
	if m.getLastMessageFunc != nil {
		return m.getLastMessageFunc(ctx, consultationID)
	}
	return telemedicine.LastMessagePreview{}, domain.ErrNotFound
}

func (m *mockConsultationMessagesRepository) MarkMessageRead(ctx context.Context, id uuid.UUID) error {
	if m.markMessageReadFunc != nil {
		return m.markMessageReadFunc(ctx, id)
	}
	return nil
}

func (m *mockConsultationMessagesRepository) MarkAllProviderMessagesRead(ctx context.Context, consultationID uuid.UUID) error {
	if m.markAllProviderMessagesReadFunc != nil {
		return m.markAllProviderMessagesReadFunc(ctx, consultationID)
	}
	return nil
}

func (m *mockConsultationMessagesRepository) MarkAllPatientMessagesRead(ctx context.Context, consultationID uuid.UUID) error {
	if m.markAllPatientMessagesReadFunc != nil {
		return m.markAllPatientMessagesReadFunc(ctx, consultationID)
	}
	return nil
}

func (m *mockConsultationMessagesRepository) CountUnreadMessages(ctx context.Context, consultationID uuid.UUID, senderRole telemedicine.SenderRole) (telemedicine.UnreadCount, error) {
	if m.countUnreadMessagesFunc != nil {
		return m.countUnreadMessagesFunc(ctx, consultationID, senderRole)
	}
	return telemedicine.UnreadCount{}, nil
}

func (m *mockConsultationMessagesRepository) InsertSystemEvent(ctx context.Context, consultationID uuid.UUID, systemUserID uuid.UUID, label string, metadata map[string]interface{}) (telemedicine.ConsultationMessage, error) {
	if m.insertSystemEventFunc != nil {
		return m.insertSystemEventFunc(ctx, consultationID, systemUserID, label, metadata)
	}
	return telemedicine.ConsultationMessage{}, nil
}

func (m *mockConsultationMessagesRepository) GetSystemEvents(ctx context.Context, consultationID uuid.UUID) ([]telemedicine.SystemEvent, error) {
	if m.getSystemEventsFunc != nil {
		return m.getSystemEventsFunc(ctx, consultationID)
	}
	return nil, nil
}

func (m *mockConsultationMessagesRepository) GetConsultationAttachments(ctx context.Context, consultationID uuid.UUID) ([]telemedicine.AttachmentEntry, error) {
	if m.getConsultationAttachmentsFunc != nil {
		return m.getConsultationAttachmentsFunc(ctx, consultationID)
	}
	return nil, nil
}

func (m *mockProviderAvailabilityRepository) UpsertAvailability(ctx context.Context, staffID uuid.UUID) (telemedicine.ProviderAvailability, error) {
	if m.upsertAvailabilityFunc != nil {
		return m.upsertAvailabilityFunc(ctx, staffID)
	}
	return telemedicine.ProviderAvailability{}, nil
}

func (m *mockProviderAvailabilityRepository) GoOnline(ctx context.Context, staffID uuid.UUID) (telemedicine.ProviderAvailability, error) {
	if m.goOnlineFunc != nil {
		return m.goOnlineFunc(ctx, staffID)
	}
	return telemedicine.ProviderAvailability{}, domain.ErrNotFound
}

func (m *mockProviderAvailabilityRepository) GoOffline(ctx context.Context, staffID uuid.UUID) error {
	if m.goOfflineFunc != nil {
		return m.goOfflineFunc(ctx, staffID)
	}
	return domain.ErrNotFound
}

func (m *mockProviderAvailabilityRepository) SetAccepting(ctx context.Context, staffID uuid.UUID, accepting bool, feeOverride *float64, waitMinutes *int) (telemedicine.ProviderAvailability, error) {
	if m.setAcceptingFunc != nil {
		return m.setAcceptingFunc(ctx, staffID, accepting, feeOverride, waitMinutes)
	}
	return telemedicine.ProviderAvailability{}, nil
}

func (m *mockProviderAvailabilityRepository) UpdateStatus(ctx context.Context, staffID uuid.UUID, status telemedicine.ProviderAvailabilityStatus, message *string) error {
	if m.updateStatusFunc != nil {
		return m.updateStatusFunc(ctx, staffID, status, message)
	}
	return nil
}

func (m *mockProviderAvailabilityRepository) UpdateHeartbeat(ctx context.Context, staffID uuid.UUID) error {
	if m.updateHeartbeatFunc != nil {
		return m.updateHeartbeatFunc(ctx, staffID)
	}
	return nil
}

func (m *mockProviderAvailabilityRepository) UpdateWaitTime(ctx context.Context, staffID uuid.UUID, minutes int) error {
	if m.updateWaitTimeFunc != nil {
		return m.updateWaitTimeFunc(ctx, staffID, minutes)
	}
	return nil
}

func (m *mockProviderAvailabilityRepository) GetAvailabilityByStaffID(ctx context.Context, staffID uuid.UUID) (telemedicine.ProviderAvailability, error) {
	if m.getAvailabilityByStaffIDFunc != nil {
		return m.getAvailabilityByStaffIDFunc(ctx, staffID)
	}
	return telemedicine.ProviderAvailability{}, domain.ErrNotFound
}

func (m *mockProviderAvailabilityRepository) GetAvailableProviders(ctx context.Context, clinicID *uuid.UUID) ([]telemedicine.AvailableProvider, error) {
	if m.getAvailableProvidersFunc != nil {
		return m.getAvailableProvidersFunc(ctx, clinicID)
	}
	return nil, nil
}

func (m *mockProviderAvailabilityRepository) GetAvailableProvidersBySpecialization(ctx context.Context, specialization string) ([]telemedicine.AvailableProviderBySpecialization, error) {
	if m.getAvailableProvidersBySpecFunc != nil {
		return m.getAvailableProvidersBySpecFunc(ctx, specialization)
	}
	return nil, nil
}

func (m *mockProviderAvailabilityRepository) GetStaleProviders(ctx context.Context) ([]telemedicine.StaleProvider, error) {
	if m.getStaleProvidersFunc != nil {
		return m.getStaleProvidersFunc(ctx)
	}
	return nil, nil
}

func (m *mockProviderAvailabilityRepository) SetStaleProvidersOffline(ctx context.Context) error {
	if m.setStaleProvidersOfflineFunc != nil {
		return m.setStaleProvidersOfflineFunc(ctx)
	}
	return nil
}

func (m *mockProviderAvailabilityRepository) IncrementActiveConsultations(ctx context.Context, staffID uuid.UUID) (telemedicine.ProviderAvailability, error) {
	if m.incrementActiveConsultationsFunc != nil {
		return m.incrementActiveConsultationsFunc(ctx, staffID)
	}
	return telemedicine.ProviderAvailability{}, nil
}

func (m *mockProviderAvailabilityRepository) DecrementActiveConsultations(ctx context.Context, staffID uuid.UUID) error {
	if m.decrementActiveConsultationsFunc != nil {
		return m.decrementActiveConsultationsFunc(ctx, staffID)
	}
	return nil
}

func (m *mockProviderAvailabilityRepository) SetMaxConcurrent(ctx context.Context, staffID uuid.UUID, max int) error {
	if m.setMaxConcurrentFunc != nil {
		return m.setMaxConcurrentFunc(ctx, staffID, max)
	}
	return nil
}

type mockSymptomCheckerRepository struct {
	getSessionByIDFunc           func(ctx context.Context, id uuid.UUID) (telemedicine.SymptomCheckerSession, error)
	markSessionConvertedFunc     func(ctx context.Context, id uuid.UUID) error
	getLatestEligibleSessionFunc func(ctx context.Context, patientID uuid.UUID) (telemedicine.EligibleSession, error)
}

func (m *mockSymptomCheckerRepository) CreateSession(ctx context.Context, session telemedicine.SymptomCheckerSession) (telemedicine.SymptomCheckerSession, error) {
	return session, nil
}

func (m *mockSymptomCheckerRepository) GetSessionByID(ctx context.Context, id uuid.UUID) (telemedicine.SymptomCheckerSession, error) {
	if m.getSessionByIDFunc != nil {
		return m.getSessionByIDFunc(ctx, id)
	}
	return telemedicine.SymptomCheckerSession{}, domain.ErrNotFound
}

func (m *mockSymptomCheckerRepository) UpdateSessionStatus(ctx context.Context, id uuid.UUID, status telemedicine.SessionStatus) error {
	return nil
}

func (m *mockSymptomCheckerRepository) MarkSessionConverted(ctx context.Context, sessionID uuid.UUID) error {
	if m.markSessionConvertedFunc != nil {
		return m.markSessionConvertedFunc(ctx, sessionID)
	}
	return nil
}

func (m *mockSymptomCheckerRepository) GetLatestEligibleSession(ctx context.Context, patientID uuid.UUID) (telemedicine.EligibleSession, error) {
	if m.getLatestEligibleSessionFunc != nil {
		return m.getLatestEligibleSessionFunc(ctx, patientID)
	}
	return telemedicine.EligibleSession{}, domain.ErrNotFound
}

func (m *mockSymptomCheckerRepository) GetPatientSessions(ctx context.Context, patientID uuid.UUID, limit, offset int) ([]telemedicine.SymptomSessionSummary, error) {
	return nil, nil
}

func (m *mockSymptomCheckerRepository) GetDependentSessions(ctx context.Context, patientID uuid.UUID, dependentID uuid.UUID) ([]telemedicine.DependentSessionSummary, error) {
	return nil, nil
}

func (m *mockSymptomCheckerRepository) GetSessionWithPatientContext(ctx context.Context, sessionID uuid.UUID) (telemedicine.SessionWithPatientContext, error) {
	return telemedicine.SessionWithPatientContext{}, domain.ErrNotFound
}

func (m *mockSymptomCheckerRepository) GetSessionsByTriageLevel(ctx context.Context, triageLevel telemedicine.TriageLevel, from, to time.Time, limit, offset int) ([]telemedicine.AdminSessionSummary, error) {
	return nil, nil
}

func (m *mockSymptomCheckerRepository) CountSessionsByOutcome(ctx context.Context, from, to time.Time) ([]telemedicine.SessionOutcomeCount, error) {
	return nil, nil
}

type mockCacheService struct {
	deletedKeys []string
	store       map[string]interface{}
}

func (m *mockCacheService) Get(ctx context.Context, key string, dest interface{}) error {
	if m.store == nil {
		return cache.ErrCacheMiss
	}
	value, ok := m.store[key]
	if !ok {
		return cache.ErrCacheMiss
	}

	switch target := dest.(type) {
	case *[]string:
		typed, ok := value.([]string)
		if !ok {
			return cache.ErrCacheMiss
		}
		*target = append((*target)[:0], typed...)
		return nil
	default:
		return cache.ErrCacheMiss
	}
}

func (m *mockCacheService) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	if m.store == nil {
		m.store = make(map[string]interface{})
	}
	m.store[key] = value
	return nil
}

func (m *mockCacheService) Delete(ctx context.Context, key string) error {
	m.deletedKeys = append(m.deletedKeys, key)
	if m.store != nil {
		delete(m.store, key)
	}
	return nil
}

func (m *mockCacheService) Exists(ctx context.Context, key string) (bool, error) {
	return false, nil
}

func (m *mockCacheService) Ping(ctx context.Context) error {
	return nil
}

func (m *mockCacheService) IsAvailable() bool {
	return true
}

func newConsultationServiceForTest(t *testing.T) *consultationService {
	t.Helper()
	logger := zerolog.New(io.Discard)
	return &consultationService{
		consultationRepo: &mockConsultationRepository{},
		availabilityRepo: &mockProviderAvailabilityRepository{},
		sessionRepo:      &mockSymptomCheckerRepository{},
		cache:            &mockCacheService{},
		logger:           &logger,
	}
}

func newConsultationServiceWithMocks(t *testing.T) (*consultationService, *mockConsultationRepository, *mockProviderAvailabilityRepository, *mockSymptomCheckerRepository) {
	t.Helper()
	logger := zerolog.New(io.Discard)
	mockConsultationRepo := &mockConsultationRepository{}
	mockAvailabilityRepo := &mockProviderAvailabilityRepository{}
	mockSessionRepo := &mockSymptomCheckerRepository{}

	return &consultationService{
		consultationRepo: mockConsultationRepo,
		availabilityRepo: mockAvailabilityRepo,
		sessionRepo:      mockSessionRepo,
		cache:            &mockCacheService{},
		logger:           &logger,
	}, mockConsultationRepo, mockAvailabilityRepo, mockSessionRepo
}

func newProviderAvailabilityServiceForTest(t *testing.T) *providerAvailabilityService {
	t.Helper()
	logger := zerolog.New(io.Discard)
	return &providerAvailabilityService{
		availabilityRepo: &mockProviderAvailabilityRepository{},
		cache:            &mockCacheService{},
		logger:           &logger,
	}
}

func newProviderAvailabilityServiceWithMocks(t *testing.T) (*providerAvailabilityService, *mockProviderAvailabilityRepository) {
	t.Helper()
	logger := zerolog.New(io.Discard)
	mockAvailabilityRepo := &mockProviderAvailabilityRepository{}

	return &providerAvailabilityService{
		availabilityRepo: mockAvailabilityRepo,
		cache:             &mockCacheService{},
		logger:            &logger,
	}, mockAvailabilityRepo
}

func newConsultationMessagesServiceWithMocks(t *testing.T) (*consultationMessagesService, *mockConsultationMessagesRepository, *mockConsultationRepository, *mockCacheService) {
	t.Helper()
	logger := zerolog.New(io.Discard)
	mockMessagesRepo := &mockConsultationMessagesRepository{}
	mockConsultationRepo := &mockConsultationRepository{}
	cacheSvc := &mockCacheService{}

	return &consultationMessagesService{
		messagesRepo:     mockMessagesRepo,
		consultationRepo: mockConsultationRepo,
		cache:            cacheSvc,
		logger:           &logger,
	}, mockMessagesRepo, mockConsultationRepo, cacheSvc
}

func newConsultationNotesServiceWithMocks(t *testing.T) (*consultationNotesService, *mockConsultationNotesRepository, *mockConsultationRepository, *mockCacheService) {
	t.Helper()
	logger := zerolog.New(io.Discard)
	mockNotesRepo := &mockConsultationNotesRepository{}
	mockConsultationRepo := &mockConsultationRepository{}
	cacheSvc := &mockCacheService{}

	return &consultationNotesService{
		notesRepo:        mockNotesRepo,
		consultationRepo: mockConsultationRepo,
		cache:            cacheSvc,
		logger:           &logger,
	}, mockNotesRepo, mockConsultationRepo, cacheSvc
}

func newSymptomCheckerServiceWithMocks(t *testing.T) (*symptomCheckerService, *mockSymptomCheckerRepository, *mockCacheService) {
	t.Helper()
	logger := zerolog.New(io.Discard)
	mockSessionRepo := &mockSymptomCheckerRepository{}
	cacheSvc := &mockCacheService{}

	return &symptomCheckerService{
		sessionRepo: mockSessionRepo,
		patientRepo: nil,
		aiClient:    nil,
		cache:       cacheSvc,
		logger:      &logger,
	}, mockSessionRepo, cacheSvc
}

func TestConsultationService_RequestConsultation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, mockConsultationRepo, _, mockSessionRepo := newConsultationServiceWithMocks(t)

		patientID := uuid.New()
		sessionID := uuid.New()

		mockConsultationRepo.getPatientActiveConsultationFunc = func(ctx context.Context, pid uuid.UUID) (telemedicine.ActiveConsultationCheck, error) {
			return telemedicine.ActiveConsultationCheck{}, domain.ErrNotFound
		}

		mockSessionRepo.getSessionByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.SymptomCheckerSession, error) {
			return telemedicine.SymptomCheckerSession{
				ID:                 id,
				PatientID:         patientID,
				RecommendedAction: telemedicine.ActionTelemedicine,
				TriageLevel:       telemedicine.TriageMedium,
			}, nil
		}

		mockConsultationRepo.createConsultationFunc = func(ctx context.Context, c telemedicine.Consultation) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{
				ID:                uuid.New(),
				PatientID:        c.PatientID,
				SymptomSessionID:  c.SymptomSessionID,
				Channel:          c.Channel,
				Status:           telemedicine.ConsultationStatusPendingAcceptance,
				FeeCurrency:      "ZAR",
				TriageLevelAtStart: c.TriageLevelAtStart,
			}, nil
		}

		consultation := telemedicine.Consultation{
			PatientID:        patientID,
			SymptomSessionID: sessionID,
			Channel:          telemedicine.ChannelChat,
		}

		result, err := svc.RequestConsultation(context.Background(), consultation)
		require.NoError(t, err)
		assert.Equal(t, telemedicine.ConsultationStatusPendingAcceptance, result.Status)
		assert.NotNil(t, result.TriageLevelAtStart)
	})

	t.Run("patient already has active consultation", func(t *testing.T) {
		svc, _, _, _ := newConsultationServiceWithMocks(t)

		patientID := uuid.New()

		consultationRepo := &mockConsultationRepository{}
		consultationRepo.getPatientActiveConsultationFunc = func(ctx context.Context, pid uuid.UUID) (telemedicine.ActiveConsultationCheck, error) {
			return telemedicine.ActiveConsultationCheck{
				ID:     uuid.New(),
				Status: telemedicine.ConsultationStatusAccepted,
			}, nil
		}
		svc.consultationRepo = consultationRepo

		consultation := telemedicine.Consultation{
			PatientID:        patientID,
			SymptomSessionID: uuid.New(),
			Channel:          telemedicine.ChannelChat,
		}

		_, err := svc.RequestConsultation(context.Background(), consultation)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "patient already has an active consultation")
	})

	t.Run("symptom session not eligible for telemedicine", func(t *testing.T) {
		svc, _, _, _ := newConsultationServiceWithMocks(t)

		patientID := uuid.New()
		sessionID := uuid.New()

		consultationRepo := &mockConsultationRepository{}
		consultationRepo.getPatientActiveConsultationFunc = func(ctx context.Context, pid uuid.UUID) (telemedicine.ActiveConsultationCheck, error) {
			return telemedicine.ActiveConsultationCheck{}, domain.ErrNotFound
		}

		sessionRepo := &mockSymptomCheckerRepository{}
		sessionRepo.getSessionByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.SymptomCheckerSession, error) {
			return telemedicine.SymptomCheckerSession{
				ID:                 id,
				PatientID:         patientID,
				RecommendedAction: telemedicine.ActionEmergency,
				TriageLevel:       telemedicine.TriageHigh,
			}, nil
		}

		svc.consultationRepo = consultationRepo
		svc.sessionRepo = sessionRepo

		consultation := telemedicine.Consultation{
			PatientID:        patientID,
			SymptomSessionID: sessionID,
			Channel:          telemedicine.ChannelChat,
		}

		_, err := svc.RequestConsultation(context.Background(), consultation)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not eligible for telemedicine")
	})

	t.Run("validation error - missing patient ID", func(t *testing.T) {
		svc := newConsultationServiceForTest(t)

		consultation := telemedicine.Consultation{
			SymptomSessionID: uuid.New(),
			Channel:         telemedicine.ChannelChat,
		}

		_, err := svc.RequestConsultation(context.Background(), consultation)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "patient_id is required")
	})

	t.Run("validation error - missing symptom session ID", func(t *testing.T) {
		svc := newConsultationServiceForTest(t)

		consultation := telemedicine.Consultation{
			PatientID: uuid.New(),
			Channel:   telemedicine.ChannelChat,
		}

		_, err := svc.RequestConsultation(context.Background(), consultation)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "symptom_session_id is required")
	})

	t.Run("validation error - invalid channel", func(t *testing.T) {
		svc := newConsultationServiceForTest(t)

		consultation := telemedicine.Consultation{
			PatientID:        uuid.New(),
			SymptomSessionID: uuid.New(),
			Channel:          "invalid_channel",
		}

		_, err := svc.RequestConsultation(context.Background(), consultation)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "channel must be one of")
	})
}

func TestConsultationService_AcceptConsultation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, mockConsultationRepo, mockAvailabilityRepo, _ := newConsultationServiceWithMocks(t)

		consultationID := uuid.New()
		providerStaffID := uuid.New()
		clinicID := uuid.New()

		mockConsultationRepo.getConsultationByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{
				ID:             id,
				Status:         telemedicine.ConsultationStatusPendingAcceptance,
				ProviderStaffID: nil,
			}, nil
		}

		mockAvailabilityRepo.incrementActiveConsultationsFunc = func(ctx context.Context, staffID uuid.UUID) (telemedicine.ProviderAvailability, error) {
			return telemedicine.ProviderAvailability{StaffID: staffID}, nil
		}

		mockConsultationRepo.acceptConsultationFunc = func(ctx context.Context, id uuid.UUID, providerID uuid.UUID, cID uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{
				ID:             id,
				Status:         telemedicine.ConsultationStatusAccepted,
				ProviderStaffID: &providerID,
				ClinicID:       &cID,
			}, nil
		}

		result, err := svc.AcceptConsultation(context.Background(), consultationID, providerStaffID, clinicID)
		require.NoError(t, err)
		assert.Equal(t, telemedicine.ConsultationStatusAccepted, result.Status)
	})

	t.Run("invalidates provider active cache after accept", func(t *testing.T) {
		svc, mockConsultationRepo, mockAvailabilityRepo, _ := newConsultationServiceWithMocks(t)

		consultationID := uuid.New()
		patientID := uuid.New()
		providerStaffID := uuid.New()
		clinicID := uuid.New()
		cacheSvc := &mockCacheService{}
		svc.cache = cacheSvc

		mockConsultationRepo.getConsultationByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{
				ID:       id,
				PatientID: patientID,
				Status:   telemedicine.ConsultationStatusPendingAcceptance,
			}, nil
		}
		mockAvailabilityRepo.incrementActiveConsultationsFunc = func(ctx context.Context, staffID uuid.UUID) (telemedicine.ProviderAvailability, error) {
			return telemedicine.ProviderAvailability{StaffID: staffID}, nil
		}
		mockConsultationRepo.acceptConsultationFunc = func(ctx context.Context, id uuid.UUID, providerID uuid.UUID, cID uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{
				ID:             id,
				PatientID:      patientID,
				Status:         telemedicine.ConsultationStatusAccepted,
				ProviderStaffID: &providerID,
				ClinicID:       &cID,
			}, nil
		}

		_, err := svc.AcceptConsultation(context.Background(), consultationID, providerStaffID, clinicID)
		require.NoError(t, err)
		assert.Contains(t, cacheSvc.deletedKeys, providerActiveConsultationsCacheKey(providerStaffID))
	})

	t.Run("invalidates registered patient consultation history caches", func(t *testing.T) {
		svc, mockConsultationRepo, mockAvailabilityRepo, _ := newConsultationServiceWithMocks(t)

		consultationID := uuid.New()
		patientID := uuid.New()
		providerStaffID := uuid.New()
		clinicID := uuid.New()
		cacheSvc := &mockCacheService{
			store: map[string]interface{}{
				patientConsultationIndexKey(patientID): []string{
					patientConsultationsCacheKey(patientID, 20),
					patientConsultationsCacheKey(patientID, 50),
				},
			},
		}
		svc.cache = cacheSvc

		mockConsultationRepo.getConsultationByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{
				ID:        id,
				PatientID: patientID,
				Status:    telemedicine.ConsultationStatusPendingAcceptance,
			}, nil
		}
		mockAvailabilityRepo.incrementActiveConsultationsFunc = func(ctx context.Context, staffID uuid.UUID) (telemedicine.ProviderAvailability, error) {
			return telemedicine.ProviderAvailability{StaffID: staffID}, nil
		}
		mockConsultationRepo.acceptConsultationFunc = func(ctx context.Context, id uuid.UUID, providerID uuid.UUID, cID uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{
				ID:              id,
				PatientID:       patientID,
				Status:          telemedicine.ConsultationStatusAccepted,
				ProviderStaffID: &providerID,
				ClinicID:        &cID,
			}, nil
		}

		_, err := svc.AcceptConsultation(context.Background(), consultationID, providerStaffID, clinicID)
		require.NoError(t, err)
		assert.Contains(t, cacheSvc.deletedKeys, patientConsultationsCacheKey(patientID, 20))
		assert.Contains(t, cacheSvc.deletedKeys, patientConsultationsCacheKey(patientID, 50))
		assert.Contains(t, cacheSvc.deletedKeys, patientConsultationIndexKey(patientID))
	})

	t.Run("consultation not found", func(t *testing.T) {
		svc, _, _, _ := newConsultationServiceWithMocks(t)

		consultationRepo := &mockConsultationRepository{}
		consultationRepo.getConsultationByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{}, domain.ErrNotFound
		}

		svc.consultationRepo = consultationRepo

		_, err := svc.AcceptConsultation(context.Background(), uuid.New(), uuid.New(), uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "consultation not found")
	})

	t.Run("already accepted by another provider", func(t *testing.T) {
		svc, _, _, _ := newConsultationServiceWithMocks(t)

		existingProviderID := uuid.New()

		consultationRepo := &mockConsultationRepository{}
		consultationRepo.getConsultationByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{
				ID:             id,
				Status:         telemedicine.ConsultationStatusAccepted,
				ProviderStaffID: &existingProviderID,
			}, nil
		}

		svc.consultationRepo = consultationRepo

		_, err := svc.AcceptConsultation(context.Background(), uuid.New(), uuid.New(), uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not pending acceptance")
	})

	t.Run("not in pending acceptance state", func(t *testing.T) {
		svc, _, _, _ := newConsultationServiceWithMocks(t)

		consultationRepo := &mockConsultationRepository{}
		consultationRepo.getConsultationByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{
				ID:     id,
				Status: telemedicine.ConsultationStatusInProgress,
			}, nil
		}

		svc.consultationRepo = consultationRepo

		_, err := svc.AcceptConsultation(context.Background(), uuid.New(), uuid.New(), uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not pending acceptance")
	})
}

func TestConsultationService_StartConsultation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, mockConsultationRepo, _, _ := newConsultationServiceWithMocks(t)

		consultationID := uuid.New()

		mockConsultationRepo.getConsultationByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{
				ID:     id,
				Status: telemedicine.ConsultationStatusAccepted,
			}, nil
		}

		mockConsultationRepo.startConsultationFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{
				ID:     id,
				Status: telemedicine.ConsultationStatusInProgress,
			}, nil
		}

		result, err := svc.StartConsultation(context.Background(), consultationID)
		require.NoError(t, err)
		assert.Equal(t, telemedicine.ConsultationStatusInProgress, result.Status)
	})

	t.Run("consultation not found", func(t *testing.T) {
		svc, _, _, _ := newConsultationServiceWithMocks(t)

		consultationRepo := &mockConsultationRepository{}
		consultationRepo.getConsultationByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{}, domain.ErrNotFound
		}

		svc.consultationRepo = consultationRepo

		_, err := svc.StartConsultation(context.Background(), uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "consultation not found")
	})

	t.Run("not in accepted state", func(t *testing.T) {
		svc, _, _, _ := newConsultationServiceWithMocks(t)

		consultationRepo := &mockConsultationRepository{}
		consultationRepo.getConsultationByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{
				ID:     id,
				Status: telemedicine.ConsultationStatusPendingAcceptance,
			}, nil
		}

		svc.consultationRepo = consultationRepo

		_, err := svc.StartConsultation(context.Background(), uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be in 'accepted' state")
	})

	t.Run("already in progress", func(t *testing.T) {
		svc, _, _, _ := newConsultationServiceWithMocks(t)

		consultationRepo := &mockConsultationRepository{}
		consultationRepo.getConsultationByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{
				ID:     id,
				Status: telemedicine.ConsultationStatusInProgress,
			}, nil
		}

		svc.consultationRepo = consultationRepo

		_, err := svc.StartConsultation(context.Background(), uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be in 'accepted' state")
	})
}

func TestConsultationService_CompleteConsultation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, mockConsultationRepo, mockAvailabilityRepo, _ := newConsultationServiceWithMocks(t)

		consultationID := uuid.New()
		providerStaffID := uuid.New()
		endedBy := uuid.New()

		mockConsultationRepo.getConsultationByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{
				ID:             id,
				Status:         telemedicine.ConsultationStatusInProgress,
				ProviderStaffID: &providerStaffID,
			}, nil
		}

		mockConsultationRepo.completeConsultationFunc = func(ctx context.Context, id uuid.UUID, endedByID uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{
				ID:     id,
				Status: telemedicine.ConsultationStatusCompleted,
			}, nil
		}

		mockAvailabilityRepo.decrementActiveConsultationsFunc = func(ctx context.Context, staffID uuid.UUID) error {
			return nil
		}

		result, err := svc.CompleteConsultation(context.Background(), consultationID, endedBy)
		require.NoError(t, err)
		assert.Equal(t, telemedicine.ConsultationStatusCompleted, result.Status)
	})

	t.Run("invalidates provider active cache after completion", func(t *testing.T) {
		svc, mockConsultationRepo, mockAvailabilityRepo, _ := newConsultationServiceWithMocks(t)

		consultationID := uuid.New()
		patientID := uuid.New()
		providerStaffID := uuid.New()
		endedBy := uuid.New()
		cacheSvc := &mockCacheService{}
		svc.cache = cacheSvc

		mockConsultationRepo.getConsultationByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{
				ID:             id,
				PatientID:      patientID,
				Status:         telemedicine.ConsultationStatusInProgress,
				ProviderStaffID: &providerStaffID,
			}, nil
		}
		mockConsultationRepo.completeConsultationFunc = func(ctx context.Context, id uuid.UUID, endedBy uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{
				ID:             id,
				PatientID:      patientID,
				Status:         telemedicine.ConsultationStatusCompleted,
				ProviderStaffID: &providerStaffID,
			}, nil
		}
		mockAvailabilityRepo.decrementActiveConsultationsFunc = func(ctx context.Context, staffID uuid.UUID) error {
			return nil
		}

		_, err := svc.CompleteConsultation(context.Background(), consultationID, endedBy)
		require.NoError(t, err)
		assert.Contains(t, cacheSvc.deletedKeys, providerActiveConsultationsCacheKey(providerStaffID))
	})

	t.Run("consultation not found", func(t *testing.T) {
		svc, _, _, _ := newConsultationServiceWithMocks(t)

		consultationRepo := &mockConsultationRepository{}
		consultationRepo.getConsultationByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{}, domain.ErrNotFound
		}

		svc.consultationRepo = consultationRepo

		_, err := svc.CompleteConsultation(context.Background(), uuid.New(), uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "consultation not found")
	})

	t.Run("not in progress state", func(t *testing.T) {
		svc, _, _, _ := newConsultationServiceWithMocks(t)

		consultationRepo := &mockConsultationRepository{}
		consultationRepo.getConsultationByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{
				ID:     id,
				Status: telemedicine.ConsultationStatusAccepted,
			}, nil
		}

		svc.consultationRepo = consultationRepo

		_, err := svc.CompleteConsultation(context.Background(), uuid.New(), uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be in_progress")
	})

	t.Run("consultation already completed", func(t *testing.T) {
		svc, _, _, _ := newConsultationServiceWithMocks(t)

		consultationRepo := &mockConsultationRepository{}
		consultationRepo.getConsultationByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{
				ID:     id,
				Status: telemedicine.ConsultationStatusCompleted,
			}, nil
		}

		svc.consultationRepo = consultationRepo

		_, err := svc.CompleteConsultation(context.Background(), uuid.New(), uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be in_progress")
	})
}

func TestConsultationService_UpdatePaymentStatus(t *testing.T) {
	t.Run("invalidates patient and provider caches", func(t *testing.T) {
		svc, mockConsultationRepo, _, _ := newConsultationServiceWithMocks(t)

		consultationID := uuid.New()
		patientID := uuid.New()
		providerStaffID := uuid.New()
		cacheSvc := &mockCacheService{
			store: map[string]interface{}{
				patientConsultationIndexKey(patientID): []string{
					patientConsultationsCacheKey(patientID, 20),
					patientConsultationsCacheKey(patientID, 50),
				},
			},
		}
		svc.cache = cacheSvc

		mockConsultationRepo.getConsultationByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{
				ID:              id,
				PatientID:       patientID,
				ProviderStaffID: &providerStaffID,
			}, nil
		}
		mockConsultationRepo.updatePaymentStatusFunc = func(ctx context.Context, id uuid.UUID, status telemedicine.PaymentStatus, reference *string) error {
			return nil
		}

		err := svc.UpdatePaymentStatus(context.Background(), consultationID, telemedicine.PaymentStatusPaid, nil)
		require.NoError(t, err)
		assert.Contains(t, cacheSvc.deletedKeys, patientConsultationsCacheKey(patientID, 20))
		assert.Contains(t, cacheSvc.deletedKeys, patientConsultationsCacheKey(patientID, 50))
		assert.Contains(t, cacheSvc.deletedKeys, providerActiveConsultationsCacheKey(providerStaffID))
	})
}

func TestConsultationService_UpdateConsultationChannel(t *testing.T) {
	t.Run("invalidates waiting room and patient history caches", func(t *testing.T) {
		svc, mockConsultationRepo, _, _ := newConsultationServiceWithMocks(t)

		consultationID := uuid.New()
		patientID := uuid.New()
		cacheSvc := &mockCacheService{
			store: map[string]interface{}{
				patientConsultationIndexKey(patientID): []string{
					patientConsultationsCacheKey(patientID, 20),
				},
			},
		}
		svc.cache = cacheSvc

		mockConsultationRepo.getConsultationByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{
				ID:        id,
				PatientID: patientID,
				Status:    telemedicine.ConsultationStatusPendingAcceptance,
			}, nil
		}
		mockConsultationRepo.updateConsultationChannelFunc = func(ctx context.Context, id uuid.UUID, channel telemedicine.ConsultationChannel) error {
			return nil
		}

		err := svc.UpdateConsultationChannel(context.Background(), consultationID, telemedicine.ChannelVideo)
		require.NoError(t, err)
		assert.Contains(t, cacheSvc.deletedKeys, "consultation:waiting_room")
		assert.Contains(t, cacheSvc.deletedKeys, patientConsultationsCacheKey(patientID, 20))
	})
}

func TestConsultationService_EscalateConsultation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, mockConsultationRepo, mockAvailabilityRepo, _ := newConsultationServiceWithMocks(t)

		consultationID := uuid.New()
		providerStaffID := uuid.New()
		endedBy := uuid.New()

		mockConsultationRepo.getConsultationByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{
				ID:             id,
				Status:         telemedicine.ConsultationStatusInProgress,
				ProviderStaffID: &providerStaffID,
			}, nil
		}

		mockConsultationRepo.escalateConsultationFunc = func(ctx context.Context, id uuid.UUID, endedByID uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{
				ID:     id,
				Status: telemedicine.ConsultationStatusEscalated,
			}, nil
		}

		mockAvailabilityRepo.decrementActiveConsultationsFunc = func(ctx context.Context, staffID uuid.UUID) error {
			return nil
		}

		result, err := svc.EscalateConsultation(context.Background(), consultationID, endedBy)
		require.NoError(t, err)
		assert.Equal(t, telemedicine.ConsultationStatusEscalated, result.Status)
	})

	t.Run("success from accepted state", func(t *testing.T) {
		svc, mockConsultationRepo, mockAvailabilityRepo, _ := newConsultationServiceWithMocks(t)

		consultationID := uuid.New()
		providerStaffID := uuid.New()
		endedBy := uuid.New()

		mockConsultationRepo.getConsultationByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{
				ID:             id,
				Status:         telemedicine.ConsultationStatusAccepted,
				ProviderStaffID: &providerStaffID,
			}, nil
		}

		mockConsultationRepo.escalateConsultationFunc = func(ctx context.Context, id uuid.UUID, endedByID uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{
				ID:     id,
				Status: telemedicine.ConsultationStatusEscalated,
			}, nil
		}

		mockAvailabilityRepo.decrementActiveConsultationsFunc = func(ctx context.Context, staffID uuid.UUID) error {
			return nil
		}

		result, err := svc.EscalateConsultation(context.Background(), consultationID, endedBy)
		require.NoError(t, err)
		assert.Equal(t, telemedicine.ConsultationStatusEscalated, result.Status)
	})

	t.Run("consultation not found", func(t *testing.T) {
		svc, _, _, _ := newConsultationServiceWithMocks(t)

		consultationRepo := &mockConsultationRepository{}
		consultationRepo.getConsultationByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{}, domain.ErrNotFound
		}

		svc.consultationRepo = consultationRepo

		_, err := svc.EscalateConsultation(context.Background(), uuid.New(), uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "consultation not found")
	})

	t.Run("cannot escalate completed consultation", func(t *testing.T) {
		svc, _, _, _ := newConsultationServiceWithMocks(t)

		consultationRepo := &mockConsultationRepository{}
		consultationRepo.getConsultationByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{
				ID:     id,
				Status: telemedicine.ConsultationStatusCompleted,
			}, nil
		}

		svc.consultationRepo = consultationRepo

		_, err := svc.EscalateConsultation(context.Background(), uuid.New(), uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot escalate")
	})
}

func TestProviderAvailabilityService_GoOnline(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, mockAvailRepo := newProviderAvailabilityServiceWithMocks(t)

		staffID := uuid.New()

		mockAvailRepo.upsertAvailabilityFunc = func(ctx context.Context, sID uuid.UUID) (telemedicine.ProviderAvailability, error) {
			return telemedicine.ProviderAvailability{StaffID: sID}, nil
		}

		mockAvailRepo.goOnlineFunc = func(ctx context.Context, sID uuid.UUID) (telemedicine.ProviderAvailability, error) {
			return telemedicine.ProviderAvailability{
				StaffID:  sID,
				IsOnline: true,
			}, nil
		}

		result, err := svc.GoOnline(context.Background(), staffID)
		require.NoError(t, err)
		assert.True(t, result.IsOnline)
	})

	t.Run("success - first time going online", func(t *testing.T) {
		svc, mockAvailRepo := newProviderAvailabilityServiceWithMocks(t)

		staffID := uuid.New()

		mockAvailRepo.upsertAvailabilityFunc = func(ctx context.Context, sID uuid.UUID) (telemedicine.ProviderAvailability, error) {
			return telemedicine.ProviderAvailability{StaffID: sID}, nil
		}

		mockAvailRepo.goOnlineFunc = func(ctx context.Context, sID uuid.UUID) (telemedicine.ProviderAvailability, error) {
			return telemedicine.ProviderAvailability{
				StaffID:  sID,
				IsOnline: true,
			}, nil
		}

		result, err := svc.GoOnline(context.Background(), staffID)
		require.NoError(t, err)
		assert.True(t, result.IsOnline)
	})

	t.Run("provider already online", func(t *testing.T) {
		svc, mockAvailRepo := newProviderAvailabilityServiceWithMocks(t)

		staffID := uuid.New()

		mockAvailRepo.upsertAvailabilityFunc = func(ctx context.Context, sID uuid.UUID) (telemedicine.ProviderAvailability, error) {
			return telemedicine.ProviderAvailability{StaffID: sID}, nil
		}

		mockAvailRepo.goOnlineFunc = func(ctx context.Context, sID uuid.UUID) (telemedicine.ProviderAvailability, error) {
			return telemedicine.ProviderAvailability{
				StaffID:  sID,
				IsOnline: true,
			}, nil
		}

		result, err := svc.GoOnline(context.Background(), staffID)
		require.NoError(t, err)
		assert.True(t, result.IsOnline)
	})

	t.Run("validation error - missing staff ID", func(t *testing.T) {
		svc := newProviderAvailabilityServiceForTest(t)

		_, err := svc.GoOnline(context.Background(), uuid.Nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "staff_id is required")
	})

	t.Run("invalidates registered filtered availability caches", func(t *testing.T) {
		svc, mockAvailRepo := newProviderAvailabilityServiceWithMocks(t)

		staffID := uuid.New()
		cacheSvc := &mockCacheService{
			store: map[string]interface{}{
				availableProvidersRegistryKey(): []string{
					availableProvidersCacheKey(nil),
					availableProvidersCacheKey(&staffID),
				},
				availableProvidersBySpecRegistryKey(): []string{
					availableProvidersBySpecCacheKey("gp"),
				},
			},
		}
		svc.cache = cacheSvc

		mockAvailRepo.upsertAvailabilityFunc = func(ctx context.Context, sID uuid.UUID) (telemedicine.ProviderAvailability, error) {
			return telemedicine.ProviderAvailability{StaffID: sID}, nil
		}
		mockAvailRepo.goOnlineFunc = func(ctx context.Context, sID uuid.UUID) (telemedicine.ProviderAvailability, error) {
			return telemedicine.ProviderAvailability{StaffID: sID, IsOnline: true}, nil
		}

		_, err := svc.GoOnline(context.Background(), staffID)
		require.NoError(t, err)
		assert.Contains(t, cacheSvc.deletedKeys, availableProvidersRegistryKey())
		assert.Contains(t, cacheSvc.deletedKeys, availableProvidersBySpecRegistryKey())
		assert.Contains(t, cacheSvc.deletedKeys, availableProvidersBySpecCacheKey("gp"))
	})
}

func TestProviderAvailabilityService_GoOffline(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, mockAvailRepo := newProviderAvailabilityServiceWithMocks(t)

		staffID := uuid.New()

		mockAvailRepo.goOfflineFunc = func(ctx context.Context, sID uuid.UUID) error {
			return nil
		}

		err := svc.GoOffline(context.Background(), staffID)
		require.NoError(t, err)
	})

	t.Run("success - provider never existed", func(t *testing.T) {
		svc, mockAvailRepo := newProviderAvailabilityServiceWithMocks(t)

		staffID := uuid.New()

		mockAvailRepo.goOfflineFunc = func(ctx context.Context, sID uuid.UUID) error {
			return domain.ErrNotFound
		}

		err := svc.GoOffline(context.Background(), staffID)
		require.NoError(t, err)
	})

	t.Run("has active consultations - should warn", func(t *testing.T) {
		svc, mockAvailRepo := newProviderAvailabilityServiceWithMocks(t)

		staffID := uuid.New()

		mockAvailRepo.goOfflineFunc = func(ctx context.Context, sID uuid.UUID) error {
			return nil
		}

		err := svc.GoOffline(context.Background(), staffID)
		require.NoError(t, err)
	})

	t.Run("validation error - missing staff ID", func(t *testing.T) {
		svc := newProviderAvailabilityServiceForTest(t)

		err := svc.GoOffline(context.Background(), uuid.Nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "staff_id is required")
	})
}

func TestConsultationMessagesService_SendMessage(t *testing.T) {
	t.Run("invalidates unread cache for sender role", func(t *testing.T) {
		svc, mockMessagesRepo, mockConsultationRepo, cacheSvc := newConsultationMessagesServiceWithMocks(t)

		consultationID := uuid.New()
		senderID := uuid.New()
		content := "hello"

		mockConsultationRepo.getConsultationByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{ID: id, Status: telemedicine.ConsultationStatusAccepted}, nil
		}
		mockMessagesRepo.insertMessageFunc = func(ctx context.Context, msg telemedicine.ConsultationMessage) (telemedicine.ConsultationMessage, error) {
			return telemedicine.ConsultationMessage{
				ID:             uuid.New(),
				ConsultationID: msg.ConsultationID,
				SenderUserID:   msg.SenderUserID,
				SenderRole:     msg.SenderRole,
				MessageType:    msg.MessageType,
				Content:        msg.Content,
			}, nil
		}

		_, err := svc.SendMessage(context.Background(), telemedicine.ConsultationMessage{
			ConsultationID: consultationID,
			SenderUserID:   senderID,
			SenderRole:     telemedicine.SenderRolePatient,
			MessageType:    telemedicine.MessageTypeText,
			Content:        &content,
		})
		require.NoError(t, err)
		assert.Contains(t, cacheSvc.deletedKeys, unreadCountCacheKey(consultationID, telemedicine.SenderRolePatient))
	})

	t.Run("invalidates registered thread cache keys across limits", func(t *testing.T) {
		svc, mockMessagesRepo, mockConsultationRepo, cacheSvc := newConsultationMessagesServiceWithMocks(t)

		consultationID := uuid.New()
		senderID := uuid.New()
		content := "hello"
		cacheSvc.store = map[string]interface{}{
			messageThreadIndexKey(consultationID): []string{
				messageThreadCacheKey(consultationID, 20),
				messageThreadCacheKey(consultationID, 50),
			},
		}

		mockConsultationRepo.getConsultationByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{ID: id, Status: telemedicine.ConsultationStatusAccepted}, nil
		}
		mockMessagesRepo.insertMessageFunc = func(ctx context.Context, msg telemedicine.ConsultationMessage) (telemedicine.ConsultationMessage, error) {
			return telemedicine.ConsultationMessage{
				ID:             uuid.New(),
				ConsultationID: msg.ConsultationID,
				SenderUserID:   msg.SenderUserID,
				SenderRole:     msg.SenderRole,
				MessageType:    msg.MessageType,
				Content:        msg.Content,
			}, nil
		}

		_, err := svc.SendMessage(context.Background(), telemedicine.ConsultationMessage{
			ConsultationID: consultationID,
			SenderUserID:   senderID,
			SenderRole:     telemedicine.SenderRolePatient,
			MessageType:    telemedicine.MessageTypeText,
			Content:        &content,
		})
		require.NoError(t, err)
		assert.Contains(t, cacheSvc.deletedKeys, messageThreadCacheKey(consultationID, 20))
		assert.Contains(t, cacheSvc.deletedKeys, messageThreadCacheKey(consultationID, 50))
		assert.Contains(t, cacheSvc.deletedKeys, messageThreadIndexKey(consultationID))
	})
}

func TestConsultationMessagesService_DeleteMessage(t *testing.T) {
	t.Run("invalidates unread cache for deleted sender role", func(t *testing.T) {
		svc, mockMessagesRepo, _, cacheSvc := newConsultationMessagesServiceWithMocks(t)

		messageID := uuid.New()
		consultationID := uuid.New()
		senderID := uuid.New()

		mockMessagesRepo.getMessageByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.ConsultationMessage, error) {
			return telemedicine.ConsultationMessage{
				ID:             id,
				ConsultationID: consultationID,
				SenderUserID:   senderID,
				SenderRole:     telemedicine.SenderRoleProvider,
				MessageType:    telemedicine.MessageTypeText,
			}, nil
		}
		mockMessagesRepo.softDeleteMessageFunc = func(ctx context.Context, id uuid.UUID) error {
			return nil
		}

		err := svc.DeleteMessage(context.Background(), messageID, senderID)
		require.NoError(t, err)
		assert.Contains(t, cacheSvc.deletedKeys, unreadCountCacheKey(consultationID, telemedicine.SenderRoleProvider))
	})
}

func TestConsultationMessagesService_MarkMessageRead(t *testing.T) {
	t.Run("invalidates unread cache for message sender role", func(t *testing.T) {
		svc, mockMessagesRepo, _, cacheSvc := newConsultationMessagesServiceWithMocks(t)

		messageID := uuid.New()
		consultationID := uuid.New()

		mockMessagesRepo.getMessageByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.ConsultationMessage, error) {
			return telemedicine.ConsultationMessage{
				ID:             id,
				ConsultationID: consultationID,
				SenderRole:     telemedicine.SenderRoleProvider,
			}, nil
		}
		mockMessagesRepo.markMessageReadFunc = func(ctx context.Context, id uuid.UUID) error {
			return nil
		}

		err := svc.MarkMessageRead(context.Background(), messageID)
		require.NoError(t, err)
		assert.Contains(t, cacheSvc.deletedKeys, unreadCountCacheKey(consultationID, telemedicine.SenderRoleProvider))
	})
}

func TestConsultationNotesService_CreateNote(t *testing.T) {
	t.Run("invalidates patient note history cache", func(t *testing.T) {
		svc, mockNotesRepo, mockConsultationRepo, cacheSvc := newConsultationNotesServiceWithMocks(t)

		consultationID := uuid.New()
		patientID := uuid.New()
		staffID := uuid.New()

		mockConsultationRepo.getConsultationByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{ID: id, PatientID: patientID, Status: telemedicine.ConsultationStatusAccepted}, nil
		}
		mockNotesRepo.noteExistsForConsultationFunc = func(ctx context.Context, id uuid.UUID) (bool, error) {
			return false, nil
		}
		mockNotesRepo.createNoteFunc = func(ctx context.Context, cID uuid.UUID, authoredByStaffID uuid.UUID) (telemedicine.ConsultationNote, error) {
			return telemedicine.ConsultationNote{ID: uuid.New(), ConsultationID: cID, AuthoredByStaffID: authoredByStaffID}, nil
		}

		_, err := svc.CreateNote(context.Background(), consultationID, staffID)
		require.NoError(t, err)
		assert.Contains(t, cacheSvc.deletedKeys, patientNoteHistoryCacheKey(patientID))
	})
}

func TestConsultationNotesService_FinaliseNote(t *testing.T) {
	t.Run("invalidates registered provider history caches and patient history", func(t *testing.T) {
		svc, mockNotesRepo, mockConsultationRepo, cacheSvc := newConsultationNotesServiceWithMocks(t)

		noteID := uuid.New()
		consultationID := uuid.New()
		patientID := uuid.New()
		staffID := uuid.New()
		cacheSvc.store = map[string]interface{}{
			providerNoteHistoryIndexKey(staffID): []string{
				providerNoteHistoryCacheKey(staffID, 20),
				providerNoteHistoryCacheKey(staffID, 50),
			},
		}

		mockNotesRepo.getNoteByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.ConsultationNote, error) {
			return telemedicine.ConsultationNote{ID: id, ConsultationID: consultationID, AuthoredByStaffID: staffID}, nil
		}
		mockNotesRepo.finaliseNoteFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.ConsultationNote, error) {
			return telemedicine.ConsultationNote{ID: id, ConsultationID: consultationID, AuthoredByStaffID: staffID, IsFinalised: true}, nil
		}
		mockConsultationRepo.getConsultationByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
			return telemedicine.Consultation{ID: id, PatientID: patientID}, nil
		}

		_, err := svc.FinaliseNote(context.Background(), noteID, staffID)
		require.NoError(t, err)
		assert.Contains(t, cacheSvc.deletedKeys, providerNoteHistoryCacheKey(staffID, 20))
		assert.Contains(t, cacheSvc.deletedKeys, providerNoteHistoryCacheKey(staffID, 50))
		assert.Contains(t, cacheSvc.deletedKeys, providerNoteHistoryIndexKey(staffID))
		assert.Contains(t, cacheSvc.deletedKeys, patientNoteHistoryCacheKey(patientID))
	})
}

func TestSymptomCheckerService_MarkSessionConverted(t *testing.T) {
	t.Run("invalidates registered patient session history caches", func(t *testing.T) {
		svc, mockSessionRepo, cacheSvc := newSymptomCheckerServiceWithMocks(t)

		sessionID := uuid.New()
		patientID := uuid.New()
		cacheSvc.store = map[string]interface{}{
			patientSessionIndexKey(patientID): []string{
				patientSessionsCacheKey(patientID, 20),
				patientSessionsCacheKey(patientID, 50),
			},
		}

		mockSessionRepo.getSessionByIDFunc = func(ctx context.Context, id uuid.UUID) (telemedicine.SymptomCheckerSession, error) {
			return telemedicine.SymptomCheckerSession{
				ID:        id,
				PatientID: patientID,
				Status:    telemedicine.StatusCompleted,
			}, nil
		}
		mockSessionRepo.markSessionConvertedFunc = func(ctx context.Context, id uuid.UUID) error {
			return nil
		}

		err := svc.MarkSessionConverted(context.Background(), sessionID)
		require.NoError(t, err)
		assert.Contains(t, cacheSvc.deletedKeys, patientSessionsCacheKey(patientID, 20))
		assert.Contains(t, cacheSvc.deletedKeys, patientSessionsCacheKey(patientID, 50))
		assert.Contains(t, cacheSvc.deletedKeys, patientSessionIndexKey(patientID))
	})
}

var _ repository.ConsultationRepository = (*mockConsultationRepository)(nil)
var _ repository.ConsultationNotesRepository = (*mockConsultationNotesRepository)(nil)
var _ repository.ConsultationMessagesRepository = (*mockConsultationMessagesRepository)(nil)
var _ repository.ProviderAvailabilityRepository = (*mockProviderAvailabilityRepository)(nil)
var _ repository.SymptomCheckerRepository = (*mockSymptomCheckerRepository)(nil)
var _ cache.Service = (*mockCacheService)(nil)
