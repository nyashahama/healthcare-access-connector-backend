package sms

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	domainsms "github.com/nyashahama/healthcare-access-connector-backend/internal/domain/sms"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
)

type smsService struct {
	repo repository.SMSRepository
}

func NewSMSService(repo repository.SMSRepository) service.SMSService {
	return &smsService{repo: repo}
}

func (s *smsService) CreateConversation(ctx context.Context, conv domainsms.SMSConversation) (domainsms.SMSConversation, error) {
	repo, err := s.repositoryOrError()
	if err != nil {
		return domainsms.SMSConversation{}, err
	}
	return repo.CreateConversation(ctx, conv)
}

func (s *smsService) GetConversation(ctx context.Context, id uuid.UUID) (domainsms.SMSConversation, error) {
	repo, err := s.repositoryOrError()
	if err != nil {
		return domainsms.SMSConversation{}, err
	}
	return repo.GetConversation(ctx, id)
}

func (s *smsService) GetConversationByPhone(ctx context.Context, phone string) (domainsms.SMSConversation, error) {
	repo, err := s.repositoryOrError()
	if err != nil {
		return domainsms.SMSConversation{}, err
	}
	return repo.GetConversationByPhone(ctx, phone)
}

func (s *smsService) GetConversationByUserID(ctx context.Context, userID uuid.UUID) (domainsms.SMSConversation, error) {
	repo, err := s.repositoryOrError()
	if err != nil {
		return domainsms.SMSConversation{}, err
	}
	return repo.GetConversationByUserID(ctx, userID)
}

func (s *smsService) UpdateConversation(ctx context.Context, conv domainsms.SMSConversation) error {
	repo, err := s.repositoryOrError()
	if err != nil {
		return err
	}
	return repo.UpdateConversation(ctx, conv)
}

func (s *smsService) CloseConversation(ctx context.Context, id uuid.UUID, reason string) error {
	repo, err := s.repositoryOrError()
	if err != nil {
		return err
	}
	return repo.CloseConversation(ctx, id, reason)
}

func (s *smsService) GetActiveConversations(ctx context.Context) ([]domainsms.SMSConversation, error) {
	repo, err := s.repositoryOrError()
	if err != nil {
		return nil, err
	}
	return repo.GetActiveConversations(ctx)
}

func (s *smsService) LogMessage(ctx context.Context, msg domainsms.SMSMessage) (domainsms.SMSMessage, error) {
	repo, err := s.repositoryOrError()
	if err != nil {
		return domainsms.SMSMessage{}, err
	}
	return repo.LogMessage(ctx, msg)
}

func (s *smsService) GetMessage(ctx context.Context, id uuid.UUID) (domainsms.SMSMessage, error) {
	repo, err := s.repositoryOrError()
	if err != nil {
		return domainsms.SMSMessage{}, err
	}
	return repo.GetMessage(ctx, id)
}

func (s *smsService) GetConversationMessages(ctx context.Context, conversationID uuid.UUID, limit, offset int) ([]domainsms.SMSMessage, error) {
	repo, err := s.repositoryOrError()
	if err != nil {
		return nil, err
	}
	return repo.GetConversationMessages(ctx, conversationID, limit, offset)
}

func (s *smsService) GetFailedMessages(ctx context.Context, startDate, endDate time.Time) ([]domainsms.SMSMessage, error) {
	repo, err := s.repositoryOrError()
	if err != nil {
		return nil, err
	}
	return repo.GetFailedMessages(ctx, startDate, endDate)
}

func (s *smsService) ArchiveOldMessages(ctx context.Context, olderThan time.Duration) error {
	repo, err := s.repositoryOrError()
	if err != nil {
		return err
	}
	return repo.ArchiveOldMessages(ctx, olderThan)
}

func (s *smsService) ExportConversation(ctx context.Context, conversationID uuid.UUID) ([]byte, error) {
	repo, err := s.repositoryOrError()
	if err != nil {
		return nil, err
	}
	return repo.ExportConversation(ctx, conversationID)
}

func (s *smsService) repositoryOrError() (repository.SMSRepository, error) {
	if s == nil || s.repo == nil {
		return nil, domain.NewAppError(
			domain.ErrServiceNotAvailable,
			"SMS service repository is not configured",
			503,
		)
	}
	return s.repo, nil
}
