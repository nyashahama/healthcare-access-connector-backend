// Package mock provides a mock email provider for testing
package mock

import (
	"context"
	"sync"

	emailtypes "github.com/nyashahama/healthcare-access-connector-backend/internal/email/types"
)

// Provider implements a mock email provider
type Provider struct {
	mu         sync.RWMutex
	sentEmails []*emailtypes.Message
	available  bool
	shouldFail bool
	failureErr error
	healthErr  error
}

// New creates a new mock provider
func New() *Provider {
	return &Provider{
		sentEmails: make([]*emailtypes.Message, 0),
		available:  true,
	}
}

// Send records the email message
func (p *Provider) Send(ctx context.Context, msg *emailtypes.Message) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.available {
		return emailtypes.ErrServiceUnavailable
	}

	if p.shouldFail {
		if p.failureErr != nil {
			return p.failureErr
		}
		return emailtypes.ErrSendFailed
	}

	if len(msg.To) == 0 {
		return emailtypes.ErrNoRecipients
	}

	// Create a copy of the message
	msgCopy := &emailtypes.Message{
		To:       append([]string{}, msg.To...),
		CC:       append([]string{}, msg.CC...),
		BCC:      append([]string{}, msg.BCC...),
		Subject:  msg.Subject,
		Body:     msg.Body,
		HTMLBody: msg.HTMLBody,
		ReplyTo:  msg.ReplyTo,
		Template: msg.Template,
	}

	p.sentEmails = append(p.sentEmails, msgCopy)
	return nil
}

// IsAvailable returns the availability status
func (p *Provider) IsAvailable() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.available
}

// Name returns the provider name
func (p *Provider) Name() string {
	return "mock"
}

// HealthCheck performs a mock health check
func (p *Provider) HealthCheck(ctx context.Context) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.healthErr != nil {
		return p.healthErr
	}

	if !p.available {
		return emailtypes.ErrServiceUnavailable
	}

	return nil
}

// Close does nothing for mock provider
func (p *Provider) Close() error {
	return nil
}

// GetSentEmails returns all sent emails
func (p *Provider) GetSentEmails() []*emailtypes.Message {
	p.mu.RLock()
	defer p.mu.RUnlock()

	emails := make([]*emailtypes.Message, len(p.sentEmails))
	copy(emails, p.sentEmails)
	return emails
}

// GetLastEmail returns the last sent email
func (p *Provider) GetLastEmail() *emailtypes.Message {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if len(p.sentEmails) == 0 {
		return nil
	}

	return p.sentEmails[len(p.sentEmails)-1]
}

// Reset clears all sent emails and resets state
func (p *Provider) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.sentEmails = make([]*emailtypes.Message, 0)
	p.available = true
	p.shouldFail = false
	p.failureErr = nil
	p.healthErr = nil
}

// SetAvailable sets the availability status
func (p *Provider) SetAvailable(available bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.available = available
}

// SetShouldFail sets whether sends should fail
func (p *Provider) SetShouldFail(shouldFail bool, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.shouldFail = shouldFail
	p.failureErr = err
}

// SetHealthCheckError sets the health check error
func (p *Provider) SetHealthCheckError(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.healthErr = err
}

// EmailCount returns the number of sent emails
func (p *Provider) EmailCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.sentEmails)
}
