package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type otpSMSSender interface {
	IsAvailable() bool
	SendOTP(ctx context.Context, phoneNumber, otp string) (*otpSMSDelivery, error)
}

type otpSMSDelivery struct {
	MessageBody     string
	TwilioMessageID *string
	TwilioStatus    *string
	SentAt          *time.Time
	Segments        int
	Cost            *float64
	CostCurrency    string
}

type twilioOTPSender struct {
	accountSID string
	authToken  string
	fromNumber string
	client     *http.Client
}

func newTwilioOTPSenderFromEnv() otpSMSSender {
	provider := strings.ToLower(strings.TrimSpace(os.Getenv("SMS_PROVIDER")))
	if provider != "twilio" {
		return nil
	}

	accountSID := strings.TrimSpace(os.Getenv("TWILIO_ACCOUNT_SID"))
	authToken := strings.TrimSpace(os.Getenv("TWILIO_AUTH_TOKEN"))
	fromNumber := strings.TrimSpace(os.Getenv("TWILIO_FROM_NUMBER"))

	timeout := 30 * time.Second
	if rawTimeout := strings.TrimSpace(os.Getenv("HTTP_CLIENT_TIMEOUT")); rawTimeout != "" {
		if parsed, err := time.ParseDuration(rawTimeout); err == nil && parsed > 0 {
			timeout = parsed
		}
	}

	return &twilioOTPSender{
		accountSID: accountSID,
		authToken:  authToken,
		fromNumber: fromNumber,
		client:     &http.Client{Timeout: timeout},
	}
}

func (s *twilioOTPSender) IsAvailable() bool {
	return s != nil && s.accountSID != "" && s.authToken != "" && s.fromNumber != "" && s.client != nil
}

func (s *twilioOTPSender) SendOTP(ctx context.Context, phoneNumber, otp string) (*otpSMSDelivery, error) {
	if !s.IsAvailable() {
		return nil, fmt.Errorf("twilio sms sender is not configured")
	}

	bodyText := fmt.Sprintf("Your Healthcare Access Connector verification code is %s. It expires in 10 minutes.", otp)
	form := url.Values{}
	form.Set("To", phoneNumber)
	form.Set("From", s.fromNumber)
	form.Set("Body", bodyText)

	endpoint := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", s.accountSID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build twilio request: %w", err)
	}

	req.SetBasicAuth(s.accountSID, s.authToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send twilio request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, fmt.Errorf("read twilio response: %w", err)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		var apiErr struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(body, &apiErr); err == nil && apiErr.Message != "" {
			return nil, fmt.Errorf("twilio sms request failed: %s", apiErr.Message)
		}
		return nil, fmt.Errorf("twilio sms request failed: status %d", resp.StatusCode)
	}

	var apiResp struct {
		Sid    string `json:"sid"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("decode twilio response: %w", err)
	}

	var sidPtr *string
	if apiResp.Sid != "" {
		sidPtr = &apiResp.Sid
	}

	var statusPtr *string
	if apiResp.Status != "" {
		statusPtr = &apiResp.Status
	}

	sentAt := time.Now().UTC()

	return &otpSMSDelivery{
		MessageBody:     bodyText,
		TwilioMessageID: sidPtr,
		TwilioStatus:    statusPtr,
		SentAt:          &sentAt,
		Segments:        1,
	}, nil
}
