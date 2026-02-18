// Package ai provides an AI client for symptom summarization via HuggingFace router
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog"
)

const (
	huggingFaceRouterURL = "https://router.huggingface.co/v1/chat/completions"
	defaultModel         = "openai/gpt-oss-20b:fastest"
)

// Client is the interface for AI operations
type Client interface {
	// SummarizeSymptoms takes a list of raw symptom inputs from the patient
	// and returns a structured clinical summary for the provider
	SummarizeSymptoms(ctx context.Context, req SymptomSummaryRequest) (*SymptomSummaryResponse, error)

	// IsAvailable returns whether the AI service is reachable
	IsAvailable() bool
}

// SymptomSummaryRequest contains the patient's raw symptom input
type SymptomSummaryRequest struct {
	PatientAge         int      `json:"patient_age,omitempty"`
	PatientGender      string   `json:"patient_gender,omitempty"`
	RawSymptoms        string   `json:"raw_symptoms"`       // free-text from patient
	Duration           string   `json:"duration,omitempty"` // e.g. "3 days"
	Severity           string   `json:"severity,omitempty"` // mild / moderate / severe
	ExistingAllergies  []string `json:"existing_allergies,omitempty"`
	ExistingConditions []string `json:"existing_conditions,omitempty"`
}

// SymptomSummaryResponse holds the AI-generated clinical summary
type SymptomSummaryResponse struct {
	ClinicalSummary    string   `json:"clinical_summary"`    // 2-3 sentence provider-facing summary
	TriageLevel        string   `json:"triage_level"`        // low / medium / high / emergency
	KeySymptoms        []string `json:"key_symptoms"`        // extracted symptom list
	SuggestedQuestions []string `json:"suggested_questions"` // follow-up questions for provider
	RawResponse        string   `json:"raw_response"`        // full model output for audit
}

// chatMessage mirrors the OpenAI-compatible message format
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
}

type chatChoice struct {
	Message chatMessage `json:"message"`
}

type chatResponse struct {
	Choices []chatChoice `json:"choices"`
	Error   *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// aiClient is the concrete implementation
type aiClient struct {
	cfg       *Config
	http      *http.Client
	logger    *zerolog.Logger
	available bool
}

// New creates a new AI client
func New(cfg *Config, logger *zerolog.Logger) Client {
	c := &aiClient{
		cfg:    cfg,
		logger: logger,
		http: &http.Client{
			Timeout: cfg.RequestTimeout,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		available: cfg.APIKey != "",
	}

	if !c.available {
		logger.Warn().Msg("AI client: no API key configured, service disabled")
	} else {
		logger.Info().
			Str("model", cfg.Model).
			Msg("AI client initialized")
	}

	return c
}

// SummarizeSymptoms sends a structured prompt and parses the JSON response
func (c *aiClient) SummarizeSymptoms(ctx context.Context, req SymptomSummaryRequest) (*SymptomSummaryResponse, error) {
	if !c.available {
		return nil, ErrAIUnavailable
	}

	prompt := buildSymptomPrompt(req)

	body := chatRequest{
		Model: c.cfg.Model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: prompt},
		},
	}

	raw, err := c.call(ctx, body)
	if err != nil {
		return nil, err
	}

	result, err := parseSymptomResponse(raw)
	if err != nil {
		// Fallback: return a simple summary rather than failing entirely
		c.logger.Warn().Err(err).Msg("AI: failed to parse structured response, using raw output")
		return &SymptomSummaryResponse{
			ClinicalSummary: raw,
			TriageLevel:     "medium",
			RawResponse:     raw,
		}, nil
	}

	result.RawResponse = raw
	return result, nil
}

// IsAvailable returns whether the client is configured and ready
func (c *aiClient) IsAvailable() bool {
	return c.available
}

// call executes a single HTTP request to the HuggingFace router
func (c *aiClient) call(ctx context.Context, body chatRequest) (string, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("ai: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, huggingFaceRouterURL, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("ai: build request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		c.logger.Error().Err(err).Msg("AI: HTTP call failed")
		return "", fmt.Errorf("ai: %w: %v", ErrAIUnavailable, err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("ai: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		c.logger.Error().
			Int("status", resp.StatusCode).
			Str("body", string(respBytes)).
			Msg("AI: non-200 response")
		return "", fmt.Errorf("ai: upstream returned %d: %s", resp.StatusCode, string(respBytes))
	}

	var chat chatResponse
	if err := json.Unmarshal(respBytes, &chat); err != nil {
		return "", fmt.Errorf("ai: unmarshal response: %w", err)
	}

	if chat.Error != nil {
		return "", fmt.Errorf("ai: upstream error: %s", chat.Error.Message)
	}

	if len(chat.Choices) == 0 {
		return "", fmt.Errorf("ai: empty choices in response")
	}

	return chat.Choices[0].Message.Content, nil
}

// buildSymptomPrompt constructs the user-turn prompt
func buildSymptomPrompt(req SymptomSummaryRequest) string {
	prompt := fmt.Sprintf(`Patient reported symptoms: %s`, req.RawSymptoms)

	if req.Duration != "" {
		prompt += fmt.Sprintf(`\nDuration: %s`, req.Duration)
	}
	if req.Severity != "" {
		prompt += fmt.Sprintf(`\nSeverity (self-reported): %s`, req.Severity)
	}
	if req.PatientAge > 0 {
		prompt += fmt.Sprintf(`\nPatient age: %d`, req.PatientAge)
	}
	if req.PatientGender != "" {
		prompt += fmt.Sprintf(`\nGender: %s`, req.PatientGender)
	}
	if len(req.ExistingConditions) > 0 {
		prompt += fmt.Sprintf(`\nKnown conditions: %v`, req.ExistingConditions)
	}
	if len(req.ExistingAllergies) > 0 {
		prompt += fmt.Sprintf(`\nKnown allergies: %v`, req.ExistingAllergies)
	}

	return prompt
}

// parseSymptomResponse attempts to unmarshal the model's JSON output
func parseSymptomResponse(raw string) (*SymptomSummaryResponse, error) {
	// Model is instructed to return JSON; try direct unmarshal first
	var result SymptomSummaryResponse
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("parse symptom response: %w", err)
	}
	return &result, nil
}

// systemPrompt instructs the model to behave as a clinical triage assistant
const systemPrompt = `You are a clinical triage assistant helping healthcare providers quickly understand a patient's reported symptoms before a telemedicine consultation.

Given the patient's symptom input, respond ONLY with a valid JSON object in exactly this format:
{
  "clinical_summary": "<2-3 sentence provider-facing summary in clinical language>",
  "triage_level": "<one of: low | medium | high | emergency>",
  "key_symptoms": ["<symptom 1>", "<symptom 2>", "..."],
  "suggested_questions": ["<follow-up question 1>", "<follow-up question 2>", "..."]
}

Rules:
- clinical_summary must be objective and free of diagnosis
- triage_level must be one of the four allowed values
- key_symptoms should extract 3-8 discrete symptoms
- suggested_questions should contain 2-4 clinically relevant follow-ups
- Do not include any text outside the JSON object
- Do not add markdown code fences`
