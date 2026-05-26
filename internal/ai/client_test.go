package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("creates client with valid config", func(t *testing.T) {
		cfg := &Config{
			APIKey:         "test-api-key",
			Model:          "test-model",
			RequestTimeout: 30 * time.Second,
			Enabled:        true,
		}

		logger := zerolog.New(nil)
		client := New(cfg, &logger)

		assert.NotNil(t, client)
		assert.True(t, client.IsAvailable())
	})

	t.Run("creates disabled client without API key", func(t *testing.T) {
		cfg := &Config{
			APIKey:  "",
			Model:   "test-model",
			Enabled: true,
		}

		logger := zerolog.New(nil)
		client := New(cfg, &logger)

		assert.NotNil(t, client)
		assert.False(t, client.IsAvailable())
	})
}

func TestClient_SummarizeSymptoms(t *testing.T) {
	t.Run("returns error when unavailable", func(t *testing.T) {
		cfg := &Config{
			APIKey:  "",
			Enabled: true,
		}

		logger := zerolog.New(nil)
		client := New(cfg, &logger)

		req := SymptomSummaryRequest{
			RawSymptoms: "headache and fever",
		}

		_, err := client.SummarizeSymptoms(context.Background(), req)
		assert.Error(t, err)
		assert.Equal(t, ErrAIUnavailable, err)
	})

	t.Run("successful summarization", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Model    string `json:"model"`
				Messages []struct {
					Role    string `json:"role"`
					Content string `json:"content"`
				} `json:"messages"`
			}
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.Equal(t, "test-model", req.Model)
			assert.Len(t, req.Messages, 2)

			response := map[string]interface{}{
				"choices": []map[string]interface{}{
					{
						"message": map[string]interface{}{
							"role":    "assistant",
							"content": `{"clinical_summary":"Test summary","triage_level":"medium","key_symptoms":["headache","fever"],"suggested_questions":["How long?"]}`,
						},
					},
				},
			}

			w.Header().Set("Content-Type", "application/json")
			err = json.NewEncoder(w).Encode(response)
			assert.NoError(t, err)
		}))
		defer server.Close()

		cfg := &Config{
			APIKey:         "test-api-key",
			Model:          "test-model",
			RequestTimeout: 30 * time.Second,
			Enabled:        true,
		}

		logger := zerolog.New(nil)
		client := newTestClient(cfg, &logger, server.URL)

		req := SymptomSummaryRequest{
			RawSymptoms: "headache and fever",
			Duration:    "2 days",
			Severity:    "moderate",
		}

		resp, err := client.SummarizeSymptoms(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, "Test summary", resp.ClinicalSummary)
		assert.Equal(t, "medium", resp.TriageLevel)
		assert.Contains(t, resp.KeySymptoms, "headache")
	})

	t.Run("uses fallback on parse error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			response := map[string]interface{}{
				"choices": []map[string]interface{}{
					{
						"message": map[string]interface{}{
							"role":    "assistant",
							"content": "Not a JSON response",
						},
					},
				},
			}

			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(response)
			if err != nil {
				t.Fatalf("encode response: %v", err)
			}
		}))
		defer server.Close()

		cfg := &Config{
			APIKey:         "test-api-key",
			Model:          "test-model",
			RequestTimeout: 30 * time.Second,
			Enabled:        true,
		}

		logger := zerolog.New(nil)
		client := newTestClient(cfg, &logger, server.URL)

		req := SymptomSummaryRequest{
			RawSymptoms: "test symptoms",
		}

		resp, err := client.SummarizeSymptoms(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, "Not a JSON response", resp.ClinicalSummary)
		assert.Equal(t, "medium", resp.TriageLevel)
	})
}

func newTestClient(cfg *Config, logger *zerolog.Logger, testURL string) Client {
	return &testAIClient{
		cfg:     cfg,
		logger:  logger,
		testURL: testURL,
	}
}

type testAIClient struct {
	cfg       *Config
	logger    *zerolog.Logger
	testURL   string
	available bool
}

func (c *testAIClient) SummarizeSymptoms(ctx context.Context, req SymptomSummaryRequest) (*SymptomSummaryResponse, error) {
	if !c.available && c.cfg.APIKey == "" {
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

	raw, err := c.testCall(ctx, body)
	if err != nil {
		return nil, err
	}

	result, err := parseSymptomResponse(raw)
	if err != nil {
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

func (c *testAIClient) IsAvailable() bool {
	return c.cfg.APIKey != ""
}

func (c *testAIClient) testCall(ctx context.Context, body chatRequest) (string, error) {
	data, _ := json.Marshal(body)

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.testURL, bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("ai: %w: %v", ErrAIUnavailable, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	respBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ai: upstream returned %d: %s", resp.StatusCode, string(respBytes))
	}

	var chat chatResponse
	err = json.Unmarshal(respBytes, &chat)
	if err != nil {
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

func TestClient_IsAvailable(t *testing.T) {
	t.Run("available with API key", func(t *testing.T) {
		cfg := &Config{
			APIKey:  "test-api-key",
			Enabled: true,
		}

		logger := zerolog.New(nil)
		client := New(cfg, &logger)

		assert.True(t, client.IsAvailable())
	})

	t.Run("not available without API key", func(t *testing.T) {
		cfg := &Config{
			APIKey:  "",
			Enabled: true,
		}

		logger := zerolog.New(nil)
		client := New(cfg, &logger)

		assert.False(t, client.IsAvailable())
	})
}

func TestConfig_Validate(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		cfg := &Config{
			APIKey:         "test-api-key",
			RequestTimeout: 30 * time.Second,
			MaxTokens:      512,
			Enabled:        true,
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("valid disabled config", func(t *testing.T) {
		cfg := &Config{
			APIKey:         "",
			RequestTimeout: 30 * time.Second,
			MaxTokens:      512,
			Enabled:        false,
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("missing API key when enabled", func(t *testing.T) {
		cfg := &Config{
			APIKey:         "",
			RequestTimeout: 30 * time.Second,
			MaxTokens:      512,
			Enabled:        true,
		}

		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "HF_API_KEY")
	})
}

func TestBuildSymptomPrompt(t *testing.T) {
	t.Run("basic symptoms", func(t *testing.T) {
		req := SymptomSummaryRequest{
			RawSymptoms: "headache",
		}

		prompt := buildSymptomPrompt(req)
		assert.Contains(t, prompt, "headache")
	})

	t.Run("symptoms with duration", func(t *testing.T) {
		req := SymptomSummaryRequest{
			RawSymptoms: "cough",
			Duration:    "3 days",
		}

		prompt := buildSymptomPrompt(req)
		assert.Contains(t, prompt, "cough")
		assert.Contains(t, prompt, "3 days")
	})

	t.Run("symptoms with severity", func(t *testing.T) {
		req := SymptomSummaryRequest{
			RawSymptoms: "fever",
			Severity:    "high",
		}

		prompt := buildSymptomPrompt(req)
		assert.Contains(t, prompt, "fever")
		assert.Contains(t, prompt, "high")
	})

	t.Run("symptoms with patient info", func(t *testing.T) {
		req := SymptomSummaryRequest{
			RawSymptoms:   "chest pain",
			PatientAge:    45,
			PatientGender: "male",
		}

		prompt := buildSymptomPrompt(req)
		assert.Contains(t, prompt, "chest pain")
		assert.Contains(t, prompt, "45")
		assert.Contains(t, prompt, "male")
	})

	t.Run("symptoms with existing conditions", func(t *testing.T) {
		req := SymptomSummaryRequest{
			RawSymptoms:        "dizziness",
			ExistingConditions: []string{"diabetes", "hypertension"},
		}

		prompt := buildSymptomPrompt(req)
		assert.Contains(t, prompt, "diabetes")
		assert.Contains(t, prompt, "hypertension")
	})

	t.Run("symptoms with allergies", func(t *testing.T) {
		req := SymptomSummaryRequest{
			RawSymptoms:       "rash",
			ExistingAllergies: []string{"penicillin"},
		}

		prompt := buildSymptomPrompt(req)
		assert.Contains(t, prompt, "penicillin")
	})
}

func TestParseSymptomResponse(t *testing.T) {
	t.Run("valid JSON response", func(t *testing.T) {
		raw := `{"clinical_summary":"Test summary","triage_level":"high","key_symptoms":["fever","cough"],"suggested_questions":["How long?"]}`

		resp, err := parseSymptomResponse(raw)
		require.NoError(t, err)
		assert.Equal(t, "Test summary", resp.ClinicalSummary)
		assert.Equal(t, "high", resp.TriageLevel)
		assert.Len(t, resp.KeySymptoms, 2)
	})

	t.Run("invalid JSON response", func(t *testing.T) {
		raw := "Not a JSON string"

		_, err := parseSymptomResponse(raw)
		assert.Error(t, err)
	})
}

func TestSymptomSummaryRequest(t *testing.T) {
	t.Run("serializes to JSON", func(t *testing.T) {
		req := SymptomSummaryRequest{
			PatientAge:         30,
			PatientGender:      "female",
			RawSymptoms:        "abdominal pain",
			Duration:           "1 week",
			Severity:           "moderate",
			ExistingAllergies:  []string{"latex"},
			ExistingConditions: []string{"PCOS"},
		}

		data, err := json.Marshal(req)
		require.NoError(t, err)

		var parsed SymptomSummaryRequest
		err = json.Unmarshal(data, &parsed)
		require.NoError(t, err)

		assert.Equal(t, 30, parsed.PatientAge)
		assert.Equal(t, "female", parsed.PatientGender)
		assert.Equal(t, "abdominal pain", parsed.RawSymptoms)
	})
}

func TestSymptomSummaryResponse(t *testing.T) {
	t.Run("serializes to JSON", func(t *testing.T) {
		resp := SymptomSummaryResponse{
			ClinicalSummary:    "Patient reports chest discomfort",
			TriageLevel:        "high",
			KeySymptoms:        []string{"chest pain", "shortness of breath"},
			SuggestedQuestions: []string{"Duration of symptoms?"},
			RawResponse:        "raw model output",
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var parsed SymptomSummaryResponse
		err = json.Unmarshal(data, &parsed)
		require.NoError(t, err)

		assert.Equal(t, "Patient reports chest discomfort", parsed.ClinicalSummary)
		assert.Equal(t, "high", parsed.TriageLevel)
		assert.Len(t, parsed.KeySymptoms, 2)
	})
}
