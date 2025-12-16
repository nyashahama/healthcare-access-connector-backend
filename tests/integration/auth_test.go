//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/app"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/config"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthIntegration(t *testing.T) {
	// Setup test configuration
	cfg := &config.Config{
		DBURL:          "postgres://postgres:admin@localhost:5432/testdb?sslmode=disable",
		JWTSecret:      "test-secret-key-min-32-characters-long",
		Port:           ":8888",
		LogLevel:       "error",
		Timeout:        30 * time.Second,
		Environment:    "test",
		AllowedOrigins: []string{"*"},
		RateLimitRPS:   100,
		RateLimitBurst: 200,
		JWTExpiry:      24 * time.Hour,
		RedisURL:       "redis://localhost:6379",
		NatsURL:        "nats://localhost:4222",
		CacheTTL:       5 * time.Minute,
	}

	// Initialize application
	application, err := app.New(cfg)
	require.NoError(t, err)
	defer application.Cleanup()

	// Create test server
	// srv := httptest.NewServer(application.Server.Handler)
	// defer srv.Close()

	t.Run("Register New User", func(t *testing.T) {
		reqBody := dto.RegisterRequest{
			Username: "testuser",
			Email:    "test@example.com",
			Password: "password123",
			Role:     "user",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		rec := httptest.NewRecorder()
		// handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusCreated, rec.Code)

		var response dto.UserResponse
		err := json.NewDecoder(rec.Body).Decode(&response)
		require.NoError(t, err)
		assert.Equal(t, "testuser", response.Username)
		assert.Equal(t, "test@example.com", response.Email)
	})

	t.Run("Login With Valid Credentials", func(t *testing.T) {
		reqBody := dto.LoginRequest{
			Email:    "test@example.com",
			Password: "password123",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		rec := httptest.NewRecorder()
		// handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var response dto.LoginResponse
		err := json.NewDecoder(rec.Body).Decode(&response)
		require.NoError(t, err)
		assert.NotEmpty(t, response.Token)
		assert.NotZero(t, response.User.ID)
	})

	t.Run("Login With Invalid Credentials", func(t *testing.T) {
		reqBody := dto.LoginRequest{
			Email:    "test@example.com",
			Password: "wrongpassword",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		rec := httptest.NewRecorder()
		// handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("Get Profile With Valid Token", func(t *testing.T) {
		// First login to get token
		loginBody := dto.LoginRequest{
			Email:    "test@example.com",
			Password: "password123",
		}

		body, _ := json.Marshal(loginBody)
		loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/login", bytes.NewReader(body))
		loginReq.Header.Set("Content-Type", "application/json")

		loginRec := httptest.NewRecorder()
		// handler.ServeHTTP(loginRec, loginReq)

		var loginResponse dto.LoginResponse
		json.NewDecoder(loginRec.Body).Decode(&loginResponse)

		// Get profile
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/1", nil)
		req.Header.Set("Authorization", "Bearer "+loginResponse.Token)

		rec := httptest.NewRecorder()
		// handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestHealthEndpoints(t *testing.T) {
	t.Run("Health Check", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()

		// handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("Readiness Check", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		rec := httptest.NewRecorder()

		// handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("Liveness Check", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/live", nil)
		rec := httptest.NewRecorder()

		// handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

// Helper functions

func cleanupTestData(t *testing.T) {
	// Implement database cleanup
}

func createTestUser(t *testing.T) int32 {
	// Implement test user creation
	return 1
}
