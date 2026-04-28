//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/app"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/config"
)

func TestAuthFlow(t *testing.T) {
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	appInstance, err := app.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create app: %v", err)
	}
	defer appInstance.Cleanup()

	router := appInstance.Server.Router()

	ts := httptest.NewServer(router)
	defer ts.Close()

	registerPayload := map[string]interface{}{
		"email":    "patient@example.com",
		"password": "SecurePass123!",
		"role":     "patient",
	}
	registerBody, _ := json.Marshal(registerPayload)

	resp, err := ts.Client().Post(ts.URL+"/api/v1/auth/register", "application/json", bytes.NewReader(registerBody))
	if err != nil {
		t.Fatalf("Failed to register: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected status 201, got %d", resp.StatusCode)
	}

	var registerResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&registerResp); err != nil {
		t.Fatalf("Failed to decode register response: %v", err)
	}

	userID := registerResp["id"].(string)

	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer pool.Close()

	verificationToken := ""
	for i := 0; i < 10; i++ {
		err = pool.QueryRow(context.Background(), "SELECT verification_token FROM users WHERE id = $1", userID).Scan(&verificationToken)
		if err == nil && verificationToken != "" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if verificationToken == "" {
		_, err = pool.Exec(context.Background(), "UPDATE users SET is_verified = true WHERE id = $1", userID)
		if err != nil {
			t.Fatalf("Failed to verify user: %v", err)
		}
	} else {
		verifyPayload := map[string]interface{}{
			"token": verificationToken,
		}
		verifyBody, _ := json.Marshal(verifyPayload)

		resp, err = ts.Client().Post(ts.URL+"/api/v1/auth/verify-email", "application/json", bytes.NewReader(verifyBody))
		if err != nil {
			t.Fatalf("Failed to verify email: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d", resp.StatusCode)
		}
	}

	loginPayload := map[string]interface{}{
		"identifier": "patient@example.com",
		"password":  "SecurePass123!",
	}
	loginBody, _ := json.Marshal(loginPayload)

	resp, err = ts.Client().Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	var loginResp struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		t.Fatalf("Failed to decode login response: %v", err)
	}
	if loginResp.Token == "" {
		t.Fatal("Token is empty")
	}

	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.Token)

	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to refresh token: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	req, _ = http.NewRequest("POST", ts.URL+"/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.Token)

	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to logout: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	req, _ = http.NewRequest("POST", ts.URL+"/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.Token)

	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to login with expired session: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected status 401, got %d", resp.StatusCode)
	}
}
