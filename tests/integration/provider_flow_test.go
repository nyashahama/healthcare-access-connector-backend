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

func TestProviderFlow(t *testing.T) {
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
		"email":    "provider@example.com",
		"password": "SecurePass123!",
		"role":     "provider_staff",
	}
	registerBody, _ := json.Marshal(registerPayload)

	resp, err := ts.Client().Post(ts.URL+"/api/v1/auth/register", "application/json", bytes.NewReader(registerBody))
	if err != nil {
		t.Fatalf("Failed to register provider: %v", err)
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

	_, err = pool.Exec(context.Background(), "UPDATE users SET is_verified = true WHERE id = $1", userID)
	if err != nil {
		t.Fatalf("Failed to verify user: %v", err)
	}

	loginPayload := map[string]interface{}{
		"identifier": "provider@example.com",
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

	token := loginResp.Token

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/providers/profile", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to get provider profile: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	clinicPayload := map[string]interface{}{
		"clinic_name":     "Test Clinic",
		"clinic_type":    "private_clinic",
		"physical_address": "123 Test Street",
		"country":        "ZA",
	}
	clinicBody, _ := json.Marshal(clinicPayload)

	req, _ = http.NewRequest("POST", ts.URL+"/api/v1/clinics", bytes.NewReader(clinicBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to create clinic: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected status 201, got %d", resp.StatusCode)
	}

	var clinicResp struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&clinicResp); err != nil {
		t.Fatalf("Failed to decode clinic response: %v", err)
	}

	clinicID := clinicResp.ID

	time.Sleep(100 * time.Millisecond)

	_, err = pool.Exec(context.Background(), "UPDATE users SET primary_clinic_id = $1, onboarding_completed = true WHERE id = $2", clinicID, userID)
	if err != nil {
		t.Fatalf("Failed to update user clinic: %v", err)
	}

	req, _ = http.NewRequest("GET", ts.URL+"/api/v1/providers/appointments", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to get provider appointments: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	req, _ = http.NewRequest("GET", ts.URL+"/api/v1/providers/telemedicine/waiting-room", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to get waiting room: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}
}