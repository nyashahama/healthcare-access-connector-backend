//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/app"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/config"
)

func TestPatientFlow(t *testing.T) {
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
		"email":    "newpatient@example.com",
		"password": "SecurePass123!",
		"role":     "patient",
	}
	registerBody, _ := json.Marshal(registerPayload)

	resp, err := ts.Client().Post(ts.URL+"/api/v1/auth/register", "application/json", bytes.NewReader(registerBody))
	if err != nil {
		t.Fatalf("Failed to register patient: %v", err)
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
		"identifier": "newpatient@example.com",
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

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/users/"+userID+"/profile", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to get patient profile: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	updateProfilePayload := map[string]interface{}{
		"first_name": "Test",
		"last_name":  "Patient",
	}
	updateBody, _ := json.Marshal(updateProfilePayload)

	req, _ = http.NewRequest("PUT", ts.URL+"/api/v1/users/"+userID+"/profile", bytes.NewReader(updateBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to update patient profile: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	req, _ = http.NewRequest("GET", ts.URL+"/api/v1/telemedicine/consultations/me/history", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to get telemedicine history: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	req, _ = http.NewRequest("GET", ts.URL+"/api/v1/providers/clinics?city=Johannesburg", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to search clinics: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}
}
