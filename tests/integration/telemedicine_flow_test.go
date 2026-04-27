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

func TestTelemedicineFlow(t *testing.T) {
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

	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer pool.Close()

	var providerID string
	var clinicID string
	err = pool.QueryRow(context.Background(), `
		SELECT u.id, uc.clinic_id FROM users u
		JOIN user_clinics uc ON uc.user_id = u.id
		WHERE u.role = 'provider_staff' AND u.is_verified = true LIMIT 1
	`).Scan(&providerID, &clinicID)
	if err != nil {
		t.Skipf("No provider found, skipping telemedicine flow test: %v", err)
	}

	patientPayload := map[string]interface{}{
		"email":    "telemed@example.com",
		"password": "SecurePass123!",
		"role":     "patient",
	}
	patientBody, _ := json.Marshal(patientPayload)

	resp, err := ts.Client().Post(ts.URL+"/api/v1/auth/register", "application/json", bytes.NewReader(patientBody))
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

	patientID := registerResp["id"].(string)

	_, err = pool.Exec(context.Background(), "UPDATE users SET is_verified = true WHERE id = $1", patientID)
	if err != nil {
		t.Fatalf("Failed to verify patient: %v", err)
	}

	symptomCheckerPayload := map[string]interface{}{
		"raw_symptoms": "I have a headache and fever for the past 2 days",
		"duration":     "2 days",
		"severity":     "moderate",
	}
	symptomBody, _ := json.Marshal(symptomCheckerPayload)

	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/telemedicine/symptom-checker", bytes.NewReader(symptomBody))
	req.Header.Set("Authorization", "Bearer ")
	req.Header.Set("Content-Type", "application/json")
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to get symptom checker without auth: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected status 401, got %d", resp.StatusCode)
	}

	loginPayload := map[string]interface{}{
		"identifier": "telemed@example.com",
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

	token := loginResp.Token

	req, _ = http.NewRequest("POST", ts.URL+"/api/v1/telemedicine/symptom-checker", bytes.NewReader(symptomBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to submit symptom checker: %v", err)
	}

	var symptomResp struct {
		SessionID        string `json:"session_id"`
		ClinicalSummary string `json:"clinical_summary"`
		TriageLevel      string `json:"triage_level"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&symptomResp); err != nil {
		t.Fatalf("Failed to decode symptom response: %v", err)
	}

	consultationPayload := map[string]interface{}{
		"symptom_session_id": symptomResp.SessionID,
		"channel":            "chat",
	}
	consultationBody, _ := json.Marshal(consultationPayload)

	req, _ = http.NewRequest("POST", ts.URL+"/api/v1/telemedicine/consultations", bytes.NewReader(consultationBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to create consultation: %v", err)
	}

	var consultationResp struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&consultationResp); err != nil {
		t.Fatalf("Failed to decode consultation response: %v", err)
	}

	consultationID := consultationResp.ID

	req, _ = http.NewRequest("GET", ts.URL+"/api/v1/telemedicine/consultations/"+consultationID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to get consultation: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	req, _ = http.NewRequest("GET", ts.URL+"/api/v1/telemedicine/consultations", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to get consultations: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	messagePayload := map[string]interface{}{
		"message_type": "text",
		"content":      "Hello, I have a question about my symptoms",
	}
	messageBody, _ := json.Marshal(messagePayload)

	req, _ = http.NewRequest("POST", ts.URL+"/api/v1/telemedicine/consultations/"+consultationID+"/messages", bytes.NewReader(messageBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	req, _ = http.NewRequest("GET", ts.URL+"/api/v1/telemedicine/consultations/"+consultationID+"/messages", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to get messages: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	req, _ = http.NewRequest("GET", ts.URL+"/api/v1/telemedicine/waiting-room", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to get waiting room: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	req, _ = http.NewRequest("GET", ts.URL+"/api/v1/patients/telemedicine/history", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to get telemedicine history: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	time.Sleep(100 * time.Millisecond)
}