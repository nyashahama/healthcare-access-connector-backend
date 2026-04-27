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

func TestAppointmentFlow(t *testing.T) {
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

	var clinicID string
	err = pool.QueryRow(context.Background(), "SELECT id FROM clinics LIMIT 1").Scan(&clinicID)
	if err != nil {
		t.Skipf("No clinic found, skipping appointment flow test: %v", err)
	}

	var providerID string
	err = pool.QueryRow(context.Background(), `
		SELECT u.id FROM users u
		JOIN user_clinics uc ON uc.user_id = u.id
		WHERE uc.clinic_id = $1 AND u.role = 'provider_staff' LIMIT 1
	`, clinicID).Scan(&providerID)
	if err != nil {
		t.Skipf("No provider found for clinic, skipping: %v", err)
	}

	patientPayload := map[string]interface{}{
		"email":    "appointmenttest@example.com",
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

	loginPayload := map[string]interface{}{
		"identifier": "appointmenttest@example.com",
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

	appointmentDate := time.Now().Add(48 * time.Hour)
	bookingPayload := map[string]interface{}{
		"clinic_id":           clinicID,
		"appointment_datetime": appointmentDate.Format(time.RFC3339),
		"reason_for_visit":     "General checkup",
		"patient_name":        "Test Patient",
		"patient_phone":       "+27123456789",
	}
	bookingBody, _ := json.Marshal(bookingPayload)

	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/appointments", bytes.NewReader(bookingBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to create appointment: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected status 201, got %d", resp.StatusCode)
	}

	var appointmentResp struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&appointmentResp); err != nil {
		t.Fatalf("Failed to decode appointment response: %v", err)
	}

	appointmentID := appointmentResp.ID

	req, _ = http.NewRequest("GET", ts.URL+"/api/v1/appointments/"+appointmentID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to get appointment: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	req, _ = http.NewRequest("GET", ts.URL+"/api/v1/patients/appointments", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to get patient appointments: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	providerToken := ""
	err = pool.QueryRow(context.Background(), `
		SELECT auth_token FROM sessions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1
	`, providerID).Scan(&providerToken)
	if err == nil && providerToken != "" {
		req, _ = http.NewRequest("GET", ts.URL+"/api/v1/providers/appointments", nil)
		req.Header.Set("Authorization", "Bearer "+providerToken)
		resp, err = ts.Client().Do(req)
		if err != nil {
			t.Fatalf("Failed to get provider appointments: %v", err)
		}
	}

	cancelPayload := map[string]interface{}{
		"reason": "Changed plans",
	}
	cancelBody, _ := json.Marshal(cancelPayload)

	req, _ = http.NewRequest("DELETE", ts.URL+"/api/v1/appointments/"+appointmentID, bytes.NewReader(cancelBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to cancel appointment: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}
}