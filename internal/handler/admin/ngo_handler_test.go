package admin

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	domainadmin "github.com/nyashahama/healthcare-access-connector-backend/internal/domain/admin"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func createTestNGOPartner(id, userID uuid.UUID) domainadmin.NGOPartner {
	return domainadmin.NGOPartner{
		ID:                id,
		UserID:            userID,
		OrganizationName:  "Health Access NGO",
		PartnershipStatus: "active",
		OperatingRegions:  []string{"Nairobi"},
		FocusAreas:        []string{"nutrition"},
		CanAccessReports:  true,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}
}

func TestAdminHandler_CreateNGOPartner(t *testing.T) {
	mockService := new(MockSystemAdminService)
	mockNGOService := new(MockNGOPartnerService)
	handler := setupTestAdminHandler(mockService, mockNGOService)

	userID := uuid.New()
	partnerID := uuid.New()
	partner := createTestNGOPartner(partnerID, userID)

	mockNGOService.On("CreateNGOPartner", mock.Anything, mock.Anything).Return(partner, nil).Once()

	body := `{
		"user_id": "` + userID.String() + `",
		"organization_name": "Health Access NGO",
		"partnership_status": "active",
		"operating_regions": ["Nairobi"],
		"focus_areas": ["nutrition"],
		"can_access_reports": true
	}`

	req := httptest.NewRequest(http.MethodPost, "/admin/ngo-partners", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &service.TokenClaims{UserID: uuid.New(), Role: "system_admin", Email: "admin@example.com"}
	req = req.WithContext(addUserToContext(req.Context(), claims))

	w := httptest.NewRecorder()
	handler.CreateNGOPartner(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	mockNGOService.AssertExpectations(t)
}

func TestAdminHandler_GetNGOPartnerByUserID(t *testing.T) {
	mockService := new(MockSystemAdminService)
	mockNGOService := new(MockNGOPartnerService)
	handler := setupTestAdminHandler(mockService, mockNGOService)

	userID := uuid.New()
	partnerID := uuid.New()
	partner := createTestNGOPartner(partnerID, userID)

	mockNGOService.On("GetNGOPartnerByUserID", mock.Anything, userID).Return(partner, nil).Once()

	req := httptest.NewRequest(http.MethodGet, "/admin/ngo-partners/user/"+userID.String(), nil)
	claims := &service.TokenClaims{UserID: uuid.New(), Role: "system_admin", Email: "admin@example.com"}
	req = req.WithContext(addUserToContext(req.Context(), claims))

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("user_id", userID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	handler.GetNGOPartnerByUserID(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockNGOService.AssertExpectations(t)
}
