package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	domainmodels "github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/validator"
	"github.com/rs/zerolog"
)

type ServiceHandler struct {
	serviceService service.ServiceCatalogService
	logger         *zerolog.Logger
	timeout        time.Duration
}

// NewServiceHandler creates a new service handler
func NewServiceHandler(
	serviceService service.ServiceCatalogService,
	logger *zerolog.Logger,
	timeout time.Duration,
) *ServiceHandler {
	return &ServiceHandler{
		serviceService: serviceService,
		logger:         logger,
		timeout:        timeout,
	}
}

// CreateService handles service creation
func (h *ServiceHandler) CreateService(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req providers.CreateServiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("service_name", req.ServiceName)
	v.ValidateMinLength("service_name", req.ServiceName, 1)
	v.ValidateRequired("cost_currency", req.CostCurrency)
	v.ValidateLength("cost_currency", req.CostCurrency, 3, 3)

	if req.GenderRestriction != nil {
		v.ValidateEnum("gender_restriction", *req.GenderRestriction, []string{
			"male",
			"female",
			"none",
		})
	}

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Convert DTO to domain model
	svc := providers.ToDomainService(req)

	// Create service
	createdService, err := h.serviceService.CreateClinicService(ctx, svc)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusCreated, providers.ToServiceResponse(createdService))
}

// GetService handles getting a service by ID
func (h *ServiceHandler) GetService(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	serviceIDStr := chi.URLParam(r, "id")
	serviceID, err := uuid.Parse(serviceIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid service ID format",
		})
		return
	}

	svc, err := h.serviceService.GetServiceByID(ctx, serviceID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, providers.ToServiceResponse(svc))
}

// UpdateService handles service updates
func (h *ServiceHandler) UpdateService(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	serviceIDStr := chi.URLParam(r, "id")
	serviceID, err := uuid.Parse(serviceIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid service ID format",
		})
		return
	}

	var req providers.UpdateServiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("service_name", req.ServiceName)
	v.ValidateMinLength("service_name", req.ServiceName, 1)
	v.ValidateRequired("cost_currency", req.CostCurrency)
	v.ValidateLength("cost_currency", req.CostCurrency, 3, 3)

	if req.GenderRestriction != nil {
		v.ValidateEnum("gender_restriction", *req.GenderRestriction, []string{
			"male",
			"female",
			"none",
		})
	}

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Get existing service to preserve clinic_id
	existingService, err := h.serviceService.GetServiceByID(ctx, serviceID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Update service with new data
	updated := providers.UpdateToDomainService(existingService, req)

	// Update service
	if err := h.serviceService.UpdateClinicService(ctx, updated); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Fetch updated service
	updatedService, err := h.serviceService.GetServiceByID(ctx, serviceID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, providers.ToServiceResponse(updatedService))
}

// DeleteService handles service deletion
func (h *ServiceHandler) DeleteService(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	serviceIDStr := chi.URLParam(r, "id")
	serviceID, err := uuid.Parse(serviceIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid service ID format",
		})
		return
	}

	if err := h.serviceService.DeleteClinicService(ctx, serviceID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Service deleted successfully",
	})
}

// ListClinicServices handles listing services for a clinic
func (h *ServiceHandler) ListClinicServices(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	clinicIDStr := chi.URLParam(r, "clinic_id")
	clinicID, err := uuid.Parse(clinicIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid clinic ID format",
		})
		return
	}

	// Get optional active filter
	activeOnly := r.URL.Query().Get("active_only") == "true"

	var services []domainmodels.ClinicService
	if activeOnly {
		services, err = h.serviceService.GetActiveClinicServices(ctx, clinicID)
	} else {
		services, err = h.serviceService.GetClinicServices(ctx, clinicID)
	}

	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	response := providers.ServiceListResponse{
		Services: make([]providers.ServiceResponse, len(services)),
		Total:    len(services),
	}

	for i, svc := range services {
		response.Services[i] = providers.ToServiceResponse(svc)
	}

	handler.RespondJSON(w, http.StatusOK, response)
}

// CheckServiceExists handles checking if service exists
func (h *ServiceHandler) CheckServiceExists(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	serviceIDStr := chi.URLParam(r, "id")
	serviceID, err := uuid.Parse(serviceIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid service ID format",
		})
		return
	}

	exists, err := h.serviceService.ServiceExists(ctx, serviceID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]bool{
		"exists": exists,
	})
}
