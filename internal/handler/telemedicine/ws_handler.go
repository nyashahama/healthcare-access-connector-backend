package telemedicine

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	sc_dto "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/telemedicine"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/ws"
	"github.com/rs/zerolog"
)

// WSHandler authenticates incoming WebSocket upgrade requests and delegates
// them to the hub. It is intentionally thin — all real-time logic lives in
// ws.Hub and the MessageHandler closure wired in app.go.
type WSHandler struct {
	hub         *ws.Hub
	authService service.AuthService
	logger      *zerolog.Logger
}

// NewWSHandler creates a WSHandler.
func NewWSHandler(hub *ws.Hub, authService service.AuthService, logger *zerolog.Logger) *WSHandler {
	return &WSHandler{hub: hub, authService: authService, logger: logger}
}

// ServeWS handles GET /ws/consultations/{consultationId}.
//
// Authentication flow:
//  1. Try the Authorization: Bearer <token> header first (native clients).
//  2. Fall back to the ?token=<jwt> query param (browser WebSocket API, which
//     cannot set arbitrary headers before the upgrade handshake).
//
// Once the token is validated the connection is handed to the hub. The
// sender's role ("patient" | "provider") is read from the JWT claims so the
// hub can correctly tag presence and typing events.
func (h *WSHandler) ServeWS(w http.ResponseWriter, r *http.Request) {
	consultationID := chi.URLParam(r, "consultationId")
	if consultationID == "" {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{
			Error: "consultation_id is required",
		})
		return
	}

	// ── Token extraction ───────────────────────────────────────────────────────
	token := tokenFromRequest(r)
	if token == "" {
		handler.RespondJSON(w, http.StatusUnauthorized, sc_dto.ErrorResponse{
			Error: "missing authentication token",
		})
		return
	}

	// ── Token validation ───────────────────────────────────────────────────────
	claims, err := h.authService.ValidateToken(r.Context(), token)
	if err != nil {
		h.logger.Warn().Err(err).Str("consultation_id", consultationID).Msg("WS: invalid token")
		handler.RespondJSON(w, http.StatusUnauthorized, sc_dto.ErrorResponse{
			Error: "invalid or expired token",
		})
		return
	}

	userID := claims.UserID.String()
	role := string(claims.Role) // "patient" | "provider" | "system_admin" …

	h.logger.Info().
		Str("user_id", userID).
		Str("role", role).
		Str("consultation_id", consultationID).
		Msg("WS: upgrading connection")

	// ── Hand off to the hub ────────────────────────────────────────────────────
	// ServeWS is non-blocking; the hub launches readPump/writePump goroutines
	// internally and returns immediately.
	h.hub.ServeWS(w, r, consultationID, userID, role)
}

// tokenFromRequest extracts the JWT from either the Authorization header or
// the ?token= query param. Returns an empty string when neither is present.
func tokenFromRequest(r *http.Request) string {
	// 1. Authorization: Bearer <token>
	if auth := r.Header.Get("Authorization"); auth != "" {
		if after, ok := strings.CutPrefix(auth, "Bearer "); ok {
			return strings.TrimSpace(after)
		}
	}
	// 2. ?token=<jwt>  (browser WebSocket fallback)
	return r.URL.Query().Get("token")
}