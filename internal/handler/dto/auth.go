// Package dto defines data transfer objects for health project
package dto

import (
	"time"

	"github.com/docker/distribution/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
)

// RegisterRequest represents a user registration request
type RegisterRequest struct {
	Email    string `json:"email,omitempty"`
	Phone    string `json:"phone,omitempty"`
	Password string `json:"password"`
	Role     string `json:"role,omitempty"`
}

// LoginRequest represents a login request
type LoginRequest struct {
	Identifier string `json:"identifier"` // Can be email or phone
	Password   string `json:"password"`
}

// LoginResponse represents a successful login response
type LoginResponse struct {
	Token     string       `json:"token"`
	ExpiresAt time.Time    `json:"expires_at"`
	User      UserResponse `json:"user"`
}

// UserResponse represents user data in responses
type UserResponse struct {
	ID                   uuid.UUID  `json:"id"`
	Email                *string    `json:"email,omitempty"`
	Phone                *string    `json:"phone,omitempty"`
	Role                 string     `json:"role"`
	Status               string     `json:"status"`
	IsVerified           bool       `json:"is_verified"`
	LastLogin            *time.Time `json:"last_login,omitempty"`
	ProfileCompletionPct int        `json:"profile_completion_percentage"`
	CreatedAt            time.Time  `json:"created_at"`
}

// PatientProfileResponse represents patient profile data
type PatientProfileResponse struct {
	ID                           uuid.UUID  `json:"id"`
	UserID                       uuid.UUID  `json:"user_id"`
	FirstName                    string     `json:"first_name"`
	LastName                     string     `json:"last_name"`
	PreferredName                *string    `json:"preferred_name,omitempty"`
	DateOfBirth                  *time.Time `json:"date_of_birth,omitempty"`
	Gender                       *string    `json:"gender,omitempty"`
	PreferredGenderPronouns      *string    `json:"preferred_gender_pronouns,omitempty"`
	PrimaryAddress               *string    `json:"primary_address,omitempty"`
	City                         *string    `json:"city,omitempty"`
	Province                     *string    `json:"province,omitempty"`
	Country                      string     `json:"country"`
	LanguagePreferences          []string   `json:"language_preferences"`
	PreferredCommunicationMethod string     `json:"preferred_communication_method"`
	HasMedicalAid                bool       `json:"has_medical_aid"`
	ProfilePictureURL            *string    `json:"profile_picture_url,omitempty"`
	Timezone                     string     `json:"timezone"`
	LastProfileUpdate            *time.Time `json:"last_profile_update,omitempty"`
	CreatedAt                    time.Time  `json:"created_at"`
	UpdatedAt                    time.Time  `json:"updated_at"`
}

// ProfileResponse combines user and patient profile
type ProfileResponse struct {
	User    UserResponse            `json:"user"`
	Profile *PatientProfileResponse `json:"profile,omitempty"`
}

// ToUserResponse converts domain.User to UserResponse
func ToUserResponse(user domain.User) UserResponse {
	return UserResponse{
		ID:                   user.ID,
		Email:                user.Email,
		Phone:                user.Phone,
		Role:                 user.Role,
		Status:               user.Status,
		IsVerified:           user.IsVerified,
		LastLogin:            user.LastLogin,
		ProfileCompletionPct: user.ProfileCompletionPct,
		CreatedAt:            user.CreatedAt,
	}
}

// ToPatientProfileResponse converts domain.PatientProfile to PatientProfileResponse
func ToPatientProfileResponse(profile domain.PatientProfile) PatientProfileResponse {
	return PatientProfileResponse{
		ID:                           profile.ID,
		UserID:                       profile.UserID,
		FirstName:                    profile.FirstName,
		LastName:                     profile.LastName,
		PreferredName:                profile.PreferredName,
		DateOfBirth:                  profile.DateOfBirth,
		Gender:                       profile.Gender,
		PreferredGenderPronouns:      profile.PreferredGenderPronouns,
		PrimaryAddress:               profile.PrimaryAddress,
		City:                         profile.City,
		Province:                     profile.Province,
		Country:                      profile.Country,
		LanguagePreferences:          profile.LanguagePreferences,
		PreferredCommunicationMethod: profile.PreferredCommunicationMethod,
		HasMedicalAid:                profile.HasMedicalAid,
		ProfilePictureURL:            profile.ProfilePictureURL,
		Timezone:                     profile.Timezone,
		LastProfileUpdate:            profile.LastProfileUpdate,
		CreatedAt:                    profile.CreatedAt,
		UpdatedAt:                    profile.UpdatedAt,
	}
}

// ToProfileResponse converts user and profile to combined response

func ToProfileResponse(user domain.User, profile domain.PatientProfile) ProfileResponse {
	var profileResp *PatientProfileResponse

	if profile.ID != (uuid.UUID{}) {
		p := ToPatientProfileResponse(profile)
		profileResp = &p
	}

	return ProfileResponse{
		User:    ToUserResponse(user),
		Profile: profileResp,
	}
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error  string            `json:"error"`
	Fields map[string]string `json:"fields,omitempty"`
	Code   string            `json:"code,omitempty"`
}

// PasswordResetRequest represents password reset request
type PasswordResetRequest struct {
	Identifier string `json:"identifier"` // Email or phone
}

// PasswordUpdateRequest represents password update request
type PasswordUpdateRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// ConsentResponse represents consent settings
type ConsentResponse struct {
	HealthDataConsent         bool       `json:"health_data_consent"`
	ResearchConsent           bool       `json:"research_consent"`
	EmergencyAccessConsent    bool       `json:"emergency_access_consent"`
	SMSCommunicationConsent   bool       `json:"sms_communication_consent"`
	EmailCommunicationConsent bool       `json:"email_communication_consent"`
	ConsentWithdrawn          bool       `json:"consent_withdrawn"`
	ConsentDate               *time.Time `json:"consent_date,omitempty"`
	CreatedAt                 time.Time  `json:"created_at"`
	UpdatedAt                 time.Time  `json:"updated_at"`
}
