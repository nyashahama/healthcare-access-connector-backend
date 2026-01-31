package admin

import (
	"time"

	"github.com/google/uuid"
)

// NGOPartner represents an NGO partner organization
type NGOPartner struct {
	ID     uuid.UUID `json:"id"`
	UserID uuid.UUID `json:"user_id"`

	// Organization Details
	OrganizationName   string  `json:"organization_name"`
	OrganizationType   *string `json:"organization_type,omitempty"` // 'international', 'local', 'government', 'religious'
	RegistrationNumber *string `json:"registration_number,omitempty"`
	TaxID              *string `json:"tax_id,omitempty"`

	// Contact Information
	OrganizationAddress *string `json:"organization_address,omitempty"`
	OrganizationPhone   *string `json:"organization_phone,omitempty"`
	OrganizationEmail   *string `json:"organization_email,omitempty"`
	Website             *string `json:"website,omitempty"`

	// Primary Contact
	ContactPersonName  *string `json:"contact_person_name,omitempty"`
	ContactPersonRole  *string `json:"contact_person_role,omitempty"`
	ContactPersonPhone *string `json:"contact_person_phone,omitempty"`
	ContactPersonEmail *string `json:"contact_person_email,omitempty"`

	// Partnership Details
	PartnershipType      *string    `json:"partnership_type,omitempty"` // 'funding', 'implementation', 'technical'
	PartnershipStartDate *time.Time `json:"partnership_start_date,omitempty"`
	PartnershipEndDate   *time.Time `json:"partnership_end_date,omitempty"`
	PartnershipStatus    string     `json:"partnership_status"` // 'active', 'suspended', 'terminated'

	// Regions of Operation
	OperatingRegions []string `json:"operating_regions,omitempty"`
	FocusAreas       []string `json:"focus_areas,omitempty"` // ['child_health', 'hiv', 'nutrition']

	// Reporting Access
	CanAccessReports    bool        `json:"can_access_reports"`
	ReportAccessLevel   *string     `json:"report_access_level,omitempty"`   // 'summary', 'detailed', 'custom'
	CustomReportFilters interface{} `json:"custom_report_filters,omitempty"` // JSONB

	// Logo & Branding
	LogoURL       *string `json:"logo_url,omitempty"`
	BrandingColor *string `json:"branding_color,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ContactPersonInfo represents contact person information
type ContactPersonInfo struct {
	ID                 uuid.UUID `json:"id"`
	ContactPersonName  *string   `json:"contact_person_name,omitempty"`
	ContactPersonRole  *string   `json:"contact_person_role,omitempty"`
	ContactPersonPhone *string   `json:"contact_person_phone,omitempty"`
	ContactPersonEmail *string   `json:"contact_person_email,omitempty"`
}

// ReportAccessInfo represents report access information
type ReportAccessInfo struct {
	ID                  uuid.UUID   `json:"id"`
	OrganizationName    string      `json:"organization_name"`
	CanAccessReports    bool        `json:"can_access_reports"`
	ReportAccessLevel   *string     `json:"report_access_level,omitempty"`
	CustomReportFilters interface{} `json:"custom_report_filters,omitempty"`
}

// NGOBranding represents branding information
type NGOBranding struct {
	ID               uuid.UUID `json:"id"`
	OrganizationName string    `json:"organization_name"`
	LogoURL          *string   `json:"logo_url,omitempty"`
	BrandingColor    *string   `json:"branding_color,omitempty"`
}

// PartnershipStatistics represents statistics about partnerships
type PartnershipStatistics struct {
	TotalPartners              int64 `json:"total_partners"`
	ActivePartnerships         int64 `json:"active_partnerships"`
	SuspendedPartnerships      int64 `json:"suspended_partnerships"`
	TerminatedPartnerships     int64 `json:"terminated_partnerships"`
	WithReportAccess           int64 `json:"with_report_access"`
	InternationalNGOs          int64 `json:"international_ngos"`
	LocalNGOs                  int64 `json:"local_ngos"`
	AveragePartnershipDuration int64 `json:"average_partnership_duration_days"`
	ExpiringThisMonth          int64 `json:"expiring_this_month"`
	ExpiredPartnerships        int64 `json:"expired_partnerships"`
}

// OrganizationTypeDistribution represents distribution by organization type
type OrganizationTypeDistribution struct {
	OrganizationType *string `json:"organization_type,omitempty"`
	Count            int64   `json:"count"`
}

// PartnershipTypeDistribution represents distribution by partnership type
type PartnershipTypeDistribution struct {
	PartnershipType *string `json:"partnership_type,omitempty"`
	Count           int64   `json:"count"`
}

// FocusAreaDistribution represents distribution by focus area
type FocusAreaDistribution struct {
	FocusArea string `json:"focus_area"`
	Count     int64  `json:"count"`
}

// NGORegionCoverage represents NGO coverage by region
type NGORegionCoverage struct {
	Region   string `json:"region"`
	NGOCount int64  `json:"ngo_count"`
}

// ReportAccessStatistics represents statistics about report access
type ReportAccessStatistics struct {
	TotalWithAccess int64 `json:"total_with_access"`
	SummaryLevel    int64 `json:"summary_level"`
	DetailedLevel   int64 `json:"detailed_level"`
	CustomLevel     int64 `json:"custom_level"`
}

// PartnerContactDirectory represents contact directory entry
type PartnerContactDirectory struct {
	ID                 uuid.UUID `json:"id"`
	OrganizationName   string    `json:"organization_name"`
	ContactPersonName  *string   `json:"contact_person_name,omitempty"`
	ContactPersonRole  *string   `json:"contact_person_role,omitempty"`
	ContactPersonPhone *string   `json:"contact_person_phone,omitempty"`
	ContactPersonEmail *string   `json:"contact_person_email,omitempty"`
	OrganizationPhone  *string   `json:"organization_phone,omitempty"`
	OrganizationEmail  *string   `json:"organization_email,omitempty"`
}
