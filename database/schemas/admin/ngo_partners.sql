CREATE TABLE ngo_partners (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    
    -- Organization Details
    organization_name VARCHAR(255) NOT NULL,
    organization_type VARCHAR(100), -- 'international', 'local', 'government', 'religious'
    registration_number VARCHAR(100),
    tax_id VARCHAR(100),
    
    -- Contact Information
    organization_address TEXT,
    organization_phone VARCHAR(20),
    organization_email VARCHAR(255),
    website VARCHAR(255),
    
    -- Primary Contact
    contact_person_name VARCHAR(255),
    contact_person_role VARCHAR(100),
    contact_person_phone VARCHAR(20),
    contact_person_email VARCHAR(255),
    
    -- Partnership Details
    partnership_type VARCHAR(50), -- 'funding', 'implementation', 'technical'
    partnership_start_date DATE,
    partnership_end_date DATE,
    partnership_status VARCHAR(20) DEFAULT 'active',
    
    -- Regions of Operation
    operating_regions VARCHAR(255)[],
    focus_areas VARCHAR(255)[], -- ['child_health', 'hiv', 'nutrition']
    
    -- Reporting Access
    can_access_reports BOOLEAN DEFAULT false,
    report_access_level VARCHAR(50), -- 'summary', 'detailed', 'custom'
    custom_report_filters JSONB,
    
    -- Logo & Branding
    logo_url TEXT,
    branding_color VARCHAR(20),
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
