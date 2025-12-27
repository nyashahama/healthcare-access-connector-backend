-- Professional credentials
CREATE TABLE professional_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    staff_id UUID REFERENCES clinic_staff(id) ON DELETE CASCADE,
    credential_type VARCHAR(100) NOT NULL, -- 'professional_license', 'specialization', 'degree', 'certification'
    credential_number VARCHAR(100),
    issuing_authority VARCHAR(255) NOT NULL,
    issue_date DATE,
    expiry_date DATE,
    status VARCHAR(20) DEFAULT 'pending', -- 'verified', 'pending', 'expired', 'revoked'
    verified_by UUID REFERENCES users(id),
    verification_date TIMESTAMP,
    document_url TEXT,
    notes TEXT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

