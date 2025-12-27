-- ============================================
-- Activity & Audit Logging
-- ============================================

CREATE TABLE user_activities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    
    activity_type VARCHAR(100) NOT NULL,
    activity_details JSONB,
    
    -- Device & Location
    ip_address INET,
    user_agent TEXT,
    device_type VARCHAR(50),
    device_id VARCHAR(255),
    location JSONB, -- Store geolocation data
    
    -- Resource
    resource_type VARCHAR(100), -- 'appointment', 'chat', 'profile', etc.
    resource_id UUID,
    
    -- Timestamps
    performed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
