-- Data access audit log (POPIA compliance)
CREATE TABLE data_access_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Who accessed
    accessed_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    accessed_by_role VARCHAR(50),
    
    -- What was accessed
    accessed_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    accessed_resource_type VARCHAR(100),
    accessed_resource_id UUID,
    
    -- Access Details
    access_type VARCHAR(50), -- 'view', 'edit', 'export', 'delete'
    access_reason TEXT,
    is_emergency_access BOOLEAN DEFAULT false,
    
    -- Context
    ip_address INET,
    user_agent TEXT,
    location JSONB,
    
    accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

