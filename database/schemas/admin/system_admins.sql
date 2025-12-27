-- ============================================
-- System Administration & NGO Partners
-- ============================================

CREATE TABLE system_admins (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    
    -- Admin Details
    admin_level VARCHAR(50) NOT NULL, -- 'super_admin', 'regional_admin', 'support_admin'
    assigned_regions VARCHAR(255)[], -- For regional admins
    department VARCHAR(100),
    
    -- Permissions
    permissions JSONB NOT NULL, -- Store permission flags
    can_manage_users BOOLEAN DEFAULT false,
    can_manage_clinics BOOLEAN DEFAULT false,
    can_manage_content BOOLEAN DEFAULT false,
    can_view_analytics BOOLEAN DEFAULT false,
    can_manage_system BOOLEAN DEFAULT false,
    
    -- Contact
    work_phone VARCHAR(20),
    extension VARCHAR(20),
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

