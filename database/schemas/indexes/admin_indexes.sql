-- Admin Indexes
CREATE INDEX idx_admin_level ON system_admins(admin_level);
CREATE INDEX idx_ngo_status ON ngo_partners(partnership_status);
CREATE INDEX idx_ngo_regions ON ngo_partners(operating_regions);