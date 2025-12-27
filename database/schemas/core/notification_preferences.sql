-- ============================================
-- Notification Preferences
-- ============================================

CREATE TABLE notification_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    
    -- Channels
    sms_enabled BOOLEAN DEFAULT true,
    email_enabled BOOLEAN DEFAULT true,
    push_enabled BOOLEAN DEFAULT true,
    whatsapp_enabled BOOLEAN DEFAULT false,
    
    -- Notification Types
    appointment_reminders BOOLEAN DEFAULT true,
    appointment_reminder_hours_before INTEGER DEFAULT 24,
    
    health_tips BOOLEAN DEFAULT true,
    health_tips_frequency VARCHAR(20) DEFAULT 'weekly', -- 'daily', 'weekly', 'monthly'
    
    medication_reminders BOOLEAN DEFAULT false,
    prescription_updates BOOLEAN DEFAULT true,
    
    clinic_updates BOOLEAN DEFAULT true,
    newsletter BOOLEAN DEFAULT false,
    
    emergency_alerts BOOLEAN DEFAULT true,
    system_maintenance BOOLEAN DEFAULT true,
    
    -- Language Preferences
    notification_language VARCHAR(50) DEFAULT 'English',
    
    -- Quiet Hours
    quiet_hours_start TIME,
    quiet_hours_end TIME,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
