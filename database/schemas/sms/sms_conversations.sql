-- ============================================
-- SMS Communication Tracking
-- ============================================

CREATE TABLE sms_conversations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    phone_number VARCHAR(20) NOT NULL,
    
    -- Conversation State
    current_menu VARCHAR(50), -- 'main', 'clinic_search', 'nutrition', 'callback'
    conversation_state JSONB,
    
    -- Last Interaction
    last_message_sent TEXT,
    last_message_received TEXT,
    last_interaction_at TIMESTAMP,
    
    -- Context
    last_location JSONB,
    last_search_query TEXT,
    callback_scheduled TIMESTAMP,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

