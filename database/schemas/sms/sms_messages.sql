CREATE TABLE sms_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID REFERENCES sms_conversations(id) ON DELETE CASCADE,
    
    direction VARCHAR(10) NOT NULL, -- 'inbound', 'outbound'
    message_body TEXT NOT NULL,
    twilio_message_id VARCHAR(100),
    twilio_status VARCHAR(50),
    
    -- Timing
    sent_at TIMESTAMP,
    delivered_at TIMESTAMP,
    
    -- Cost
    segments INTEGER DEFAULT 1,
    cost DECIMAL(5,4),
    cost_currency VARCHAR(3) DEFAULT 'USD',
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

