-- SMS Indexes
CREATE INDEX idx_sms_phone ON sms_conversations(phone_number);
CREATE INDEX idx_sms_user ON sms_conversations(user_id);
CREATE INDEX idx_sms_conversation ON sms_messages(conversation_id, created_at);
CREATE INDEX idx_sms_twilio_id ON sms_messages(twilio_message_id);