-- ============================================
-- CONSULTATION MESSAGES REPOSITORY QUERIES
-- Maps to: ConsultationMessageRepository interface
-- Domain: Telemedicine / Real-time Chat
-- ============================================

-- ============================================
-- SCHEMA
-- ============================================

CREATE TABLE consultation_messages (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    consultation_id UUID NOT NULL REFERENCES consultations(id) ON DELETE CASCADE,
    sender_user_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    sender_role     VARCHAR(20) NOT NULL,
        -- 'patient' | 'provider' | 'system'
    message_type    VARCHAR(30) NOT NULL DEFAULT 'text',
        -- 'text' | 'attachment' | 'system_event' | 'prescription'

    -- Content: text messages or system event descriptions
    content         TEXT,

    -- Attachments (photo, document, lab result, prescription PDF)
    attachment_url       TEXT,
    attachment_type      VARCHAR(50),
        -- 'photo' | 'document' | 'lab_result' | 'prescription_pdf'
    attachment_filename  VARCHAR(255),

    -- Read state (for the receiving party)
    is_read     BOOLEAN   NOT NULL DEFAULT false,
    read_at     TIMESTAMP,

    -- Soft delete (preserves audit trail; content NULLed server-side)
    is_deleted  BOOLEAN   NOT NULL DEFAULT false,

    -- Extensible metadata (video call SID, system event type, etc.)
    metadata    JSONB,

    sent_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT valid_sender_role CHECK (
        sender_role IN ('patient', 'provider', 'system')
    ),
    CONSTRAINT valid_message_type CHECK (
        message_type IN ('text', 'attachment', 'system_event', 'prescription')
    ),
    CONSTRAINT content_or_attachment CHECK (
        content IS NOT NULL OR attachment_url IS NOT NULL
    )
);

CREATE INDEX idx_messages_consultation ON consultation_messages(consultation_id, sent_at ASC);
CREATE INDEX idx_messages_unread ON consultation_messages(consultation_id, is_read)
    WHERE is_read = false AND is_deleted = false;
CREATE INDEX idx_messages_after_timestamp ON consultation_messages(consultation_id, sent_at)
    WHERE is_deleted = false;
