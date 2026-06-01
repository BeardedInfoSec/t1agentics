-- 026: In-app notification inbox
-- Stores notifications for the bell icon dropdown

CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    user_id UUID,                          -- NULL = broadcast to all tenant users
    title VARCHAR(255) NOT NULL,
    message TEXT,
    category VARCHAR(50) NOT NULL DEFAULT 'system',  -- system, alert, investigation, billing, security
    severity VARCHAR(20) DEFAULT 'info',             -- info, warning, error, critical
    link VARCHAR(500),                               -- optional deep-link (e.g. /investigations/INV-xxx)
    read BOOLEAN DEFAULT FALSE,
    read_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_notifications_tenant_user ON notifications(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_notifications_unread ON notifications(tenant_id, user_id, read) WHERE read = FALSE;
CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(created_at DESC);
