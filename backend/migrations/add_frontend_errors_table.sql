-- Frontend error tracking table
-- Stores error reports sent from the frontend ErrorBoundary component
-- for monitoring and debugging purposes.

CREATE TABLE IF NOT EXISTS frontend_errors (
    id SERIAL PRIMARY KEY,
    error TEXT NOT NULL,
    component_stack TEXT,
    url VARCHAR(500),
    user_agent VARCHAR(500),
    client_ip VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_frontend_errors_created_at ON frontend_errors(created_at DESC);
