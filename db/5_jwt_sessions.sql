-- выполнить под postgres в базе tournament_db после 4_security.sql

CREATE TABLE IF NOT EXISTS user_sessions (
    id                   UUID PRIMARY KEY,
    username             VARCHAR(100) NOT NULL,
    device_id            VARCHAR(255),
    access_token         TEXT NOT NULL,
    refresh_token        TEXT NOT NULL,
    access_token_expiry  TIMESTAMP WITH TIME ZONE NOT NULL,
    refresh_token_expiry TIMESTAMP WITH TIME ZONE NOT NULL,
    status               VARCHAR(20) NOT NULL CHECK (status IN ('ACTIVE', 'USED', 'REVOKED')),
    CONSTRAINT uq_user_sessions_refresh_token UNIQUE (refresh_token)
);

CREATE INDEX IF NOT EXISTS idx_user_sessions_username ON user_sessions (username);
CREATE INDEX IF NOT EXISTS idx_user_sessions_status ON user_sessions (status);

GRANT SELECT, INSERT, UPDATE, DELETE ON user_sessions TO tournament_app;
