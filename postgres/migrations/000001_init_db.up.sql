CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TYPE user_role AS ENUM (
    'admin',
    'user'
);

CREATE TABLE users (
    uuid uuid DEFAULT uuidv7() NOT NULL UNIQUE PRIMARY KEY,
    name text NOT NULL,
    email text UNIQUE NOT NULL,
    password_hash text,
    role user_role NOT NULL DEFAULT 'user',
    email_version int NOT NULL DEFAULT 0,
    email_changed_at timestamptz,
    step_up_failures int NOT NULL DEFAULT 0,
    step_up_failures_window_start timestamptz,
    previous_email text,
    created_at timestamptz DEFAULT now() NOT NULL,
    updated_at timestamptz DEFAULT now() NOT NULL
);

CREATE UNIQUE INDEX users_email_lower_key ON users (lower(email));
CREATE INDEX idx_users_previous_email_lower ON users (lower(previous_email)) WHERE previous_email IS NOT NULL;

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS trigger
AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$
LANGUAGE 'plpgsql';

CREATE TRIGGER update_users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE PROCEDURE update_updated_at_column();

CREATE TYPE oauth_provider AS ENUM (
    'google',
    'microsoft',
    'github'
);

CREATE TABLE user_oauth_providers (
    uuid uuid DEFAULT uuidv7() NOT NULL UNIQUE PRIMARY KEY,
    user_uuid uuid REFERENCES users (uuid) ON DELETE CASCADE,
    provider oauth_provider NOT NULL,
    provider_user_id text NOT NULL,
    provider_email text NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL,
    UNIQUE (provider, provider_user_id)
);

CREATE INDEX idx_user_oauth_providers_user_created ON user_oauth_providers (user_uuid, created_at);

CREATE TABLE user_sessions (
    uuid uuid DEFAULT uuidv7() NOT NULL UNIQUE PRIMARY KEY,
    user_uuid uuid NOT NULL REFERENCES users (uuid) ON DELETE CASCADE,
    current_jti text NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL,
    last_used_at timestamptz DEFAULT now() NOT NULL,
    expires_at timestamptz NOT NULL,
    step_up_until timestamptz,
    step_up_failures int NOT NULL DEFAULT 0
);

CREATE INDEX idx_user_sessions_user_last_used ON user_sessions (user_uuid, last_used_at);

CREATE INDEX idx_user_sessions_expires_at ON user_sessions (expires_at);

CREATE INDEX idx_user_sessions_last_used_at ON user_sessions (last_used_at);

CREATE TYPE session_challenge_purpose AS ENUM (
    'step_up',
    'email_change'
);

CREATE TABLE session_challenges (
    uuid uuid DEFAULT uuidv7() NOT NULL UNIQUE PRIMARY KEY,
    user_uuid uuid NOT NULL REFERENCES users (uuid) ON DELETE CASCADE,
    session_uuid uuid NOT NULL REFERENCES user_sessions (uuid) ON DELETE CASCADE,
    purpose session_challenge_purpose NOT NULL,
    new_email text,
    email_version int,
    code_hash text NOT NULL,
    attempts int NOT NULL DEFAULT 0,
    expires_at timestamptz NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL,
    UNIQUE (session_uuid, purpose),
    CONSTRAINT session_challenges_purpose_fields CHECK (
        (purpose = 'step_up' AND new_email IS NULL AND email_version IS NULL)
        OR (purpose = 'email_change' AND new_email IS NOT NULL AND email_version IS NOT NULL)
    )
);

CREATE INDEX idx_session_challenges_user ON session_challenges (user_uuid);

CREATE INDEX idx_session_challenges_expires_at ON session_challenges (expires_at);

CREATE TYPE pending_signup_kind AS ENUM (
    'credentials',
    'oauth'
);

CREATE TABLE pending_signups (
    uuid uuid DEFAULT uuidv7() NOT NULL UNIQUE PRIMARY KEY,
    kind pending_signup_kind NOT NULL,
    name text NOT NULL,
    email text NOT NULL,
    password_hash text,
    provider oauth_provider,
    provider_user_id text,
    code_hash text NOT NULL,
    attempts int NOT NULL DEFAULT 0,
    code_expires_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT pending_signups_kind_fields CHECK (
        (kind = 'credentials' AND password_hash IS NOT NULL AND provider IS NULL AND provider_user_id IS NULL)
        OR (kind = 'oauth' AND password_hash IS NULL AND provider IS NOT NULL AND provider_user_id IS NOT NULL)
    )
);

CREATE INDEX idx_pending_signups_expires_at ON pending_signups (expires_at);

CREATE TABLE email_send_limits (
    email text NOT NULL PRIMARY KEY,
    window_start timestamptz DEFAULT now() NOT NULL,
    sends int NOT NULL DEFAULT 0,
    last_sent_at timestamptz,
    failures int NOT NULL DEFAULT 0,
    failures_window_start timestamptz
);

CREATE INDEX idx_email_send_limits_window_start ON email_send_limits (window_start);

CREATE TABLE audit_logs (
    uuid uuid DEFAULT uuidv7() NOT NULL,
    actor_uuid UUID, -- Nullable for system actions or anonymous users
    ip_address TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_uuid TEXT NOT NULL,
    request_uuid UUID NOT NULL,
    changes JSONB, -- Old and New values
    status TEXT NOT NULL,
    failure_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Including partition key in Primary Key is required for partitioned tables
    PRIMARY KEY (uuid, created_at)
) PARTITION BY RANGE (created_at);

-- Create default partition to catch any data that doesn't fit into specific partitions
-- This is crucial for fallback if the partition manager fails or for past data
CREATE TABLE audit_logs_default PARTITION OF audit_logs DEFAULT;

-- Index on request_uuid for correlation lookups
CREATE INDEX idx_audit_logs_request ON audit_logs(request_uuid);

-- Index on resource_uuid and type for finding history of an object
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_uuid);

-- Index on actor_uuid
CREATE INDEX idx_audit_logs_actor ON audit_logs(actor_uuid);
