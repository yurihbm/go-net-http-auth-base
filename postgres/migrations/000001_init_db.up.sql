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
    created_at timestamptz DEFAULT now() NOT NULL,
    updated_at timestamptz DEFAULT now() NOT NULL
);

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
