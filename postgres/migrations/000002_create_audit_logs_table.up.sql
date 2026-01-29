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