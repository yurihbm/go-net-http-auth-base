-- name: CreateAuditLog :exec
INSERT INTO audit_logs (
    actor_uuid,
    ip_address,
    user_agent,
    action,
    resource_type,
    resource_uuid,
    request_uuid,
    changes,
    status,
    failure_reason
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
);