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
    @actor_uuid, @ip_address, @user_agent, @action, @resource_type, @resource_uuid, @request_uuid, @changes, @status, @failure_reason
);

-- name: ListAuditLogs :many
SELECT uuid, actor_uuid, ip_address, user_agent, action, resource_type, resource_uuid, request_uuid, changes, status, failure_reason, created_at
FROM audit_logs
WHERE
    (sqlc.narg(start_date)::timestamptz IS NULL OR created_at >= sqlc.narg(start_date)) AND
    (sqlc.narg(end_date)::timestamptz IS NULL OR created_at <= sqlc.narg(end_date)) AND
    (sqlc.narg(action)::text IS NULL OR action = sqlc.narg(action)) AND
    (sqlc.narg(resource_type)::text IS NULL OR resource_type = sqlc.narg(resource_type)) AND
    (sqlc.narg(status)::text IS NULL OR status = sqlc.narg(status)) AND
    (sqlc.narg(actor_uuid)::uuid IS NULL OR actor_uuid = sqlc.narg(actor_uuid)) AND
    (sqlc.narg(cursor)::uuid IS NULL OR uuid < sqlc.narg(cursor))
ORDER BY uuid DESC
LIMIT @page_size;

-- name: CountAuditLogs :one
SELECT COUNT(*)
FROM audit_logs
WHERE
    (sqlc.narg(start_date)::timestamptz IS NULL OR created_at >= sqlc.narg(start_date)) AND
    (sqlc.narg(end_date)::timestamptz IS NULL OR created_at < sqlc.narg(end_date)) AND
    (sqlc.narg(action)::text IS NULL OR action = sqlc.narg(action)) AND
    (sqlc.narg(resource_type)::text IS NULL OR resource_type = sqlc.narg(resource_type)) AND
    (sqlc.narg(status)::text IS NULL OR status = sqlc.narg(status)) AND
    (sqlc.narg(actor_uuid)::uuid IS NULL OR actor_uuid = sqlc.narg(actor_uuid));
