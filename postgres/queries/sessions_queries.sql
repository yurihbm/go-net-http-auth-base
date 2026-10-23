-- name: CreateUserSession :one
INSERT INTO user_sessions (user_uuid, current_jti, expires_at)
    VALUES ($1, $2, $3)
RETURNING
    *;

-- name: GetUserSession :one
SELECT
    *
FROM
    user_sessions
WHERE
    uuid = $1
    AND user_uuid = $2;

-- name: RotateUserSessionJTI :execrows
UPDATE
    user_sessions
SET
    current_jti = sqlc.arg(next_jti),
    last_used_at = now()
WHERE
    uuid = $1
    AND user_uuid = $2
    AND current_jti = sqlc.arg(current_jti);

-- name: DeleteUserSession :exec
DELETE FROM
    user_sessions
WHERE
    uuid = $1
    AND user_uuid = $2;

-- name: DeleteExpiredUserSessionsByUser :exec
DELETE FROM
    user_sessions
WHERE
    user_uuid = $1
    AND (expires_at < now()
        OR last_used_at < now() - sqlc.arg(idle_timeout)::interval);

-- name: DeleteOldestUserSessionsBeyond :exec
DELETE FROM
    user_sessions
WHERE
    uuid IN (
        SELECT
            s.uuid
        FROM
            user_sessions s
        WHERE
            s.user_uuid = $1
        ORDER BY
            s.last_used_at DESC,
            s.uuid DESC
        OFFSET sqlc.arg(keep)::int);
