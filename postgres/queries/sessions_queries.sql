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


-- name: SetUserSessionStepUp :execrows
UPDATE
    user_sessions
SET
    step_up_until = $3
WHERE
    uuid = $1
    AND user_uuid = $2;

-- name: IncrementUserSessionStepUpFailures :one
UPDATE
    user_sessions
SET
    step_up_failures = step_up_failures + 1
WHERE
    uuid = $1
    AND user_uuid = $2
RETURNING
    step_up_failures;

-- name: DeleteUserSessionsByUser :exec
DELETE FROM
    user_sessions
WHERE
    user_uuid = $1;

-- name: DeleteOtherUserSessionsByUser :exec
DELETE FROM
    user_sessions
WHERE
    user_uuid = $1
    AND uuid <> sqlc.arg(keep_uuid);
