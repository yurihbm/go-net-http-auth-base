-- name: CreatePasswordReset :one
INSERT INTO password_resets (uuid, user_uuid, email, email_version, code_hash, expires_at)
    VALUES ($1, $2, $3, $4, $5, $6)
RETURNING
    *;

-- name: GetPasswordReset :one
SELECT
    *
FROM
    password_resets
WHERE
    uuid = $1
    AND expires_at > now();

-- name: AttemptPasswordReset :one
UPDATE
    password_resets
SET
    attempts = attempts + 1
WHERE
    uuid = $1
    AND attempts < sqlc.arg(max_attempts)::int
    AND expires_at > now()
RETURNING
    *;

-- name: ConsumePasswordReset :one
DELETE FROM
    password_resets
WHERE
    uuid = $1
    AND code_hash = $2
    AND expires_at > now()
RETURNING
    *;

-- name: DeletePasswordReset :exec
DELETE FROM
    password_resets
WHERE
    uuid = $1;

-- name: DeletePasswordResetsByUser :exec
DELETE FROM
    password_resets
WHERE
    user_uuid = $1;

-- name: DeleteExpiredPasswordResetsBatch :execrows
DELETE FROM
    password_resets
WHERE
    uuid IN (
        SELECT
            p.uuid
        FROM
            password_resets p
        WHERE
            p.expires_at < now()
        LIMIT sqlc.arg(batch_size)::int);
