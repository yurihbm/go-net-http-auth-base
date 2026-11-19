-- name: CreatePendingSignup :one
INSERT INTO pending_signups (uuid, kind, name, email, password_hash, provider, provider_user_id, code_hash, code_expires_at, expires_at)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING
    *;

-- name: GetPendingSignup :one
SELECT
    *
FROM
    pending_signups
WHERE
    uuid = $1
    AND expires_at > now();

-- name: AttemptPendingSignup :one
UPDATE
    pending_signups
SET
    attempts = attempts + 1
WHERE
    uuid = $1
    AND attempts < sqlc.arg(max_attempts)::int
    AND code_expires_at > now()
    AND expires_at > now()
RETURNING
    *;

-- name: ConsumePendingSignup :one
DELETE FROM
    pending_signups
WHERE
    uuid = $1
    AND code_hash = $2
RETURNING
    *;

-- name: ResendPendingSignup :one
UPDATE
    pending_signups
SET
    code_hash = $2,
    code_expires_at = LEAST(now() + sqlc.arg(code_ttl)::interval, expires_at),
    attempts = 0,
    last_sent_at = now()
WHERE
    uuid = $1
    AND last_sent_at < now() - sqlc.arg(cooldown)::interval
    AND expires_at > now()
RETURNING
    *;

-- name: DeletePendingSignup :exec
DELETE FROM
    pending_signups
WHERE
    uuid = $1;

-- name: DeleteExpiredPendingSignupsBatch :execrows
DELETE FROM
    pending_signups
WHERE
    uuid IN (
        SELECT
            p.uuid
        FROM
            pending_signups p
        WHERE
            p.expires_at < now()
        LIMIT sqlc.arg(batch_size)::int);
