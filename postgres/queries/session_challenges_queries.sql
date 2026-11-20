-- name: UpsertSessionChallenge :execrows
INSERT INTO session_challenges (user_uuid, session_uuid, purpose, new_email, email_version, code_hash, expires_at)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (session_uuid, purpose)
    DO UPDATE SET
        new_email = EXCLUDED.new_email,
        email_version = EXCLUDED.email_version,
        code_hash = EXCLUDED.code_hash,
        attempts = 0,
        expires_at = EXCLUDED.expires_at,
        created_at = now()
    WHERE
        session_challenges.created_at < now() - sqlc.arg(cooldown)::interval;

-- name: GetSessionChallenge :one
SELECT
    *
FROM
    session_challenges
WHERE
    session_uuid = $1
    AND user_uuid = $2
    AND purpose = $3
    AND expires_at > now();

-- name: AttemptSessionChallenge :one
UPDATE
    session_challenges
SET
    attempts = attempts + 1
WHERE
    session_uuid = $1
    AND user_uuid = $2
    AND purpose = $3
    AND attempts < sqlc.arg(max_attempts)::int
    AND expires_at > now()
RETURNING
    *;

-- name: DeleteSessionChallenge :exec
DELETE FROM
    session_challenges
WHERE
    session_uuid = $1
    AND purpose = $2;

-- name: DeleteExpiredSessionChallengesBatch :execrows
DELETE FROM
    session_challenges
WHERE
    uuid IN (
        SELECT
            c.uuid
        FROM
            session_challenges c
        WHERE
            c.expires_at < now()
        LIMIT sqlc.arg(batch_size)::int);
