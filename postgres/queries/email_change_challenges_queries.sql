-- name: UpsertEmailChangeChallenge :one
INSERT INTO email_change_challenges (user_uuid, session_uuid, new_email, email_version, code_hash, expires_at)
    VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (session_uuid)
    DO UPDATE SET
        new_email = EXCLUDED.new_email,
        email_version = EXCLUDED.email_version,
        code_hash = EXCLUDED.code_hash,
        attempts = 0,
        expires_at = EXCLUDED.expires_at,
        created_at = now()
    WHERE
        email_change_challenges.created_at < now() - sqlc.arg(cooldown)::interval
RETURNING
    *;

-- name: AttemptEmailChangeChallenge :one
UPDATE
    email_change_challenges
SET
    attempts = attempts + 1
WHERE
    session_uuid = $1
    AND user_uuid = $2
    AND attempts < sqlc.arg(max_attempts)::int
    AND expires_at > now()
RETURNING
    *;

-- name: DeleteEmailChangeChallenge :exec
DELETE FROM
    email_change_challenges
WHERE
    session_uuid = $1;

-- name: DeleteExpiredEmailChangeChallengesBatch :execrows
DELETE FROM
    email_change_challenges
WHERE
    uuid IN (
        SELECT
            c.uuid
        FROM
            email_change_challenges c
        WHERE
            c.expires_at < now()
        LIMIT sqlc.arg(batch_size)::int);
