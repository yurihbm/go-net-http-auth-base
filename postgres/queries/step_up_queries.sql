-- name: UpsertStepUpChallenge :one
INSERT INTO step_up_challenges (user_uuid, session_uuid, code_hash, expires_at)
    VALUES ($1, $2, $3, $4)
ON CONFLICT (session_uuid)
    DO UPDATE SET
        code_hash = EXCLUDED.code_hash,
        attempts = 0,
        expires_at = EXCLUDED.expires_at,
        created_at = now()
    WHERE
        step_up_challenges.created_at < now() - sqlc.arg(cooldown)::interval
RETURNING
    *;

-- name: AttemptStepUpChallenge :one
UPDATE
    step_up_challenges
SET
    attempts = attempts + 1
WHERE
    session_uuid = $1
    AND user_uuid = $2
    AND attempts < sqlc.arg(max_attempts)::int
    AND expires_at > now()
RETURNING
    code_hash,
    attempts;

-- name: DeleteStepUpChallenge :exec
DELETE FROM
    step_up_challenges
WHERE
    session_uuid = $1;
