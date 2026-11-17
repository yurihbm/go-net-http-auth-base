-- name: CreateUser :one
INSERT INTO users (name, email, password_hash, email_verified)
    VALUES ($1, $2, $3, $4)
RETURNING
    *;

-- name: GetUserByUUID :one
SELECT
    *
FROM
    users
WHERE
    uuid = $1;

-- name: GetUserByEmail :one
SELECT
    *
FROM
    users
WHERE
   email = $1;

-- name: ListUsers :many
SELECT
    *
FROM
    users
ORDER BY
    created_at DESC
LIMIT $1 OFFSET $2;

-- name: UpdateUser :one
UPDATE
    users
SET
    name = COALESCE($2, name),
    password_hash = COALESCE($3, password_hash)
WHERE
    uuid = $1
RETURNING
    *;

-- name: UpdateUserEmail :one
UPDATE
    users
SET
    email = $2,
    email_verified = true,
    email_version = email_version + 1,
    email_changed_at = sqlc.narg(changed_at)
WHERE
    uuid = $1
    AND email_version = sqlc.arg(expected_version)
RETURNING
    *;

-- name: RecordUserStepUpFailure :one
UPDATE
    users
SET
    step_up_failures = CASE WHEN step_up_failures_window_start IS NULL
        OR step_up_failures_window_start < now() - sqlc.arg(failure_window)::interval THEN
        1
    ELSE
        step_up_failures + 1
    END,
    step_up_failures_window_start = CASE WHEN step_up_failures_window_start IS NULL
        OR step_up_failures_window_start < now() - sqlc.arg(failure_window)::interval THEN
        now()
    ELSE
        step_up_failures_window_start
    END
WHERE
    uuid = $1
RETURNING
    step_up_failures;

-- name: MarkUserEmailVerified :exec
UPDATE
    users
SET
    email_verified = true
WHERE
    uuid = $1;

-- name: DeleteUser :exec
DELETE FROM 
    users
WHERE 
    uuid = $1;

