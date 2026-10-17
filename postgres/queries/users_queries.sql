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

-- name: UpdateUser :exec
UPDATE
    users
SET
    name = COALESCE($2, name),
    email = COALESCE($3, email),
    password_hash = COALESCE($4, password_hash)
WHERE
    uuid = $1;

-- name: MarkUserEmailVerified :exec
UPDATE
    users
SET
    email_verified = true
WHERE
    uuid = $1;

-- name: SetUserRefreshJTI :exec
UPDATE
    users
SET
    current_refresh_jti = $2
WHERE
    uuid = $1;

-- name: RotateUserRefreshJTI :execrows
UPDATE
    users
SET
    current_refresh_jti = sqlc.arg(next_jti)
WHERE
    uuid = $1
    AND current_refresh_jti = sqlc.arg(current_jti);

-- name: DeleteUser :exec
DELETE FROM 
    users
WHERE 
    uuid = $1;

