-- name: CreateUser :one
INSERT INTO users (name, email, password_hash, auth_method)
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
    password_hash = COALESCE($4, password_hash),
    auth_method = COALESCE($5, auth_method)
WHERE
    uuid = $1;

-- name: DeleteUser :exec
DELETE FROM users
WHERE uuid = $1;

