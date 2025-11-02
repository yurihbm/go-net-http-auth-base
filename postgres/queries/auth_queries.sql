-- name: CreateUserOAuthProvider :one
INSERT INTO user_oauth_providers (
    user_uuid,
    provider,
    provider_user_id,
    provider_email
) VALUES (
    $1,
    $2,
    $3,
    $4
) RETURNING *;

-- name: GetUserOAuthProviderByProviderAndProviderUserID :one
SELECT
    uuid,
    user_uuid,
    provider,
    provider_user_id,
    provider_email,
    created_at
FROM user_oauth_providers
WHERE
    provider = $1 AND provider_user_id = $2;

-- name: DeleteUserOAuthProvider :exec
DELETE FROM user_oauth_providers
WHERE
    uuid = $1;

-- name: ListUserOAuthProvidersByUserUUID :many
SELECT
    uuid,
    user_uuid,
    provider,
    provider_user_id,
    provider_email,
    created_at
FROM user_oauth_providers
WHERE
    user_uuid = $1;
