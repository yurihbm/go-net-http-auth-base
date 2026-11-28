-- name: CreateFeatureFlag :one
INSERT INTO feature_flags (key, description, enabled_globally)
    VALUES ($1, $2, $3)
RETURNING
    *;

-- name: GetFeatureFlagDetailsByUUID :one
SELECT
    f.*,
    COALESCE(array_agg(u.user_uuid ORDER BY u.user_uuid) FILTER (WHERE u.user_uuid IS NOT NULL), '{}')::uuid[] AS user_uuids
FROM
    feature_flags f
    LEFT JOIN feature_flag_users u ON u.flag_uuid = f.uuid
WHERE
    f.uuid = $1
GROUP BY
    f.uuid;

-- name: UpdateFeatureFlag :one
UPDATE
    feature_flags
SET
    description = COALESCE(sqlc.narg(description), description),
    enabled_globally = COALESCE(sqlc.narg(enabled_globally), enabled_globally)
WHERE
    uuid = $1
RETURNING
    *;

-- name: DeleteFeatureFlag :execrows
DELETE FROM feature_flags
WHERE uuid = $1;

-- name: ListFeatureFlags :many
SELECT
    *
FROM
    feature_flags
WHERE (sqlc.narg(cursor)::uuid IS NULL
    OR uuid < sqlc.narg(cursor))
ORDER BY
    uuid DESC
LIMIT @page_size;

-- name: CountFeatureFlags :one
SELECT
    COUNT(*)
FROM
    feature_flags;

-- name: AddFeatureFlagUser :exec
INSERT INTO feature_flag_users (flag_uuid, user_uuid)
    VALUES ($1, $2)
ON CONFLICT (flag_uuid, user_uuid)
    DO NOTHING;

-- name: RemoveFeatureFlagUser :execrows
DELETE FROM feature_flag_users
WHERE flag_uuid = $1
    AND user_uuid = $2;

-- name: ListEnabledFeatureFlagKeys :many
SELECT
    f.key
FROM
    feature_flags f
WHERE
    f.enabled_globally
    OR (sqlc.narg(user_uuid)::uuid IS NOT NULL
        AND EXISTS (
            SELECT
                1
            FROM
                feature_flag_users u
            WHERE
                u.flag_uuid = f.uuid
                AND u.user_uuid = sqlc.narg(user_uuid)))
ORDER BY
    f.key;
