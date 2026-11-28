# ADR-017: Feature Flags

- **Status:** Accepted
- **Date:** 2026-11-27

## Context

The frontend needs to know which features are enabled, either for everyone or
only for some users (beta, gradual rollout). The flags must change without a
redeploy. Environment variables would cover global switches, but they need a
restart and cannot target a user.

The alternatives considered were:

- environment variables in `config`, which are simple and validated at startup
  but static and global;
- an external service (OpenFeature, Unleash, Flagsmith), which adds an
  infrastructure dependency to a template that already has PostgreSQL;
- **tables in PostgreSQL**, managed by admins through the API.

## Decision

- Two tables: `feature_flags` (`key` unique, `description`, `enabled_globally`)
  and `feature_flag_users` (an allow-list, primary key `(flag_uuid, user_uuid)`,
  `ON DELETE CASCADE` from flags and from users).
- A flag is enabled for a user when `enabled_globally` is true **or** the user
  is in its allow-list. There is no deny-list. An anonymous caller only sees
  globally enabled flags.
- Admins manage flags and allow-lists under `/feature-flags` (create, list,
  read, update, delete, add and remove a user), behind the auth and admin role
  middlewares, and every change is written to the audit log.
- Any client reads its active flags with `GET /feature-flags/enabled`, which
  returns the enabled keys. The route uses an optional auth middleware: no
  access token cookie means anonymous, while a present but invalid or expired
  token is a 401, so the frontend refreshes the session instead of silently
  receiving only the global flags. The response varies by user, and the global
  `Cache-Control: no-store` of the security headers keeps it out of every cache.
- Services enforce flags with `IsEnabled(ctx, key, userUUID)`, so the backend
  does not depend on the UI hiding a feature.
- Flags are resolved with one query per request, without a cache.

## Consequences

- Flags change at runtime and can target single users, with no new
  infrastructure.
- Every `GET /feature-flags/enabled` call hits the database. The flag set is
  small and indexed; a cache can be added later without changing the contract,
  at the cost of a staleness window after an admin change.
- No percentage rollout and no deny-list: those need a new ADR.
- The optional auth middleware is a second way to authenticate a route; routes
  that need a session keep using `AuthMiddleware`.
