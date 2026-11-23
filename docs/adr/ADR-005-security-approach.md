# ADR-005: Security Approach

- **Status:** Accepted; the Microsoft linking statement is superseded by ADR-009 and the rate limiter proxy statement by ADR-013
- **Date:** 2026-11-14

## Context

The template ships authentication (email/password and OAuth with Google, GitHub
and Microsoft) that is meant to be reused as-is by every service built from it,
for both web and mobile clients. Mistakes here spread to every bootstrap, so the
defaults must be safe. The main threats considered:

- stolen or replayed tokens, and sessions that never end;
- XSS reading tokens, and CSRF / login CSRF;
- OAuth account takeover by email matching (nOAuth, pre-hijacking) and open
  redirects;
- brute force and abusive clients;
- forged tokens from a missing or weak signing secret;
- insecure direct object references (IDOR) on user endpoints.

## Decision

**Tokens and sessions**

- Short-lived HS256 JWTs signed by a single `TokenService`. The secret must be
  at least 32 characters or the app refuses to boot. Every token carries an
  audience (access, refresh, OAuth state, email verification) checked on
  verification.
- Access tokens last 15 minutes and refresh tokens 7 days. Both are sent only as
  `HttpOnly`, `SameSite=Strict` cookies, `Secure` outside development. The
  refresh cookie is scoped to `Path=/auth/refresh`.
- **Server-side, per-device sessions** (`user_sessions`). Each login creates a
  session with an absolute `expires_at` (`SESSION_MAX_AGE`, never extended).
  Each user keeps at most `MAX_SESSIONS_PER_USER` sessions, and the least
  recently used one is evicted. Refresh tokens carry `sid` + `jti`, and the
  `jti` is rotated with a compare-and-set on every refresh:

![Refresh token rotation and reuse detection](diagrams/refresh-token-rotation.svg)

<sub>[Diagram source](diagrams/refresh-token-rotation.json) ([how to view it interactively](README.md#diagrams))</sub>

- A reused or stale refresh token, an expired session or a lost concurrent
  refresh deletes **only that session**, so the user's other devices stay signed
  in. Logout deletes the current session.

**OAuth**

- The state JWT embeds a random nonce that is also stored in a short-lived
  cookie (`__Host-` prefix outside development), which binds the callback to the
  browser that started the flow. PKCE (`S256`) is used on every provider.
- `redirect_uri` must exactly match `OAUTH_CALLBACK_ALLOW_LIST`, which is
  required in production. This is checked before the state is minted.
- Accounts are created from a provider identity only when the provider says the
  email is verified. Linking into an existing account also requires the local
  email to be verified. Emails are normalized (trim + lowercase) and unique on
  `lower(email)`.

**Authorization and passwords**

- `AuthMiddleware` verifies the access token, and `RoleMiddleware` reads the role
  from the token without a database lookup. User read/update/delete enforce
  self-or-admin in the service (`Actor.CanAccess`).
- Passwords are hashed with `bcrypt` (default cost).

**HTTP perimeter**

- Global middleware order:
  `requestContextData → requestUUID → telemetry → logger → cors → rateLimit → mux`.
- CORS is an exact-match allow list. `Vary: Origin` is always set, and preflights
  from disallowed origins get 403.
- Per-IP token-bucket rate limiting (`RATE_LIMIT_REQUESTS_PER_SECOND`,
  `RATE_LIMIT_BURST`) keyed on the remote address without the port, returning
  429 and `X-RateLimit-*` headers.
- Security-relevant actions (login, logout, user changes) are written to the
  audit log ([`docs/AUDIT.md`](../AUDIT.md)).

## Consequences

**Positive**

- A stolen refresh token is detected on its first reuse and can be revoked per
  device. No session outlives `SESSION_MAX_AGE`.
- Tokens are never readable from JavaScript, and `SameSite=Strict` plus exact
  CORS origins block cross-site use.
- OAuth flows resist login CSRF, open redirects and takeover through unverified
  emails.

**Negative / accepted residual risk**

- Access tokens are stateless and remain valid for up to 15 minutes after logout
  or session revocation.
- There is no grace window for concurrent refreshes. Two parallel refreshes with
  the same token revoke the session, so clients must serialize refreshes.
- Refresh and logout read tokens from cookies only. Mobile clients need a
  header- or body-based transport, which is a follow-up.
- The rate limiter is in memory and per instance, and it ignores
  `X-Forwarded-For`. Behind a proxy or across several replicas it needs a shared
  store and a trusted-proxy policy.
- There is no per-account login throttling, and login timing allows user
  enumeration. This is deferred, because `POST /users` already reveals taken
  emails with 409.
- The OAuth state JWT is not single-use within its 5-minute lifetime. Microsoft
  never reports a verified email, so it can only link into existing verified
  accounts.
- There are no logout-all or list/revoke-sessions endpoints yet, and a password
  change does not revoke existing sessions.
