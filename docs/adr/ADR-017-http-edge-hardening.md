# ADR-017: HTTP Edge Hardening

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

The API answered without any browser-facing security headers, and its only
rate limit was one token bucket per client IP for every route (ADR-005,
ADR-013). That bucket is generous on purpose (20 requests per second), so it
does not slow down credential guessing, code submission or email-triggering
endpoints. It also keyed an IPv6 client by its full address, while a single
subscriber usually controls a whole /64 and can rotate through 2^64 addresses.

## Decision

- **Security headers.** `SecurityHeadersMiddleware` is a global middleware placed
  right after the client IP middleware, outside recover, CORS and the rate
  limiter, so 429 and panic 500 responses carry the headers too. It sets
  `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`,
  `Referrer-Policy: no-referrer` and
  `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` on every
  response, plus `Strict-Transport-Security: max-age=31536000; includeSubDomains`
  when the app runs over HTTPS (the same signal as the `Secure` cookie flag: not
  development).
- **Swagger UI exception.** The login gate (`GET /swagger/`) and the Swagger UI
  (`GET /swagger/...`) need same-origin assets and inline scripts and styles, so
  `DocsController` overrides the CSP with
  `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'`.
  Both stay behind the auth and admin role middlewares (except the gate).
- **Credential limiter.** A second, stricter per-IP token bucket
  (`RATE_LIMIT_CREDENTIALS_PER_MINUTE`, default 5, and
  `RATE_LIMIT_CREDENTIALS_BURST`, default 10) wraps, as the outermost route
  middleware, the endpoints where an anonymous or session-bound caller can guess
  secrets or trigger emails: `POST /auth/login`, `POST /users`,
  `POST /auth/signup/verify`, `POST /auth/signup/resend`,
  `POST /auth/password/forgot`, `POST /auth/password/reset`,
  `POST /users/revert-email-change`, `POST /auth/oauth/revert-link`,
  `POST /auth/step-up` and `POST /auth/step-up/verify`. It shares the limiter
  code of the global one (`CredentialsRateLimitMiddleware` is a
  `HandlerMiddleware` over the same store), answers the same
  `429 rateLimit.exceeded` and sets the same `X-RateLimit-*` headers. It is built
  once in `NewHandler` (it needs the context that stops its cleanup goroutine)
  and injected into the auth and users controllers.
  Refresh, logout and the OAuth login and callback are excluded: refresh is
  called automatically by clients and holds a rotating secret with its own
  reuse detection, and OAuth redirects come from browsers and providers, where a
  429 would break the flow without protecting a secret.
- **IPv6 keying.** Both limiters key an IPv6 address by its /64 prefix.
  IPv4-mapped IPv6 addresses count as IPv4. A key that does not parse as an IP
  falls back to the raw string.
- **No cap on the visitor maps.** Idle entries are still swept after 3 minutes
  and the maps are unbounded. With /64 aggregation, filling them takes botnet
  scale, which the per-instance limiter does not defend against anyway.
- **Cookies stay host-only without prefixes.** `access_token` and
  `refresh_token` have no `Domain` attribute but are not `__Host-` or
  `__Secure-` prefixed. Accepted risk: a compromised sibling subdomain could plant
  a cookie on the host (cookie tossing, login CSRF). Prefixes were not adopted so
  projects remain free to scope the cookies to a parent `Domain`. The short-lived
  `pending_signup` and `password_reset` cookies already use `__Host-`.

## Consequences

- Every response is `no-store`, so browsers and proxies do not cache API
  responses.
- Brute-forcing logins and codes from one IP (or one IPv6 /64) is limited to the
  burst plus the per-minute rate. Shared IPs (offices, carrier NAT) share the
  credential bucket, so the defaults trade some friction for safety and can be
  raised through the environment.
- Limits stay per instance and in memory: running N instances multiplies the
  effective limit, as accepted in ADR-005.
- The Swagger UI CSP allows inline scripts, so it must stay behind the admin
  role.
- E2E tests share the `127.0.0.1` bucket, so their config sets high credential
  limits.
