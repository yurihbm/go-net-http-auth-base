---
paths:
  - "internal/services/auth_service*.go"
  - "internal/services/users_service*.go"
  - "internal/services/step_up_service*.go"
  - "internal/services/pending_signup_service*.go"
  - "internal/services/email_verification_service*.go"
  - "internal/services/token_service*.go"
  - "internal/services/otp*.go"
  - "internal/controllers/auth_controller*.go"
  - "internal/controllers/users_controller*.go"
  - "internal/repositories/auth_repository*.go"
  - "internal/repositories/users_repository*.go"
  - "internal/repositories/sessions_repository*.go"
  - "internal/repositories/session_challenges_repository*.go"
  - "internal/repositories/pending_signups_repository*.go"
  - "internal/repositories/email_send_limits_repository*.go"
  - "internal/repositories/*_transaction_test.go"
  - "internal/middlewares/auth_middleware*.go"
  - "internal/middlewares/step_up_middleware*.go"
  - "internal/middlewares/role_middleware*.go"
  - "internal/domain/auth.go"
  - "internal/domain/users.go"
  - "internal/domain/sessions.go"
  - "internal/domain/signup.go"
  - "internal/domain/step_up.go"
  - "internal/domain/email.go"
  - "internal/domain/email_change.go"
  - "internal/domain/session_challenge.go"
  - "internal/providers/*oauth*.go"
  - "internal/providers/*email_provider*.go"
  - "internal/infra/expired_records_sweeper*.go"
  - "internal/api/cookies*.go"
  - "internal/e2e/**"
  - "postgres/queries/**"
  - "postgres/migrations/**"
---

# Auth and Email Flows

The full behaviour of sign-up, OAuth login, refresh sessions, logout, step-up and email change (routes, status codes, error keys, TTLs, limits, transactions) is in `docs/AUTH.md`. Read the matching section before changing any of these flows, and update it in the same change. Error keys go in `docs/ERRORS.md`, audit actions in `docs/AUDIT.md`. A change to the security model needs an ADR (see ADR-005, ADR-008, ADR-009).

Invariants to keep:

- Every account is verified: it only exists after a 6-digit code proved the email (no `email_verified` column, no verification links). OAuth with a provider-verified email may create or link right away; otherwise it goes through a pending sign-up. Microsoft always reports `EmailVerified=false`.
- Codes are generated with `crypto/rand`, stored only as `HMAC-SHA256(JWT_SECRET, "<purpose>:...:" + code)` and compared with `hmac.Equal`. Wrong-code counters are reserved before the attempt (atomic, capped) and never rolled back by a transaction.
- bcrypt and email sending stay outside transactions. A failed send right after creating a challenge or pending row deletes it; a failed sign-up `Resend` keeps the row (the new code already replaced the old one, and the user resends after the cooldown).
- Emails always go through `normalizeEmail` in services. A previous email stays reserved (`users.email.conflict`) during the 72h `domain.EmailChangeLock`.
- Sessions: one `user_sessions` row per device; refresh rotates `jti` by compare-and-set, and a reused or stale token deletes only that session. `expires_at` is never extended. Confirming or reverting an email change deletes every session and clears the auth cookies.
- `AuthMiddleware` stays stateless; only routes behind `StepUpMiddleware` (`authMiddleware.Use(stepUpMiddleware.Use(handler))`) read the session row.
- Depend on the narrowest token interface: middlewares use `domain.TokenVerifier`; `domain.TokenGenerator` is not part of `AuthService`.
- Multi-step flows (`OAuthLogin`, `CompleteSignup`, ...) are one service method; controllers only decode, call it and handle cookies, redirects and the audit log.
