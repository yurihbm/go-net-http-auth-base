# ADR-009: Per-Address Code Failure Counter and Its Lockout Risk

- **Status:** Accepted
- **Date:** 2026-11-21

## Context

[ADR-008](ADR-008-otp-email-proof-and-verified-accounts.md) proves every email
with a 6-digit code. A code has only 10^6 values, so wrong guesses are capped
per pending sign-up or challenge (5 attempts) and also per destination address:
`email_send_limits.failures` allows `EmailMaxCodeFailures` (20) wrong codes per
`EmailCodeFailureWindow` (24h), reserved atomically before each attempt
(`internal/domain/signup.go`).

The counter is keyed by address only, and the address is not secret. An
anonymous attacker can `POST /users` with a victim's address (5 sends per hour,
5 attempts per pending sign-up), then submit wrong codes to
`/auth/signup/verify` until the address reaches 20 failures. The victim then
gets `429 auth.email.codeLocked` when verifying their own sign-up and when
confirming an email change to that address, for up to 24h. The window is fixed: it opens at the first failure after the
previous one expired, so the attacker can lock the address again right after
it ends and sustain the denial of service by repeating the attack. It does not block
starting a sign-up, starting OAuth or `RequestEmailChange`.

## Decision

Keep the per-address counter and accept the lockout as a residual risk.

The per-address cap is what bounds brute force spread over many pending sign-ups
or challenges. Without it an attacker could open pendings repeatedly and, after
enough guesses, verify an account on an address they do not own, which is the
takeover ADR-008 removes.

Alternatives weighed:

- **Scope the counter per pending sign-up or session.** Defeats the purpose: each
  new pending resets the budget, so the total guesses against one address are
  unbounded apart from the send limit.
- **Per-IP counters.** Bypassed by IP rotation and adds state to store and
  sweep, while the protected asset is the address.
- **Shorter window.** Reduces the lockout but raises the guesses per day allowed
  against one address; 24h stays.

## Consequences

- A targeted denial of service on one address's code verification is possible.
  Each lockout lasts up to 24h and can be renewed by repeating the attack. The victim can still start a new sign-up or OAuth flow, but its
  code is rejected with `auth.email.codeLocked` until the window ends.
- Mitigations: the global per-IP rate limiter slows the attacker, the send
  limit (60s cooldown, 5 per hour) bounds the pendings they can create, and each
  lockout is bounded by the 24h window (the sweeper deletes the row afterwards).
  They slow the attack but do not prevent renewing it.
- Brute force against an address stays capped at 20 wrong codes per 24h across
  every pending sign-up and email change challenge.
- Revisit if the lockout is abused in practice, for example by adding a
  trusted-device or proof-of-work signal.
