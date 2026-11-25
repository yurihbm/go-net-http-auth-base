# ADR-014: Password Reset and Change

- **Status:** Accepted
- **Date:** 2026-11-23

## Context

Without a reset or a change of password, a user who forgot the password is
locked out, and a user who knows it cannot rotate it. A password change that
kept existing sessions would not fit a template where every account is verified
by an emailed code (ADR-008) and every sensitive action is protected by step-up
(ADR-007).

The reset has to prove control of the mailbox without creating an account
enumeration oracle worse than the one already accepted (`POST /users` answers
`409` for a taken email), and without giving a second code flow weaker limits
than sign-up.

## Decision

- **Reset by code, bound to the browser.** `POST /auth/password/forgot` emails a
  6-digit code and sets an HttpOnly `password_reset` cookie (`__Host-` prefix
  outside development, 10 minutes) holding the UUIDv7 of a `password_resets`
  row. `POST /auth/password/reset` takes the code and the new password and needs
  that cookie, so the code is useless in any other browser. The code is stored
  as `HMAC-SHA256(JWT_SECRET, "password-reset:<uuid>:" + code)`, with 5 attempts
  per row and the per-address 24h counter of ADR-009. The row stores the user's
  `email_version`, and the update is a compare-and-set on it, so an email change
  between request and reset invalidates the reset.
- **Same answer for unknown addresses.** The request always answers `202` with a
  cookie. An unknown address gets a fresh UUIDv7 with no row and no email, and
  the per-address send limit (`ReserveSend`, as in sign-up) runs before the
  lookup, so known and unknown addresses hit `429 auth.email.sendLimit` alike.
  Every failure of the reset (missing cookie, unknown, expired or exhausted row,
  wrong code, stale version) is `401 auth.passwordReset.invalidCode`.
- **Reset revokes everything and does not log in.** In one `WithinTx` the row is
  consumed, the password updated, every session deleted and the user's other
  pending resets removed. The client signs in again with the new password, so
  whoever held a session (including an attacker) loses it. bcrypt and the email
  sends stay outside the transaction, and a notice email goes out after the
  commit (a failure is only logged).
- **Change behind step-up, no current password.** `POST /users/me/password`
  requires a recent step-up, which already proves the mailbox, and replaces the
  password, deletes every other session and the pending resets. The current
  session stays signed in. This also lets OAuth-only accounts set a first
  password, as the reset does.
- **Audit.** `PASSWORD_RESET_REQUEST` (no actor), `PASSWORD_RESET` and
  `PASSWORD_CHANGE`.
- **Sweeper.** `ExpiredRecordsSweeper` deletes expired `password_resets` in
  batches.

Rejected alternatives:

- **Magic links.** A link works in any browser, so it cannot be bound to the one
  that asked for the reset, and the token would sit in URLs and logs.
- **Email and code in the request body.** Without the cookie, anyone could
  submit guesses for a victim's address from anywhere.
- **A reset that signs the user in.** It would turn mailbox access into an
  immediate session without the new password ever being used, and skip the
  revocation point.
- **Decoy rows and asynchronous sending** to hide the timing difference. They
  add storage, a queue and failure modes for a signal that `POST /users` already
  gives away.

## Consequences

- New table `password_resets`, new cookie, three routes, two emails and three
  audit actions (see `docs/AUTH.md`, `docs/ERRORS.md`, `docs/AUDIT.md`).
- Residual risks:
  - The response time of `POST /auth/password/forgot` reveals registered emails
    (a known address sends an email synchronously), consistent with the `409` of
    `POST /users`.
  - Access tokens already issued stay valid for up to 15 minutes after a reset
    or change, because `AuthMiddleware` is stateless.
  - The per-address code counter (ADR-009) is shared with sign-up and email
    change: 20 wrong codes lock every code flow of the address for 24 hours, so
    an anonymous attacker who holds a reset cookie can lock a victim out of
    resetting for that long.
  - Enumeration goes beyond timing. An unknown address never has a row, so it
    never reaches the per-address guess counter. For a registered address, an
    attacker can exhaust `EmailMaxCodeFailures` (5 requests per hour times 5
    wrong codes per cookie is 25, above 20) and observe
    `429 auth.email.codeLocked`, which an unknown address never returns. The
    same steps lock the owner out of every code flow for 24 hours (ADR-009).
    Accepted because `POST /users` already reveals registered emails with 409.
  - `auth.passwordReset.sendFailed` is a 500 only for registered addresses, so
    a provider outage reveals registration. Accepted: hiding it would leave
    users waiting for an email that never arrives.
  - Several reset codes of one user can be live at once, because
    `RequestReset` does not delete earlier rows. Each is bound to its own
    cookie, and the per-address counter caps the total guesses.
