# ADR-008: Step-Up and Email Change Hardening

- **Status:** Accepted
- **Date:** 2026-11-17

## Context

ADR-007 made the email change a two-step flow but accepted that someone holding
a stolen `access_token` cookie can move the account to an address they control.
That is enough to take the account over for good: the attacker confirms the new
address, then logs in with OAuth using that email (ADR-005 links by verified
email), or deletes the account outright. Password re-entry is not an option
because OAuth-only accounts have no password, and OAuth re-authentication is
not reliable across providers.

## Decision

- **OTP step-up to the current email, for every account.** A sensitive route
  needs a recently verified one-time code sent to the user's **current** email.
  `POST /auth/step-up` mails a 6-digit code (`crypto/rand`, uniform), stored as
  `HMAC-SHA256(JWT_SECRET, session_uuid + ":" + code)` in `step_up_challenges`
  (one row per session). The code lives 10 minutes, allows 5 attempts and a new
  one can be requested once every 60 seconds per session. The attempt is counted
  in the same statement that reads the hash, so concurrent guesses cannot
  exceed the limit. `POST /auth/step-up/verify` compares in constant time and,
  in one transaction, deletes the challenge and sets
  `user_sessions.step_up_until` to now + 5 minutes. Exhausted, expired and
  missing challenges answer the same `401 auth.stepUp.noChallenge`.
- **Cumulative failure cap.** New codes reset the per-code attempts, so a thief
  holding a session could keep guessing at about 5 attempts per minute.
  `user_sessions.step_up_failures` counts every wrong code of the session and
  no new code resets it. At 10 failures the session is deleted and the request
  answers `401 auth.stepUp.sessionRevoked`, with the auth cookies cleared. A
  successful verification does not reset the counter, to keep it simple.
- **Required on email change and account deletion.** `POST /users/me/email` and
  `DELETE /users/{uuid}` (self and admin) sit behind `StepUpMiddleware`, which
  answers `403 auth.stepUp.required` when the session is not elevated.
- **Session lookup only on sensitive routes.** `AuthMiddleware` stays stateless.
  `StepUpMiddleware` loads the session row (`IsElevated`: the session exists, is
  not expired and `step_up_until` is in the future). A revoked session therefore
  cannot be elevated. Residual risk: the access token of a revoked session still
  works on the other routes for up to 15 minutes.
- **Revoke other devices.** `POST /auth/logout-others` deletes every session of
  the user except the current one. It does not require step-up.
- **Email change hardening (following layer).** `users.email_version` is
  compared and bumped on every email write, so the change and undo tokens are
  single use (this also stops an A to B to A replay). Confirming a change
  revokes every session. The notice sent to the old address carries an "it
  wasn't me" link (72 hours) that reverts the email, revokes all sessions and
  removes the OAuth links created since the change. Further email changes are
  locked for 72 hours. During the lock the previous email is reserved: no
  sign-up, OAuth account creation or email change of another user may take it,
  so the undo cannot be blocked. Self-deletion is rejected with
  `409 users.emailChange.locked` while the lock is active (deletion by an admin
  is unaffected), so the owner cannot be stopped from undoing by an attacker
  deleting the account.

Rejected alternatives:

- **Password re-entry.** OAuth-only accounts have no password.
- **OAuth re-authentication (`prompt=login`, `max_age`).** Microsoft honors
  `prompt=login` but its ID token has no `auth_time`, so it cannot be verified.
  Google has no `prompt=login` and `auth_time` needs an extra setting. GitHub
  has neither.
- **Session lookup in `AuthMiddleware` on every request.** It would close the
  15-minute window but adds a database query to every authenticated request.
- **Per-user hourly cap on codes.** Deferred: the per-session cooldown and the
  attempt limit already bound guessing and mail volume per session.

## Consequences

**Positive**

- A stolen access cookie is not enough to change the email or delete the
  account: the attacker also needs the code sent to the owner's inbox.
- Works the same for credential and OAuth accounts.
- Codes are not stored in clear text, and the elevation is per session, so it is
  gone when the session is deleted.

**Negative / accepted residual risk**

- Whoever also controls the current mailbox passes the step-up.
- Sensitive routes cost one extra session query.
- A revoked session's access token works on non-sensitive routes for up to 15
  minutes.
- Sending the code is not best-effort: if the email provider fails, the request
  fails with `500`, since an undelivered code is useless.
- Each user session can trigger one mail per minute; there is no per-user cap.
- A legitimate user who mistypes the code 10 times over the life of a session
  is signed out of it and logs in again; successful verifications never reset
  the counter.
- The E2E suite gains an email-capture seam (`factories.WithEmailProvider`),
  which closes the email-flow gap that ADR-006 records.

This ADR supersedes ADR-007, which accepted the stolen-session residual risk.
