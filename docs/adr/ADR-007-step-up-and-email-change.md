# ADR-007: Step-Up and Verified Email Change

- **Status:** Accepted
- **Date:** 2026-11-18

## Context

An OAuth login is linked into an existing account when the provider reports a
verified email that matches it (ADR-005). Two paths would turn that rule, or a
stolen session, into a permanent account takeover:

- If `PATCH /users/{uuid}` accepted an `email` field and kept the account
  verified, a user could switch the account to an address they do not own. The
  next OAuth login of the real owner of that address would then be linked into
  the attacker's account (account pre-hijacking), and anyone could claim an
  email without owning it.
- Someone holding a stolen `access_token` cookie could move the account to an
  address they control, confirm it, then log in with OAuth using that email, or
  delete the account outright.

Password re-entry cannot protect these actions, because OAuth-only accounts
have no password, and OAuth re-authentication is not reliable across
providers.

## Decision

**Step-up by a one-time code to the current email, for every account**

- A sensitive route needs a recently verified one-time code sent to the user's
  **current** email. `POST /auth/step-up` mails a 6-digit code (`crypto/rand`,
  uniform), stored as `HMAC-SHA256(JWT_SECRET, "step-up:" + session_uuid + ":" + code)`
  as the session's `step_up` challenge. The code lives 10 minutes, allows 5
  attempts and a new one can be requested once every 60 seconds per session.
  The attempt is counted in the same statement that reads the hash, so
  concurrent guesses cannot exceed the limit. `POST /auth/step-up/verify`
  compares in constant time and, in one transaction, deletes the challenge and
  sets `user_sessions.step_up_until` to now + 5 minutes. Exhausted, expired and
  missing challenges answer the same `401 auth.stepUp.noChallenge`.
- **Cumulative failure cap per session.** New codes reset the per-code attempts,
  so a thief holding a session could otherwise keep guessing at about 5
  attempts per minute. `user_sessions.step_up_failures` counts every wrong code
  of the session and no new code resets it. At 10 failures the session is
  deleted and the request answers `401 auth.stepUp.sessionRevoked`, with the
  auth cookies cleared. A successful verification does not reset the counter,
  to keep it simple.
- **Per-user failure cap.** The session cap alone lets someone who knows the
  password log in again for fresh guesses. `users.step_up_failures` and
  `users.step_up_failures_window_start` count wrong codes across all sessions of
  the user in a 24-hour window. `VerifyCode` reserves a guess before the compare
  with one conditional statement that increments only below 20 (it restarts the
  count at 1 when the window has expired), so parallel guesses from several
  sessions cannot exceed the cap. A correct code or a missing challenge refunds
  the reserved guess. At 20 failures, `RequestCode` and `VerifyCode` answer
  `429 auth.stepUp.userLocked` until the window ends. A successful verification
  does not reset earlier failures.
- **Required on email change, password change and account deletion.**
  `POST /users/me/email`, `POST /users/me/password`
  ([ADR-014](ADR-014-password-reset-and-change.md)) and `DELETE /users/{uuid}`
  (self and admin) sit behind `StepUpMiddleware`, which answers
  `403 auth.stepUp.required` when the session is not elevated.
- **Session lookup only on sensitive routes.** `AuthMiddleware` stays stateless.
  `StepUpMiddleware` loads the session row (`IsElevated`: the session exists, is
  not expired and `step_up_until` is in the future). A revoked session therefore
  cannot be elevated.
- **Revoke other devices.** `POST /auth/logout-others` deletes every session of
  the user except the current one. It does not require step-up.

**Email change, confirmed by a code to the new address**

- **Email leaves the generic update.** `UserUpdateDTO` only carries `name`, and
  strict decoding rejects `email` with `400`. The `UpdateUser` query never
  writes the email.
- **Two-step change, self only.** `POST /users/me/email` (behind step-up)
  rejects the current address (`400`) and a taken or reserved one (`409`, the
  same signal `POST /users` already gives), stores the session's `email_change`
  challenge with the new address and the user's `email_version`, mails a
  6-digit code to the **new** address and answers `202`. The code is hashed as
  `HMAC-SHA256(JWT_SECRET, "email-change:" + session_uuid + ":" + code)`, lives
  10 minutes, allows 5 attempts and can be re-requested once every 60 seconds;
  the per-address send limits and the per-address wrong-code counter of
  [ADR-008](ADR-008-otp-email-proof-and-verified-accounts.md) and
  [ADR-009](ADR-009-per-address-code-failure-counter.md) also apply. Nothing
  changes until `POST /users/me/email/confirm` receives the code from the
  **same session** (not behind step-up, because that session already passed
  it); another device cannot confirm. Admins cannot change another user's
  email.
- **Single use through `users.email_version`.** It is compared and bumped on
  every email write, so a confirmation or undo applies once, and an A to B to A
  replay is rejected (`users.emailChange.staleToken`). The write is a
  compare-and-set, and the unique index on `lower(email)` still turns a race
  into `409`.
- **Confirming revokes every session.** The client signs in again.
- **Notice with an undo link.** After the commit the old address receives a
  notice with an "it wasn't me" link (a JWT with audience
  `email_change_revert_token`, 72 hours, pointing to `EMAIL_CHANGE_REVERT_URL`).
  `POST /users/revert-email-change` reverts the email, revokes all sessions and
  removes the OAuth links created since the change. A failed notice is only
  logged, because the change already happened.
- **Lock and reservation.** Further email changes are locked for 72 hours after
  a change. During the lock the previous email is reserved: no sign-up, OAuth
  account creation or email change of another user may take it, so the undo
  cannot be blocked. Self-deletion is rejected with
  `409 users.emailChange.locked` while the lock is active (deletion by an admin
  is unaffected), so an attacker cannot stop the owner from undoing by deleting
  the account.

**Storage**

- Step-up and email change challenges share one `session_challenges` table: one
  row per session and `purpose` (`step_up`, `email_change`), with `new_email`
  and `email_version` only on email change rows (CHECK), cascading with the
  session and the user, one query set and one repository. The hash scopes stay
  separate (`step-up:` and `email-change:` plus the session UUID), as do the
  error keys of each flow.

## Alternatives considered

- **Keep `email` in `PUT` and mark the new address unproven until confirmed.**
  It closes the takeover, but the account email changes before ownership is
  proven, and a typo locks the user out of OAuth linking.
- **A confirmation link mailed to the new address** (a stateless JWT made single
  use by a `current_email` claim). A click carries no proof of who started the
  flow and works from any browser or session; the code bound to the requesting
  session does not.
- **No re-authentication for the email change.** The confirmation proves
  ownership of the new address, but someone holding a stolen session could then
  move the account to an address they control.
- **Password re-entry.** OAuth-only accounts have no password.
- **OAuth re-authentication (`prompt=login`, `max_age`).** Microsoft honors
  `prompt=login` but its ID token has no `auth_time`, so it cannot be verified.
  Google has no `prompt=login` and `auth_time` needs an extra setting. GitHub
  has neither.
- **Session lookup in `AuthMiddleware` on every request.** It would close the
  15-minute window of revoked sessions but adds a database query to every
  authenticated request.
- **Per-user hourly cap on step-up codes sent.** Not needed for guessing, which
  the failure caps bound; mail volume stays bounded per session by the cooldown.
- **One challenge table per flow.** Two identical tables, query sets and
  repositories for the same shape of row.

## Consequences

**Positive**

- The account email is always an address whose owner proved it with a code.
- A stolen access cookie is not enough to change the email or the password or to
  delete the account: the attacker also needs the code sent to the owner's
  inbox.
- Works the same for credential and OAuth accounts.
- Codes are not stored in clear text, and the elevation is per session, so it is
  gone when the session is deleted.
- The owner of the old address can undo a change for 72 hours, and the lock and
  the reservation keep the undo from being blocked.

**Negative / accepted residual risk**

- Whoever also controls the current mailbox passes the step-up.
- Sensitive routes cost one extra session query.
- A revoked session's access token works on non-sensitive routes for up to 15
  minutes.
- Sending the step-up or email change code is not best-effort: if the email
  provider fails, the request fails with `500`, since an undelivered code is
  useless.
- Each user session can trigger one step-up mail per minute; there is no
  per-user cap on mail volume.
- Someone who already has the password can lock the owner's step-up for up to
  24 hours by logging in and sending wrong codes.
- A legitimate user who mistypes the code 10 times over the life of a session
  is signed out of it and logs in again; successful verifications never reset
  the counter.
- Like `POST /users`, `POST /users/me/email` reveals whether an address is
  taken.
- Confirming or undoing an email change signs out every device, including the
  current one.
- The undo notice can be lost when every send attempt fails, because the failure
  is only logged ([ADR-010](ADR-010-email-send-retries.md)).
- The per-address code lock of ADR-009 also blocks email changes to a locked
  address until its window ends.
