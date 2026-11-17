# ADR-007: Verified Email Change

- **Status:** Accepted
- **Date:** 2026-11-17

## Context

`PUT /users/{uuid}` accepted an `email` field and kept `email_verified` as it
was. A user could verify their own address, switch the account to an address
they do not own and keep it marked as verified. ADR-005 links an OAuth login
into an existing account only when both the provider and the local account have
verified the email, so the next OAuth login of the real owner of that address
was linked into the attacker's account (account pre-hijacking). It also let
anyone claim a verified email without owning it.

## Decision

- **Email leaves the generic update.** `UserUpdateDTO` only carries `name`, and
  strict decoding rejects `email` with `400`. The `UpdateUser` query no longer
  writes the email.
- **Two-step change, self only.** `POST /users/me/email` (authenticated) checks
  that the new address differs from the current one and is free (`409`
  otherwise, the same signal `POST /users` already gives), then mails a link to
  the **new** address and answers `202`. Nothing changes until
  `POST /users/confirm-email-change` (public, the token is the proof) receives
  the token. Admins cannot change another user's email.
- **Token.** A JWT with audience `email_change_token`, valid for 1 hour, with
  `sub` = user UUID and a payload holding `current_email` and `new_email`. The
  frontend URL comes from `EMAIL_CHANGE_URL`, required outside development like
  `EMAIL_VERIFICATION_URL`.
- **Effectively single-use.** Confirmation fails with
  `users.emailChange.staleToken` unless the account email still equals
  `current_email`. After a change, the used token and every other pending one
  stop working, without storing tokens.
- **Apply and notify.** `UpdateUserEmail` writes the new email and sets
  `email_verified = true` in one statement, because opening the link proves
  ownership. The unique index on `lower(email)` still turns a race into `409`.
  The old address then receives a notice without a link. A failed notice is only
  logged, because the change already happened.
- **No re-authentication.** The request does not ask for the current password:
  OAuth-only accounts have none, and the confirmation already proves ownership
  of the new address.

Rejected alternative: keep `email` in `PUT` and reset `email_verified` on
change. It closes the takeover but locks the user out of OAuth linking with a
typo, and the account email changes before ownership is proven.

## Consequences

**Positive**

- A verified email always means the account owner proved ownership of that
  exact address.
- No new table: the token is stateless and its single use comes from the
  `current_email` claim.

**Negative / accepted residual risk**

- Someone holding a stolen session can move the account to an address they
  control. The old address is notified, but there is no undo link. Existing
  sessions are not revoked after a change.
- Like `POST /users`, `POST /users/me/email` reveals whether an address is
  taken.
- The confirmation step is not covered by the E2E suite (same gap as email
  verification in ADR-006). Unit and repository tests cover it.
