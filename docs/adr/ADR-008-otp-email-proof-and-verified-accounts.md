# ADR-008: One-Time Code Email Proof and Always-Verified Accounts

- **Status:** Accepted
- **Date:** 2026-11-18

## Context

If an account can exist with an unverified email, and the email is proven by
clicking a link, pre-account takeover is possible: an attacker signs up with
`victim@example.com` and a password they know. Later the victim either clicks
the verification link the attacker triggered (the click completes the
attacker's flow) or proves the mailbox through OAuth and gets linked into the
attacker's account (ADR-005 links by verified email).

## Decision

- **Every account is verified.** An account only exists after its email was
  proven, so there is no `email_verified` column. There is no unverified state
  to link into or take over.
- **Every email proof is a 6-digit one-time code typed in the browser that
  started the flow, never a link.** The flow is bound to that browser by an
  HttpOnly cookie (`__Host-` prefix outside development, `SameSite=Strict`), so
  a code read by someone else, or a code the victim receives for a flow they did
  not start, is useless without the cookie. The email change binds its code to
  the requesting session instead
  ([ADR-007](ADR-007-step-up-and-email-change.md)), and the password reset to
  its own cookie ([ADR-014](ADR-014-password-reset-and-change.md)).
- **Pending sign-ups.** `POST /users` stores a row in `pending_signups` (UUIDv7,
  generated in the service because the code hash needs it before the insert;
  its 74 random bits keep the cookie value unguessable, and the code is still
  required; kind `credentials` with the bcrypt hash, or `oauth` with the
  provider and provider user ID), emails the code and sets the `pending_signup`
  cookie. The code is stored as
  `HMAC-SHA256(JWT_SECRET, "signup:<uuid>:" + code)`, lives 10 minutes and
  allows 5 attempts; the sign-up lives 1 hour from creation and is never
  extended. Several pending sign-ups for the same email may coexist; the first
  correct code wins. `POST /auth/signup/verify` counts the attempt in its own
  statement (so a wrong code is never rolled back), compares in constant time
  and then, in one transaction, deletes the pending row (`DELETE ...
  RETURNING`, single use, wins a double submit), creates the user (with the
  existing email reservation check) and starts the session. If the email was
  taken meanwhile, the transaction rolls back and the pending sign-up is kept.
  `POST /auth/signup/resend` replaces the code, limited by the per-address
  send limits below.
- **OAuth without a verified email.** Providers that do not attest a verified
  email go through the same pending flow (kind `oauth`): the code is mailed to
  the provider email, and entering it signs in and links the provider.
- **Microsoft is an identity-only provider.** It always reports
  `EmailVerified=false` and is keyed by the `sub` from userinfo, which is
  pairwise per app registration, so its email is always proven by code.
- **Per-address limits** in `email_send_limits`, independent of the requester:
  one email per address every 60 seconds and 5 per hour (`429
  auth.email.sendLimit`), and 20 wrong codes per address in 24 hours (`429
  auth.email.codeLocked`; each guess is reserved atomically before the attempt
  is counted and given back when the code matches or the attempt is refused,
  so parallel guesses cannot exceed the cap; the email change confirmation
  reads its challenge first to know the address). The send slot is not refunded
  when delivery fails. The lockout risk of the failure counter is weighed in
  [ADR-009](ADR-009-per-address-code-failure-counter.md).

## Alternatives considered

- **Links.** A click carries no proof of who started the flow: a victim
  clicking the link from an attacker-started sign-up completes it for the
  attacker.
- **Unverified accounts with an `email_verified` gate on OAuth linking.** It
  narrows the takeover but keeps two kinds of accounts and a link that a victim
  can be tricked into opening.
- **Unverified accounts that the email owner takes over on proof.** The
  legitimate user loses their password or sessions whenever someone else proves
  the mailbox later, and both kinds of accounts keep existing.
- **Rejecting OAuth logins whose email the provider does not verify.** It locks
  out GitHub users with an unverified primary email and every Microsoft user,
  while a code proves the mailbox just as well.
- **An `OTPProvider` interface.** There is a single implementation (the
  `generateOTP`/`hashOTP` helpers shared with step-up); an abstraction would
  only add indirection.

## Consequences

- `POST /users` answers `202` without a user body; the account and the
  `USER_CREATE` audit entry appear at `POST /auth/signup/verify`, which also
  signs the user in.
- OAuth linking into an existing account only depends on the provider email
  being verified, because every local account is verified.
- `infra.ExpiredRecordsSweeper` also deletes expired pending sign-ups and
  `email_send_limits` rows whose windows both ended.
- Residual risks:
  - Per-address brute force: with 20 wrong codes per address per 24 hours over a
    space of one million codes, an attacker who can keep starting flows has
    about a 0.7% chance per year of guessing one code (5 attempts per code and
    5 sends per hour are lower than this cap).
  - An abuser can delay sign-up for an address by up to 1 hour by exhausting its
    send cap.
  - Anyone can lock an address's code entry for up to 24 hours by starting
    sign-ups for it (no account needed) and submitting 20 wrong codes. This
    blocks that address's own sign-up, OAuth pending sign-up, password reset
    and email changes to it, until the window ends. It is accepted as the price
    of the brute-force bound (ADR-009), the same class as the per-user step-up
    lock of ADR-007.
  - A victim who reads the code aloud to an attacker hands over the proof. The
    email says the code is for creating an account and must never be shared.
  - `409 users.email.conflict` on sign-up reveals that an address has an
    account.

See [ADR-005](ADR-005-security-approach.md) and
[ADR-007](ADR-007-step-up-and-email-change.md).
