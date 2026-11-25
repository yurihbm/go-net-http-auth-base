# ADR-011: Notify and Undo OAuth Provider Links

- **Status:** Accepted
- **Date:** 2026-11-22

## Context

When an OAuth login reports a verified email that matches an existing account,
the provider is linked to that account right away (Case 2, ADR-005/ADR-008) and
the login signs in, without the owner being told. The link rests on the
provider's claim that its user controls the mailbox.

The notice goes to the account email, which in Case 2 equals the provider
email. It therefore helps only when the mailbox owner is not the one logging in
through the provider: the provider wrongly asserts verification for an address
it does not control (a provider bug or misconfiguration, or a provider-side
account created with an address its holder never proved), while the real owner
of the mailbox still reads it. It also leaves the owner an audit trail of every
link. It does not help when the attacker controls the mailbox itself, for
example after a recycled domain or mailbox: the notice then reaches the
attacker.

The email change already has this shape of defence: a notice to the old address
with an undo link (ADR-007).

## Decision

- **Notice.** `AuthService.OAuthLogin` emails the account owner when Case 2
  created a link (`SendOAuthLinkedNotice`), after the link transaction
  committed and after the session started, outside any transaction (a slow send
  must not leave a session the client never receives). A send failure is only
  logged and the login still succeeds. If the session cannot start, the notice
  is still sent because the link is already persisted.
- **No notice for code-proven links.** Case 1 (existing link), Case 3 (new
  account) and `CompleteSignup` do not notify: in the last one the owner typed
  a code from an email that already said that entering it links the provider.
- **Undo link.** A JWT with audience `oauth_link_revert_token`, valid 72 hours,
  carrying the link UUID and the provider, pointing to
  `EMAIL_OAUTH_LINK_REVERT_URL`.
- **Undo.** The public `POST /auth/oauth/revert-link` deletes that link and
  every session of the user in one transaction and clears the auth cookies, so
  a session opened through the unwanted link is revoked together with the link.
  The audit action is `OAUTH_LINK_REVERT`.
- **Single use without stored state.** The link row is the state: once it is
  gone, the token deletes zero rows and is rejected with
  `auth.oauthLink.staleToken`.

Rejected alternatives:

- **Requiring a code before linking.** It would add friction for every OAuth
  login of verified providers, which ADR-008 deliberately avoids.
- **Storing a revert token row.** The link row already carries the needed state.

## Consequences

- Needs a new required setting outside development, `EMAIL_OAUTH_LINK_REVERT_URL`.
- Residual risks:
  - A recycled mailbox or domain is not mitigated: the notice reaches whoever
    controls the address.
  - The undo does not prevent re-linking. The same provider login links again
    through Case 2 and the owner gets a new notice each time; there is no block
    list.
  - The notice has no send limit of its own, only the OAuth login rate and the
    global rate limiter.
  - The notice can be lost when every send attempt fails, because the failure
    is only logged (ADR-010).
  - The access token of a revoked session stays valid for up to 15 minutes,
    since `AuthMiddleware` is stateless.
  - A legitimate owner who undoes the link also signs out every device.

See [ADR-008](ADR-008-otp-email-proof-and-verified-accounts.md) and
[ADR-010](ADR-010-email-send-retries.md).
