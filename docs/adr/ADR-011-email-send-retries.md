# ADR-011: Email Send Retries and Idempotency Key in the Provider Adapter

- **Status:** Accepted
- **Date:** 2026-11-22

## Context

Resend retries delivery once it has accepted a message, but when our API call
fails (timeout, 5xx, 429) the message never reaches Resend. Several emails are
sent after the database commit with the failure only logged, such as the email
change undo notice (`SendEmailChangedNotice`, ADR-009) and the upcoming OAuth
link notice. A transient API error therefore loses them silently.

## Decision

Retrying the API call is the job of the email provider adapter
(`internal/providers/resend_email_provider.go`); services and callers do not
change.

- Each `Send` generates one `Idempotency-Key` (UUIDv7) and sends it on every
  attempt, so a retry after a lost response cannot deliver the email twice.
- Up to 3 attempts in total, only on transport errors and timeouts, 429, 5xx
  and the 409 named `concurrent_idempotent_requests` (the previous attempt is
  still being processed after a timeout). Other 4xx responses, including any
  other 409 such as `invalid_idempotent_request`, are never retried, and
  retries stop as soon as the context is done.
- Each attempt times out after 5s and the whole `Send`, backoff included, after
  15s (a context derived from the caller's), below the 30s server
  `WriteTimeout`.
- Backoff is exponential, 200ms then 400ms, waited with a context-aware timer.
  On any retried response a `Retry-After` value in seconds replaces the
  backoff when it is at most 2s.
- The error returned is the one from the last attempt.
- The provider keeps a single `http.Client` built in its constructor.

## Consequences

- Transient Resend failures no longer lose emails in the common case.
- Residual risk: notices whose send failure is only logged (the email change
  undo notice and the OAuth link notice) can still be lost when all attempts
  fail.
- A durable outbox (table plus background worker) was weighed and deferred: it
  closes that gap but adds a table, a worker and delivery-state handling that
  this template does not need yet.
- Requests that send synchronously wait at most 15s longer when Resend is
  failing (5s per attempt, 15s in total), which stays below the 30s
  `WriteTimeout`.
