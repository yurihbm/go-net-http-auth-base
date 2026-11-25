# Architecture Decision Records

This directory records the key architectural decisions behind this template,
using the [Nygard format](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions):
Status, Context, Decision and Consequences.

| ADR                                                         | Title                                                  | Status   |
| :---------------------------------------------------------- | :----------------------------------------------------- | :------- |
| [ADR-001](ADR-001-layered-architecture.md)                  | Layered Architecture Pattern                           | Accepted |
| [ADR-002](ADR-002-error-handling.md)                        | Error Handling Strategy                                | Accepted |
| [ADR-003](ADR-003-database-strategy.md)                     | Database Strategy (PostgreSQL + sqlc)                  | Accepted |
| [ADR-004](ADR-004-logging-observability.md)                 | Logging & Observability                                | Accepted |
| [ADR-005](ADR-005-security-approach.md)                     | Security Approach                                      | Accepted |
| [ADR-006](ADR-006-e2e-and-cross-layer-test-suites.md)       | End-to-End and Cross-Layer Test Suites                 | Accepted |
| [ADR-007](ADR-007-step-up-and-email-change.md)              | Step-Up and Verified Email Change                      | Accepted |
| [ADR-008](ADR-008-otp-email-proof-and-verified-accounts.md) | One-Time Code Email Proof and Always-Verified Accounts | Accepted |
| [ADR-009](ADR-009-per-address-code-failure-counter.md)      | Per-Address Code Failure Counter and Its Lockout Risk  | Accepted |
| [ADR-010](ADR-010-email-send-retries.md)                    | Email Send Retries and Idempotency Key                 | Accepted |
| [ADR-011](ADR-011-notify-and-undo-oauth-links.md)           | Notify and Undo OAuth Provider Links                   | Accepted |
| [ADR-012](ADR-012-trusted-proxies.md)                       | Trusted Proxies and Client IP Resolution               | Accepted |
| [ADR-013](ADR-013-traefik-reverse-proxy.md)                 | Traefik Reverse Proxy and TLS in Production            | Accepted |
| [ADR-014](ADR-014-password-reset-and-change.md)             | Password Reset and Change                              | Accepted |
| [ADR-015](ADR-015-http-edge-hardening.md)                   | HTTP Edge Hardening                                    | Accepted |
| [ADR-016](ADR-016-injected-clock-in-services.md)            | Injected Clock in Services                             | Accepted |

## Writing a new ADR

1. Copy the structure of an existing ADR and use the next number
   (`ADR-00N-short-title.md`).
2. While this repository is a template, do not add superseding records: edit the
   affected ADRs so the set describes the template's final state, with every
   ADR `Accepted`. Projects created from the template should start from its
   final decisions, not from its construction history.
3. After leaving the template phase, accepted ADRs are immutable. Never rewrite
   one to change its decision: write a new one and set the old one's status to
   `Superseded by ADR-00N`.
4. Add it to the table above.

## Diagrams

Diagrams are generated with [Archify](https://github.com/tt-a1i/archify) from
the JSON sources in [`diagrams/`](diagrams/). Each one has two files:

- `<name>.json`: the source. Its components cite the code they describe, pinned
  to a commit.
- `<name>.svg`: the static export embedded in the ADRs. It follows the light or
  dark theme of the page.

To view a diagram interactively or change it, install the pinned Archify version
(`make install-archify`, requires Node 18+), render the JSON from the repository
root into `.archify/` (git-ignored) and open the resulting HTML in a browser.
`<type>` is the JSON's `diagram_type`.

```bash
node .tools/archify/bin/archify.mjs finalize <type> docs/adr/diagrams/<name>.json \
  .archify/<name>.html --repo-root . --quality showcase
```

After changing the JSON, export the SVG from the HTML viewer
(**Export → SVG · Auto**) over `docs/adr/diagrams/<name>.svg`. When the cited code
moves, update `meta.repository.revision` and the source line ranges in the JSON.
