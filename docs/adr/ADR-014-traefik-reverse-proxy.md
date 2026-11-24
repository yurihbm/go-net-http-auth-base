# ADR-014: Traefik Reverse Proxy and TLS in Production

- **Status:** Partially superseded by ADR-018 (label-based routing and the Docker socket)
- **Date:** 2026-11-23

## Context

The production compose published the API in plain HTTP. Outside development the
auth cookies are `Secure` (ADR-005; the OAuth, pending sign-up and password reset
flow cookies are also `__Host-` prefixed), so browsers drop them over HTTP and
logins do not stick. The deployment target is a single VPS that may host
other services next to this API. ADR-013 needs a known proxy address to trust
`X-Forwarded-For`.

## Decision

- **Traefik v3, pinned to an exact tag.** It terminates TLS with Let's Encrypt
  (TLS-ALPN challenge, certificates in the `traefik_acme` volume) and redirects
  port 80 to 443. It is configured with `command:` flags only.
- **Label-based routing.** The API declares its router through Docker labels
  (`Host(${API_DOMAIN})`); `exposedByDefault=false` keeps every other container
  private. Further services on the VPS join the same way.
- **Networks.** `edge` (fixed subnet `172.30.0.0/24`) holds Traefik and the API;
  `internal` (`internal: true`) holds the database, migration and API. The
  database has no route to the outside. The API sits on both, so it keeps
  outbound access (OAuth providers, email, telemetry) through `edge`.
- **Client IP.** `TRUSTED_PROXIES=172.30.0.0/24` makes the API trust
  `X-Forwarded-For` only from Traefik. Traefik's default forwarded-headers
  behavior stays on, so `X-Forwarded-*` sent by clients is discarded and
  replaced.
- Only Traefik publishes ports. The dashboard and API are disabled.

## Alternatives considered

- **Caddy.** Simpler ACME, but static per-host configuration instead of
  label-based discovery of new services.
- **nginx plus certbot.** More moving parts for certificate renewal and no
  automatic discovery.

## Consequences

- Traefik mounts `/var/run/docker.sock`, read-only. Read-only does not limit the
  Docker API, so a compromised Traefik can still control the host's Docker.
  Mitigations: no dashboard or API, a pinned image, only ports 80/443 exposed.
  Accepted residual risk; a socket proxy would reduce it at the cost of one more
  service.
- A single Traefik and API instance on one host: no high availability. The
  in-memory rate limiter stays correct for that reason (ADR-013).
- `TRUSTED_PROXIES` must contain the `edge` subnet. Changing the subnet in the
  compose file requires changing the variable, or clients share the proxy's rate
  limit bucket again.
- `API_DOMAIN` and `ACME_EMAIL` are new required variables, and the domain must
  resolve to the VPS before the first start for the certificate to be issued.
