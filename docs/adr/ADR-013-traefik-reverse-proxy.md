# ADR-013: Traefik Reverse Proxy and TLS in Production

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

Outside development the auth cookies are `Secure` (ADR-005; the OAuth, pending
sign-up and password reset flow cookies are also `__Host-` prefixed), so
browsers drop them over plain HTTP and logins do not stick: production needs
TLS. The deployment model is one project per VPS, with a known and small set of
routes. ADR-012 needs a known proxy address to trust `X-Forwarded-For`.

Traefik is the only container that faces the internet, so it must not hold
more privileges than routing needs.

## Decision

- **Traefik v3, pinned to an exact tag.** It terminates TLS with Let's Encrypt
  (TLS-ALPN challenge, certificates in the `traefik_acme` volume) and redirects
  port 80 to 443. Its static configuration is `command:` flags only.
- **File provider, no Docker socket.** Routes come from the versioned
  `docker/traefik/dynamic.yaml`, mounted read-only, with
  `--providers.file.watch=false` because the file only changes with a deploy,
  which recreates the container. The router (`Host(API_DOMAIN)`, entry point
  `websecure`, `letsencrypt` certificate resolver) and the service
  (`http://api:<API_PORT>`) live in that file. The file provider renders it as
  a Go template, so `{{ env "API_DOMAIN" }}` and `{{ env "API_PORT" }}` read the
  variables compose passes to the Traefik container.
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

- **Docker provider with label-based routing.** Services declare their routers
  through Docker labels and are discovered automatically, but Traefik needs
  `/var/run/docker.sock`. Access to the socket is root-equivalent control of the
  host: a read-only mount (`:ro`) only protects the socket file, not the Docker
  API behind it, so a compromised Traefik could start privileged containers. A
  socket proxy would reduce that at the cost of one more service. With one
  project per VPS and a small set of routes, discovery adds nothing.
- **Caddy.** Simpler ACME, but static per-host configuration instead of
  discovery of new services.
- **nginx plus certbot.** More moving parts for certificate renewal and no
  automatic discovery.

## Consequences

- Traefik has no path to the Docker API. Remaining mitigations: no dashboard or
  API, a pinned image, only ports 80/443 exposed.
- Routes are edited in `dynamic.yaml`: a new service on the same VPS needs its
  own router and service entry there, and the service must join the `edge`
  network so Traefik can reach it by name.
- Router and service names stay `api` in the file; two projects on one VPS
  still need separate Traefik instances or a shared one with distinct names.
- A single Traefik and API instance on one host: no high availability. The
  in-memory rate limiter stays correct for that reason (ADR-012).
- `TRUSTED_PROXIES` must contain the `edge` subnet. Changing the subnet in the
  compose file requires changing the variable, or clients share the proxy's rate
  limit bucket again.
- `API_DOMAIN` and `ACME_EMAIL` are required variables, and the domain must
  resolve to the VPS before the first start for the certificate to be issued.
