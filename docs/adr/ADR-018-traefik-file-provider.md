# ADR-018: Traefik File Provider Instead of the Docker Socket

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

ADR-014 made Traefik discover routes from Docker labels, which needs
`/var/run/docker.sock` mounted in the container. Traefik is the only container
that faces the internet, and access to the socket is root-equivalent control of
the host: a read-only mount (`:ro`) only protects the socket file, not the
Docker API behind it. A compromised Traefik could start privileged containers.

The deployment model is one project per VPS, with a known and small set of
routes, so automatic discovery adds nothing.

## Decision

- Traefik uses the **file provider** with the versioned
  `docker/traefik/dynamic.yaml`, mounted read-only. `--providers.file.watch=false`
  because the file only changes with a deploy, which recreates the container.
- The router (`Host(API_DOMAIN)`, entry point `websecure`, `letsencrypt`
  certificate resolver) and the service (`http://api:<API_PORT>`) live in that
  file. The file provider renders it as a Go template, so `{{ env "API_DOMAIN" }}`
  and `{{ env "API_PORT" }}` read the variables compose passes to the Traefik
  container.
- The Docker socket mount, the Docker provider flags and the `api` labels are
  removed. Everything else from ADR-014 (TLS, redirect, networks,
  `TRUSTED_PROXIES`) is unchanged.

## Consequences

- Traefik no longer has any path to the Docker API.
- Routes are edited in `dynamic.yaml`: a new service on the same VPS needs its
  own router and service entry there, and the service must join the `edge`
  network so Traefik can reach it by name.
- Router and service names stay `api` in the file; two projects on one VPS
  still need separate Traefik instances or a shared one with distinct names.
