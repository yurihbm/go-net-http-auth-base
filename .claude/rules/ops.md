---
paths:
  - "docker/**"
  - ".github/**"
  - ".dockerignore"
  - "Makefile"
---

# CI, Docker and Deployment

## GitHub Actions

- Reference official GitHub actions (`actions/*`) and the verified publishers already in use (`docker/*`, `golangci/*`) by major tag (`actions/checkout@v7`). Pin every other third-party action by full commit SHA with a `# vX.Y.Z` comment, as `marocchino/sticky-pull-request-comment` is in `test.yml`. Dependabot updates the tags, the SHAs and the comments.
- Give every workflow a `concurrency:` block (`${{ github.workflow }}-${{ github.ref }}`, cancel in progress only for pull requests) and least-privilege `permissions:`, at the workflow level or per job (`test.yml` grants `pull-requests: write` only to the `test` job).
- Read tool versions from the `Makefile` (`SWAG_VERSION`, `SQLC_VERSION`, `GOLANG_MIGRATE_VERSION`, parsed with `sed`) and the Go version from `go.mod` (`go-version-file: go.mod`), so local and CI tools match. Keep the `NAME = vX.Y.Z` format of those Makefile lines.
- Job names are the required status checks listed in the "Branch protection" item of `README.md` (`lint`, `test`, `sqlc-drift`, `govulncheck`). Rename or add a job there in the same change. Path-filtered workflows (`docker.yml`) stay out of that list, because a check that never reports blocks the merge.
- `make check` mirrors the required checks locally; keep it in sync when a job gains a step.

## Dependabot

`.github/dependabot.yml` covers `gomod`, `github-actions`, `docker` and `docker-compose` (directory `/docker`), weekly. A new ecosystem or a file outside those directories needs an entry.

## Docker Images and Compose

- Pin every image to an exact version tag (`postgres:18-alpine`, `traefik:v3.7.19`, `grafana/otel-lgtm:0.38.1`), so builds are reproducible and Dependabot can bump them. The `golang` builder tag in `docker/Dockerfile` matches the `go` line of `go.mod`.
- `docker/Dockerfile` builds both binaries, `api` and `promote-admin`, with `CGO_ENABLED=0`, `-trimpath` and `-ldflags="-s -w"`, and runs them as the non-root user `1000`. A new `cmd/` binary gets the same build line and `COPY`.
- `.dockerignore` keeps `docs/swagger/` and `internal/controllers/assets/` in the build context: `DocsController` imports the generated spec and embeds the assets. Exclude new paths only when no Go package needs them.
- Least-privilege env: only the prod `api` service gets `env_file: ../.env`; every other service lists the `${VAR}`s it uses under `environment:` (details in `.claude/rules/config.md`).
- Dev compose (`docker-compose.dev.yaml`) binds every published port to `127.0.0.1`. In prod only Traefik publishes ports; other services use `expose:` and the `edge`/`internal` networks.

## Traefik

Traefik uses the file provider without the Docker socket ([ADR-013](../../docs/adr/ADR-013-traefik-reverse-proxy.md)). A new service exposed to the internet needs a router and a service entry in `docker/traefik/dynamic.yaml`, and any variable those templates read (`{{ env "..." }}`) must be passed to the `traefik` service in `docker/docker-compose.prod.yaml`.
