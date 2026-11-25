---
paths:
  - "config/**"
  - "internal/env/**"
  - "cmd/*/main.go"
  - "postgres/test.go"
  - "internal/tests/e2e/e2e_test.go"
  - "docker/docker-compose*.yaml"
---

# Configuration and Environment Variables

`config.Load` (`config/config.go`) reads and validates every variable the app uses, once at startup. Code outside `config` receives values through `*config.Config`. The exceptions are `logger.Setup` in `cmd/*/main.go` (reads `API_ENV` before `config.Load`, so config errors are logged in the right format) and the test-only `TEST_DB_PORT_START`/`TEST_DB_PORT_END` in `postgres/test.go`.

## Adding or Changing a Variable

1. Field: add it to `Config` or the matching sub-struct (`DatabaseConfig`, `RateLimitConfig`, `EmailConfig`, ...). Pool settings belong in `LoadDatabaseConfig`, which test helpers also call.
2. Lookup: optional typed values use `read(r, env.LookupX, "NAME", defaultX)` with the default as a `defaultX` constant in the `const` block; `read` keeps the first parse error. Plain or required strings use `os.Getenv`, lists use `parseCommaSeparated`. A new type gets a `LookupX` helper in `internal/env/helpers.go` with a test in `internal/env/env_test.go`.
3. Validation: after the `r.err` check, reject out-of-range values with an error that names the variable (`"X must be positive"`). Values required only outside development go in the `!cfg.IsDevelopment()` list. Production-only rules live in the `cfg.IsProduction()` block: URLs join the `httpsURLs` list (absolute `https` URLs only) and `CORS_ALLOWED_ORIGINS` must list explicit origins (a `*` is rejected).
4. Tests: add `TestLoad` (or `TestLoadDatabaseConfig`) subtests in `config/config_test.go` with `t.Setenv`: the default (extend "applies defaults for optional vars"), parsing (extend "reads and parses all optional vars"), each invalid value and each environment-specific rule.
5. `.env.example`: `.env*` files are off-limits to agents, so give the user the exact lines to add, with a comment and a safe example value, e.g. `# Max requests per second per IP (default 20)` and `RATE_LIMIT_REQUESTS_PER_SECOND=20`.
6. Docs: add a row to the Configuration table in `README.md` (the `OTEL_*` variables are in the Observability table), and update `.claude/rules/telemetry.md` for `OTEL_*` and `docs/AUTH.md` or the ADR when the variable tunes an auth flow.
7. E2E: set the variable in the env map of `run` in `internal/tests/e2e/e2e_test.go` when it is required in development, when its default would break the suite (rate limits, since every request shares one IP) or when a value exported from `.env` by the Makefile could leak in (`RESEND_API_KEY` is forced empty).

## Docker Compose

Only the `api` service in `docker/docker-compose.prod.yaml` receives the whole `.env` (`env_file`), so a new API variable needs no compose change. Any other service gets explicit `${VAR}` entries under `environment:` (interpolated from `--env-file .env`), only the ones it uses, like `POSTGRES_*` for `db` and `API_DOMAIN`/`API_PORT` for `traefik`.
