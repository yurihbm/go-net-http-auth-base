---
paths:
  - "internal/telemetry/**"
  - "internal/middlewares/**"
  - "internal/logger/**"
  - "internal/factories/telemetry_factory.go"
  - "internal/factories/logger_factory.go"
  - "internal/factories/handler.go"
  - "postgres/*tracer*"
  - "postgres/pool_metrics*"
  - "postgres/connection*"
  - "docker/grafana/**"
  - "docker/docker-compose.dev.yaml"
  - "cmd/**"
---

# Telemetry and Logging

- **SDK used directly**: `internal/telemetry` (`telemetry.New`, `Shutdown`) bootstraps the OpenTelemetry SDK once in `cmd/api` (OTLP/HTTP traces, metrics and logs) and flushes it after the server shuts down.
- **Dependency Rule**: `go.opentelemetry.io/otel*` may only be imported in `internal/telemetry`, `internal/middlewares`, `internal/logger`, `internal/factories`, `postgres` and `cmd`; never in `services`, `controllers`, `domain` or `repositories`.
- **No Domain Abstraction**: There is deliberately no `TelemetryProvider`/`Tracer`/`Meter` interface, no NoOp provider and no telemetry mocks.
- **Gating**: Everything is gated by `OTEL_ENABLED` (default `false`, which wires nothing and returns no-op providers). `OTEL_ENABLED`, `OTEL_SERVICE_NAME`, `OTEL_EXPORTER_OTLP_ENDPOINT` and `OTEL_TRACES_SAMPLER_ARG` are loaded and validated in `config/config.go`.
- **HTTP Middleware**: `TelemetryMiddleware` (`otelhttp` plus a route hook, built by `factories.TelemetryFactory`, a pass-through when disabled) runs as `requestContextData -> clientIP -> requestUUID -> telemetry -> logger -> recover -> cors -> rateLimit -> mux`. It must sit inside `requestContextData` (which copies the request, hiding the `r.Pattern` the mux sets), outside `logger` (so the request log has the span in its context) and outside `cors`/`rateLimit` (so 403/429 are measured). The error a handler stored in `RequestContextData.Error` (set by `api.HandleError`) is recorded on the span as an `exception` event, so the trace shows why a request failed; the span status still follows the HTTP status.
- **Health Checks**: `GET /health` and `GET /ready` produce neither spans nor metrics.
- **Low Cardinality**: Metrics only carry the route pattern as `http.route` (never the raw path) and a constant `server.address` and `server.port` (the service name and the API port, never the client `Host` header). The request UUID goes on spans only (`app.request.uuid`), never on metrics.
- **DB Telemetry**: `postgres.OTelQueryTracer` (built in `cmd/api/main.go` with the database name parsed from `DATABASE_URL` via `pgx.ParseConfig`, only when enabled and passed to `NewConnectionPool`, which composes it with the `SlowQueryTracer` through pgx `multitracer`) creates a CLIENT span per query named after the sqlc query name (fallback: first SQL keyword) and records `db.client.operation.duration`. `db.query.text` is recorded on spans, but query args never are (PII), and `pgx.ErrNoRows` is not an error. `error.type` is the SQLSTATE for Postgres errors (also set as `db.response.status_code` on spans), `canceled` for `context.Canceled`, else the Go error type. Metric attributes are only `db.system.name`, `db.query.summary`, `db.operation.name` and `error.type`. The `BEGIN`/`COMMIT`/`ROLLBACK` spans produced by `WithinTx` land in the same histogram.
- **Pool and Runtime Metrics**: `postgres.RegisterPoolMetrics` (called in `cmd/api/main.go` only when enabled, unregistered before `pool.Close`) observes `db.client.connection.count` (`db.client.connection.state` = `idle`/`used`), `db.client.connection.max` and `db.client.connection.empty_acquire` (acquires that waited: pool exhaustion) from one `pool.Stat()` per collection. `telemetry.New` also starts the `contrib/instrumentation/runtime` Go metrics (`go.goroutine.count`, `go.memory.*`, `go.processor.limit`, ...).
- **Dashboards**: Grafana dashboards (`api-red`, `go-runtime`, `database`, `logs`, `request-investigation`, each with a stat row on top and a dashboards dropdown) live in `docker/grafana/dashboards/` and are provisioned into the `lgtm` service of `docker/docker-compose.dev.yaml` through `docker/grafana/provisioning/dashboards.yaml`. Metric names in queries are the Prometheus-translated OTel names (dots to underscores, unit suffix, `_total` for counters); update them if an instrument is renamed. In the `logs` dashboard `detected_level`, `path`, `status` and `trace_id` are Loki structured metadata, so they are filtered after the stream selector (`{service_name=...} | detected_level=~...`), never inside the braces. `request-investigation` is the per-request view: paste a request UUID to list its traces (TraceQL on `span.app.request.uuid`), pick one, and the Trace ID box drives the waterfall, the database spans and the logs (`trace_id`). Grafana cannot turn a UUID into a trace ID inside a variable, so the trace table links set `var-trace_id`. The image's bundled sample dashboards are disabled by mounting `docker/grafana/provisioning/empty.yaml` over its `grafana-dashboards.yaml`.
- **Logs**: When enabled, `cmd/api/main.go` calls `logger.Setup` again with an `otelslog` handler, so logs fan out to stdout and OTLP (Loki); the stdout handler adds `trace_id`/`span_id` when the context has a span. Both handlers record the call site (`AddSource` and `otelslog.WithSource`): `source` on stdout, `code.*` attributes in Loki. Always use `slog.*Context(ctx, ...)` in request paths so logs carry `trace_id`/`span_id`. `LogEmailProvider` does not log email bodies (the undo link carries a JWT).
