# ADR-004: Logging & Observability

- **Status:** Accepted
- **Date:** 2026-11-14

## Context

A service built from this template has to answer, in production, "what happened
to this request?" and "is the service healthy?". That needs structured logs,
correlation across log lines, request metrics and traces down to the database.
Two constraints shape the design:

- business code (`services`, `controllers`, `domain`, `repositories`) must not
  depend on a telemetry vendor;
- observability must cost nothing when it is disabled, and must never create
  high-cardinality metrics or record PII.

A custom `domain.Tracer`/`Meter` abstraction was considered and rejected.
OpenTelemetry is already the vendor-neutral layer (no-op by default, swappable
exporters), and a hand-written wrapper would duplicate it with weaker types.

## Decision

**Logging**

- `log/slog` everywhere, with JSON output in production. Request paths always use
  `slog.*Context(ctx, ...)`.
- One **canonical log line** per request from `LoggerMiddleware`, carrying the
  request UUID, user, status and the error stored by `api.HandleError` (see
  [ADR-002](ADR-002-error-handling.md)).
- Each request gets a UUID from `RequestUUIDMiddleware`, which is also attached
  to spans and audit logs.
- Security-relevant actions also go to the **audit log**, a partitioned database
  table and not an observability signal (see [`docs/AUDIT.md`](../AUDIT.md)).

**Telemetry (OpenTelemetry, used directly)**

![Telemetry pipeline](diagrams/telemetry-pipeline.svg)

<sub>[Diagram source](diagrams/telemetry-pipeline.json) ([how to view it interactively](README.md#diagrams))</sub>

- `internal/telemetry` starts the SDK once (traces, metrics and logs over
  OTLP/HTTP, plus Go runtime metrics) and flushes it on shutdown.
- `go.opentelemetry.io/otel*` may only be imported in `internal/telemetry`,
  `internal/middlewares`, `internal/logger`, `internal/factories`, `postgres` and
  `cmd`. There are no telemetry interfaces, no-op providers or mocks in `domain`.
- **Sources:**
  - `TelemetryMiddleware` (`otelhttp`) produces HTTP spans and RED metrics, and
    records the handler's error as an `exception` event on the span.
  - `OTelQueryTracer` creates a span per query, named after the sqlc query, and
    records `db.client.operation.duration`.
  - `RegisterPoolMetrics` publishes pool gauges.
  - The `otelslog` bridge exports logs with `trace_id`/`span_id`.
- **Gating:** `OTEL_ENABLED=false` (the default) wires nothing and returns no-op
  providers. `GET /health` and `GET /ready` never produce spans or metrics.
- **Cardinality and PII:** metrics carry only the route pattern (`http.route`),
  never the raw path, and a constant `server.address`/`server.port`. The request
  UUID goes on spans only. Query text is recorded on spans, but query arguments
  never are.
- **Local stack:** the dev compose runs `grafana/otel-lgtm` (Collector, Tempo,
  Prometheus, Loki, Grafana) with five provisioned dashboards, including a
  per-request investigation view driven by the request UUID.

## Consequences

**Positive**

- Business code stays vendor-neutral by keeping imports out of it, without a
  wrapper to maintain.
- A request can be followed from its UUID to its trace, database spans and logs.
- Any OTLP backend works in production by changing
  `OTEL_EXPORTER_OTLP_ENDPOINT`.

**Negative**

- Business metrics cannot be recorded from services without breaking the import
  rule. They have to be derived in middleware or from spans.
- Dashboards query Prometheus-translated metric names, so renaming an instrument
  means updating the dashboard JSON by hand.
- The LGTM stack is only provisioned for development. Production backends,
  retention and alerting are left to each service.
