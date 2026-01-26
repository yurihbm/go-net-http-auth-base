# Implementation Plan: OpenTelemetry + Grafana LGTM Observability Stack

## Problem Statement

Add comprehensive observability support to the Go API template using OpenTelemetry for instrumentation and the Grafana LGTM stack (Loki, Grafana, Tempo, Prometheus) for telemetry collection and visualization. This will enable:

- **Distributed Tracing** - Track requests across the API layers
- **Metrics** - Monitor request rates, latencies, error rates, and custom business metrics
- **Structured Logging** - Correlate logs with traces via trace IDs

## Decision: Yes, This Is a Good Fit 👍

Adding observability aligns well with the project goals because:

1. **Template Purpose**: This is a production-ready API template. Observability is essential for any production service.
2. **TODO.md Alignment**: Phase 2 already mentions "Logging & Observability" in the ADR section, and the project has structured logging with `slog`.
3. **Educational Value**: Provides a working example of modern observability patterns for developers using this template.
4. **Clean Architecture Fit**: OpenTelemetry integrates well with the layered architecture via dependency inversion and context propagation.

---

## Proposed Approach

### Design Principles

1. **Dependency Inversion (DIP)**: Define telemetry interfaces in `internal/domain/telemetry.go`. Implementations (OpenTelemetry, NoOp) live in `internal/providers/`. This allows swapping vendors without changing application code.

2. **Single Responsibility (SRP)**: Create a dedicated `TelemetryMiddleware` instead of extending existing middlewares:
   - `RequestContextDataMiddleware` → only creates the shared context struct
   - `TelemetryMiddleware` (NEW) → only handles tracing concerns
   - `LoggerMiddleware` → only handles logging (reads from context, no OTel imports)

3. **Open/Closed Principle (OCP)**: Existing middlewares remain unchanged. We add new functionality through composition, not modification.

4. **Graceful Degradation**: When `OTEL_ENABLED=false`, the NoOp provider is used. This satisfies the interface contract while adding zero overhead. The middleware chain remains the same, but telemetry operations are no-ops.

### Architecture Overview

```
┌────────────────────────────────────────────────────────────────────────┐
│                           Go API Application                           │
│                                                                        │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    domain/telemetry.go                          │   │
│  │  TelemetryProvider, Tracer, Meter, Span (interfaces)            │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                   ▲                                    │
│                                   │ implements                         │
│            ┌──────────────────────┘                                    │
│            │                      │                                    │
│  ┌─────────▼─────────┐  ┌─────────▼────────┐                           │
│  │ OTelTelemetry     │  │ NoOpTelemetry    │                           │
│  │ Provider          │  │ Provider         │                           │
│  │ (providers/)      │  │ (providers/)     │                           │
│  └─────────┬─────────┘  └──────────────────┘                           │
│            │                                                           │
│  ┌─────────▼────────────────────────────────────────────────────────┐  │
│  │                     Middleware Chain (SOLID)                     │  │
│  │                                                                  │  │
│  │  1. RequestContextDataMiddleware → creates shared context struct │  │
│  │  2. TelemetryMiddleware (NEW)    → creates span, populates IDs   │  │
│  │  3. RequestUUIDMiddleware        → adds request UUID             │  │
│  │  4. LoggerMiddleware             → logs with all context data    │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                        │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐         │
│  │   Controllers   │  │    Services     │  │  Repositories   │         │
│  │   (HTTP Spans)  │  │ (Business Spans)│  │   (DB Spans)    │         │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘         │
│           └────────────────────┴────────────────────┘                  │
└────────────────────────────────│───────────────────────────────────────┘
                                 │ OTLP (gRPC/HTTP)
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     OpenTelemetry Collector                            │
│                     (Receives, processes, exports)                     │
└───────────┬────────────────────┬────────────────────┬──────────────────┘
            │                    │                    │
            ▼                    ▼                    ▼
     ┌──────────┐          ┌──────────┐         ┌──────────┐
     │  Tempo   │          │Prometheus│         │   Loki   │
     │ (Traces) │          │(Metrics) │         │  (Logs)  │
     └────┬─────┘          └────┬─────┘         └────┬─────┘
          │                     │                    │
          └─────────────────────┼────────────────────┘
                                │
                         ┌──────▼──────┐
                         │   Grafana   │
                         │ (Dashboards)│
                         └─────────────┘
```

---

## Work Plan

### Phase 1: Domain Interfaces & Provider Abstraction

- [ ] **1.1 Define telemetry interfaces in `internal/domain/telemetry.go`**
  - `TelemetryProvider` interface (Init, Shutdown, Tracer, Meter)
  - `Tracer` interface (StartSpan, SpanFromContext)
  - `Meter` interface (Counter, Histogram, Gauge)
  - `Span` interface (SetAttributes, RecordError, End, TraceID, SpanID)

- [ ] **1.2 Create OpenTelemetry provider (`internal/providers/otel_telemetry_provider.go`)**
  - Implement `TelemetryProvider` interface using OpenTelemetry SDK
  - Configure OTLP exporters (traces, metrics)
  - Configure resource attributes (service name, version, environment)
  - Add graceful shutdown handling

- [ ] **1.3 Create NoOp provider (`internal/providers/noop_telemetry_provider.go`)**
  - Implement `TelemetryProvider` with no-op operations
  - Used when `OTEL_ENABLED=false`
  - Zero overhead, satisfies interface contract

### Phase 2: Go Application Instrumentation

- [ ] **2.1 Install OpenTelemetry Go SDK dependencies**
  - `go.opentelemetry.io/otel` (core SDK)
  - `go.opentelemetry.io/otel/sdk` (SDK implementation)
  - `go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp` (trace exporter)
  - `go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp` (metrics exporter)
  - `go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp` (HTTP instrumentation)
  - `go.opentelemetry.io/contrib/instrumentation/github.com/jackc/pgx/v5/otelpgx` (pgx instrumentation)

- [ ] **2.2 Create dedicated `TelemetryMiddleware` (SOLID: Single Responsibility)**
  - Create `internal/middlewares/telemetry_middleware.go`
  - Accept `TelemetryProvider` interface via dependency injection
  - Create HTTP span, propagate trace context
  - Populate `TraceID` and `SpanID` into `RequestContextData`
  - Add middleware tests

- [ ] **2.3 Update shared request context (minimal change)**
  - Add `TraceID` and `SpanID` fields to `api.RequestContextData`
  - Update `LoggerMiddleware` to read and log these fields (no OTel imports needed)

- [ ] **2.4 Instrument database layer**
  - Configure pgx with OpenTelemetry tracing in `postgres/connection.go`

- [ ] **2.5 Wire up in `cmd/main.go`**
  - Initialize telemetry provider based on `OTEL_ENABLED`
  - Inject provider into `TelemetryMiddleware`
  - Register middleware in correct order:
    1. `RequestContextDataMiddleware`
    2. `TelemetryMiddleware`
    3. `RequestUUIDMiddleware`
    4. `LoggerMiddleware`
  - Add graceful shutdown

- [ ] **2.6 Add environment configuration to `.env.example`**
  - `OTEL_ENABLED` (toggle telemetry on/off)
  - `OTEL_EXPORTER_OTLP_ENDPOINT`
  - `OTEL_SERVICE_NAME`
  - `OTEL_TRACES_SAMPLER` (for production sampling)

### Phase 3: Docker Compose Infrastructure (Grafana LGTM Stack)

- [ ] **3.1 Create OpenTelemetry Collector configuration**
  - Create `docker/otel/otel-collector-config.yaml`
  - Configure receivers (OTLP gRPC and HTTP)
  - Configure processors (batch, resource detection)
  - Configure exporters (Tempo, Prometheus, Loki)

- [ ] **3.2 Create Grafana configuration**
  - Create `docker/grafana/provisioning/datasources/datasources.yaml`
  - Configure Tempo, Prometheus, and Loki datasources
  - Enable trace-to-logs and trace-to-metrics correlation

- [ ] **3.3 Create sample Grafana dashboards**
  - Create `docker/grafana/provisioning/dashboards/dashboards.yaml`
  - Create `docker/grafana/dashboards/api-overview.json`
    - Request rate, error rate, latency percentiles
    - Database query performance
    - Active traces panel

- [ ] **3.4 Create Tempo configuration**
  - Create `docker/tempo/tempo-config.yaml`

- [ ] **3.5 Create Loki configuration**
  - Create `docker/loki/loki-config.yaml`

- [ ] **3.6 Create Prometheus configuration**
  - Create `docker/prometheus/prometheus.yaml`

- [ ] **3.7 Update `docker/docker-compose.dev.yaml`**
  - Add OpenTelemetry Collector service
  - Add Tempo service (distributed tracing)
  - Add Loki service (log aggregation)
  - Add Prometheus service (metrics)
  - Add Grafana service (dashboards)
  - Configure networking and volume mounts

- [ ] **3.8 Update `docker/docker-compose.prod.yaml`**
  - Add observability services with production settings
  - Configure persistent volumes for telemetry data
  - Add resource limits

### Phase 4: Documentation & Testing

- [ ] **4.1 Update README.md**
  - Add observability section explaining the setup
  - Document how to access Grafana dashboards (default: http://localhost:3000)
  - Document environment variables
  - Explain how to swap telemetry providers

- [ ] **4.2 Add unit tests**
  - Test telemetry provider initialization
  - Test `TelemetryMiddleware` (using NoOp provider)

- [ ] **4.3 Manual testing**
  - Start dev environment with `docker-compose up`
  - Make API requests and verify traces appear in Grafana Tempo
  - Verify logs show `trace_id` and link to traces in Loki
  - Verify metrics are scraped by Prometheus

- [ ] **4.4 Run existing tests**
  - Ensure instrumentation doesn't break existing tests
  - Tests should work with telemetry disabled (NoOp provider)

---

## Files to Create

| File                                                       | Purpose                                                       |
| ---------------------------------------------------------- | ------------------------------------------------------------- |
| `internal/domain/telemetry.go`                             | Telemetry interfaces (TelemetryProvider, Tracer, Meter, Span) |
| `internal/providers/otel_telemetry_provider.go`            | OpenTelemetry implementation                                  |
| `internal/providers/noop_telemetry_provider.go`            | NoOp implementation (when OTEL_ENABLED=false)                 |
| `internal/middlewares/telemetry_middleware.go`             | Dedicated telemetry middleware (SRP)                          |
| `internal/middlewares/telemetry_middleware_test.go`        | Middleware tests                                              |
| `docker/otel/otel-collector-config.yaml`                   | OTel Collector configuration                                  |
| `docker/grafana/provisioning/datasources/datasources.yaml` | Grafana datasource config                                     |
| `docker/grafana/provisioning/dashboards/dashboards.yaml`   | Dashboard provisioning                                        |
| `docker/grafana/dashboards/api-overview.json`              | Pre-built API dashboard                                       |
| `docker/tempo/tempo-config.yaml`                           | Tempo configuration                                           |
| `docker/loki/loki-config.yaml`                             | Loki configuration                                            |
| `docker/prometheus/prometheus.yaml`                        | Prometheus scrape config                                      |

## Files to Modify

| File                                        | Changes                                                                |
| ------------------------------------------- | ---------------------------------------------------------------------- |
| `go.mod`                                    | Add OpenTelemetry dependencies                                         |
| `internal/api/context.go`                   | Add `TraceID`, `SpanID` fields to `RequestContextData`                 |
| `internal/middlewares/logger_middleware.go` | Read `traceID`, `spanID` from context (no OTel imports)                |
| `cmd/main.go`                               | Initialize telemetry provider, inject into middleware, set chain order |
| `postgres/connection.go`                    | Add pgx OpenTelemetry instrumentation                                  |
| `.env.example`                              | Add OTEL configuration variables                                       |
| `docker/docker-compose.dev.yaml`            | Add observability stack services                                       |
| `docker/docker-compose.prod.yaml`           | Add observability stack services                                       |
| `README.md`                                 | Document observability features                                        |

---

## Notes & Considerations

1. **SOLID Principles**:
   - **SRP**: Each middleware has one responsibility. `TelemetryMiddleware` handles only tracing.
   - **OCP**: Existing middlewares unchanged. New functionality via composition.
   - **DIP**: Application depends on `TelemetryProvider` interface, not concrete implementations.

2. **Graceful Degradation**: The application should work normally if:
   - `OTEL_ENABLED=false` → NoOp provider is used
   - OTel Collector is unavailable → logs a warning, continues without telemetry

3. **Performance**: Use async batch exporters to minimize latency impact. Configure appropriate sampling for production.

4. **Sampling Strategy**:
   - Development: sample 100% of traces
   - Production: consider probabilistic sampling (e.g., 10%) to reduce costs

5. **Log Correlation**: The key value-add is clicking from a trace span directly to relevant logs. This requires `trace_id` and `span_id` in slog output, which we achieve by extending existing middlewares.

6. **Testing Consideration**: Unit tests use the NoOp provider, so they don't require a running OTel Collector.

---

## Estimated Effort

- **Phase 1** (Interfaces & Providers): ~1-2 hours
- **Phase 2** (Go instrumentation): ~2-3 hours
- **Phase 3** (Docker infrastructure): ~1-2 hours
- **Phase 4** (Documentation & testing): ~1 hour

**Total: ~5-8 hours**

---

## Success Criteria

- [ ] Telemetry interfaces defined in `internal/domain/telemetry.go`
- [ ] OpenTelemetry provider implements telemetry interfaces
- [ ] NoOp provider available for tests and disabled telemetry
- [ ] Making a request to `GET /health` creates a visible trace in Grafana Tempo
- [ ] Database queries appear as child spans in traces
- [ ] Logs in Grafana Loki show `trace_id` field and link to traces
- [ ] Grafana dashboard shows request rate, error rate, and latency metrics
- [ ] Existing tests pass without modification
- [ ] Application works correctly when telemetry is disabled or OTel Collector is unavailable
