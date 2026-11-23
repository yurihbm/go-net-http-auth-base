# ADR-013: Trusted Proxies and Client IP Resolution

- **Status:** Accepted
- **Date:** 2026-11-23

## Context

Every client IP came from `r.RemoteAddr` (ADR-005). Behind a reverse proxy
(Traefik, nginx, a cloud load balancer) that is always the proxy's address, so
all clients share one rate-limit bucket and the audit log and request log record
the proxy instead of the client. Reading `X-Forwarded-For` unconditionally is
worse: any client can send the header and pick its own IP, which defeats the
rate limiter and falsifies the audit trail.

## Decision

- **Allow-list.** `TRUSTED_PROXIES` is a comma-separated list of CIDRs or bare
  IPs (a bare IP is a /32 or /128). It is empty by default, so a deployment
  without a proxy never reads `X-Forwarded-For`. An invalid entry fails
  `config.Load`.
- **Resolution.** `ClientIPMiddleware` runs right after the request context data
  middleware and stores the result in `RequestContextData.ClientIP`. If the
  connection's `RemoteAddr` host is not in the allow-list, it is the client. If
  it is, the values of every `X-Forwarded-For` header are joined and walked right
  to left, skipping addresses in the allow-list; the first address outside it is
  the client. Each trusted proxy appends the address it received from, so
  entries left of that point are client-controlled and never used.
- **Edge cases.** If every entry is trusted, the leftmost one is used. An entry
  that is not a valid IP ends the walk at the last trusted hop seen (the
  `RemoteAddr` host when the rightmost entry is invalid): nothing left of
  garbage is believed. The walk stops after 32 hops and uses the address
  reached so far, so a header stuffed with entries (Traefik forwards the
  client's) cannot cost more than a bounded walk; real chains are far shorter. IPv4-mapped IPv6 addresses are unmapped before matching
  and storing.
- **Telemetry.** The span's `client.address` is set to `ClientIP`, overriding the
  value `otelhttp` derives from the leftmost `X-Forwarded-For` entry.
- **Consumers.** The rate limiter key, the `ip` attribute of the request log and
  the audit log IP (`api.GetClientMetadata`) read `ClientIP` and fall back to the
  `RemoteAddr` host when it is absent. The log `ip` no longer includes the port.

## Alternatives considered

- **Leftmost `X-Forwarded-For` entry.** Client-controlled; spoofable.
- **Hop count (trust the Nth entry from the right).** Breaks silently when the
  proxy chain changes and cannot tell a proxy from a client.
- **`X-Real-IP`.** A single value with no chain, set by whichever proxy is
  configured to; same trust problem and less information.
- **RFC 7239 `Forwarded`.** The standard, but proxies and load balancers
  overwhelmingly emit `X-Forwarded-For`, and parsing it adds complexity for no
  gain here.

## Consequences

- The allow-list must match the real proxy addresses. Too narrow and clients
  share the proxy's bucket again; too wide (for example a range containing
  clients) lets those clients spoof their IP.
- The proxy must append to, not just pass through, `X-Forwarded-For`; most do by
  default.
- This supersedes ADR-005's statement that the rate limiter ignores
  `X-Forwarded-For`.
- Accepted residual risk: the rate limiter is still in memory and per instance.
  With several replicas each keeps its own buckets, and a shared store is still
  needed for a global limit.
