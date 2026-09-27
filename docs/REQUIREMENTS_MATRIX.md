# Requirements matrix — Phase-1 implementation

| Area | Phase-1 status | Evidence in repository |
|---|---|---|
| Measurement-first model | Implemented | `internal/domain`, `internal/measurement` |
| DNS public-address validation | Implemented | `internal/security` |
| SSRF / IP classification | Implemented | `internal/security`, API validation |
| TCP/TLS/SNI/certificate measurements | Implemented | `internal/measurement/tls.go` |
| Bounded HTTP evidence | Implemented | `internal/measurement/http.go` |
| Passive CT seed discovery | Implemented | `internal/discovery/discovery.go` |
| Durable queue | Implemented | PostgreSQL `scan_jobs` + `SKIP LOCKED` |
| Scheduler / stale-job recovery | Implemented | `cmd/ucsi-scheduler` |
| Deterministic score | Implemented | `internal/scoring` |
| Evidence-gated TARGET output | Implemented | worker hard filter |
| REALITY candidate separation | Implemented | `internal/reality`, `reality_tests` |
| Next.js operator UI | Implemented | `apps/web` |
| OpenAPI | Implemented | `openapi/openapi.yaml` |
| Docker Compose | Implemented | `docker-compose.yml` |
| Reverse proxy example | Implemented | `deploy/nginx/ucsi.conf` |
| Backup / restore scripts | Implemented | `scripts/backup.sh`, `scripts/restore.sh` |
| Structured logs | Partially implemented | `slog` in service entrypoints |
| Persistent Prometheus metrics | Partial | HTTP metrics endpoint is in-memory in Phase-1 |
| Full multi-user RBAC/sessions/CSRF | Not implemented | Pre-production requirement |
| Multi-vantage probes + signed protocol | Not implemented | Architecture reserved; not in Phase-1 |
| Full CT/PDNS provider fleet | Not implemented | Source interface + one adapter |
| ASN/geo/BGP enrichment | Not implemented | Schema reserved |
| Historical aggregates/change engine | Not implemented | Immutable observation tables reserved |
| HTTP/2/HTTP/3 matrix | Partial | ALPN observed via TLS; dedicated H3 measurement pending |
| Authorized REALITY runtime harness | Not implemented | Candidate/prerequisite semantics only |
| Full acceptance gate | Not verified | Environment lacks Docker/PG/toolchain registry access |
