# Implementation status

This repository is a production-oriented Phase-1 vertical slice aligned to the master specification. It is intentionally honest about the acceptance boundary: it contains real code for the seed/discovery boundary, DNS public-address resolution, SSRF IP policy, TCP/TLS measurements, certificate inspection, bounded HTTP supporting evidence, durable PostgreSQL scan jobs, deterministic scoring, API auth, Next.js UI, Docker Compose and tests for the core measurement/scoring/security packages.

The full specification still requires additional production work before the system can be called complete: distributed probe orchestration and signed job/result protocol, multi-resolver DNS persistence, complete CT/PDNS source adapters with source-health persistence, ASN/geo/BGP enrichment, immutable historical aggregation/change detection, diversity-aware ranking, full RBAC/session/CSRF controls, persistent Prometheus metrics, streaming exports, full time-decay policy configuration, and the authorized Xray/REALITY runtime test harness.

The repository never emits `TEST_PASSED` for REALITY based only on TLS success or configuration prerequisites. The current adapter emits only prerequisite/candidate semantics until an authorized runtime harness exists.
