# UCSI Current-State Research — 2026-09-19

## Decisions

- Go: target toolchain 1.27.1. Go's official release history records 1.27.1 as released 2026-09-01; 1.27.0 was the August 2026 major release.
- Xray-core: production adapter baseline is the latest official stable line identified during research, v26.9.8. The official package/release record shows v26.9.8 published as a release on 2026-09-08, while v26.9.9 is explicitly marked pre-release; therefore the production baseline is v26.9.8.
- REALITY: current Xray documentation states that REALITY can be used with RAW, XHTTP and gRPC. This compatibility is encoded rather than inferred from old scanners.
- PostgreSQL: target 18.6, released 2026-08-13. PostgreSQL 19 was still beta at this research date.
- Redis OSS: target 8.6.6. Redis' official release notes identify 8.6.6 (August 2026) as a security release; Redis documentation lists 8.6 as GA-supported.
- Next.js: target 16.3.3 Active LTS, from the August 2026 security release announcement.
- CT: CT is treated as discovery evidence rather than live-service evidence. Chrome's CT log list is updated daily and offered without an availability SLA, so the implementation uses an adapter boundary and caching/disable controls rather than binding product semantics to one CT endpoint.
- RIPE Atlas: if integrated later, use the current v2 API and preserve measurement/probe provenance; results may be delayed and can be large/streamed.

## External projects considered

Subfinder, httpx and OWASP Amass are optional external discovery/enrichment integrations. Their release state is checked at maintenance time; no external tool is required for the core seed -> DNS -> TCP -> TLS path.

ZGrab2 remains an optional high-volume measurement reference, not a runtime dependency for the single-VPS build.

## Research rule

Before upgrading any pinned component, re-check the official release page/source and rerun the security, integration and compatibility suite. Avoid treating pre-releases as production defaults.

- Go `x/net`: v0.59.0 is the researched current module line. It provides the IDNA implementation used by hostname canonicalization and exposes HTTP/3 support for a later dedicated transport adapter. The security database also identifies `x/net/idna` versions before v0.55.0 as affected by a 2026 advisory, so the implementation intentionally uses a newer line rather than an old tutorial pin.
- pgx: v5.11.0 is the current stable release identified during research (2026-09-07) and is used for PostgreSQL access. The project was selected for its native PostgreSQL support and current Go compatibility.
