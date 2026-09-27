# ADR 0002 — Durable PostgreSQL job queue for single-VPS Phase-1

Status: Accepted

`scan_jobs` is claimed with `FOR UPDATE SKIP LOCKED`. This avoids making Redis job state authoritative during the first deployment and preserves recovery across worker restarts. Redis remains an integration point for caching/rate-limit/ephemeral state. A future Redis Streams transport can be introduced behind the queue interface.
