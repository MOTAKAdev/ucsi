# Architecture

```text
Next.js UI
   |
   v
Go API  ---> PostgreSQL
   |             |
   +----------> Redis (cache/rate-limit/ephemeral state)
   |
   +---- scan_jobs ----> Go worker
                           |
                           +--> discovery adapters
                           +--> DNS/IP policy
                           +--> TCP/TLS measurement
                           +--> HTTP supporting evidence
                           +--> deterministic score
                           +--> immutable observations
                           +--> result snapshot

Optional: user-owned probe agent
Optional: RIPE Atlas adapter
Optional: authorized REALITY harness
```

The initial worker is stateless and claims work through a PostgreSQL SKIP LOCKED job table. Redis is used for cache/rate-limit state; this keeps job state durable even if Redis is unavailable. Horizontal scaling can later move queue transport to Redis Streams without changing domain interfaces.

The API and worker are intentionally separate processes but share one Go module and domain model. There is no arbitrary shell-execution path in the probe agent.
