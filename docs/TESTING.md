# Testing plan

## Unit

Run the security, measurement, scoring and REALITY unit tests. The scoring test verifies deterministic output; security tests cover URL/hostname rejection and private/loopback address rejection; REALITY tests ensure unsupported transports cannot become a passing state.

## Integration

On a network-enabled CI runner:

1. start PostgreSQL and Redis with Compose;
2. run all migrations twice to verify idempotency;
3. start API, worker and scheduler;
4. create a scan against an authorized public test hostname;
5. poll scan status and result snapshots;
6. verify only TLS/SNI/certificate-valid candidates become user-facing TARGETs;
7. cancel a long-running scan and verify pending work is cancelled;
8. stop/restart the worker and verify stale jobs are recoverable;
9. run backup/restore into an isolated PostgreSQL instance.

## Security

Use dependency and container scanning, HTTP fuzzing for target/redirect parsing, SSRF regression cases, DNS-rebinding simulations, oversized body/header tests, auth bypass tests, and an external penetration test before public exposure.

## Performance

Benchmark score calculation, database candidate/result queries and bounded measurement concurrency. Load-test queue depth, worker recovery and large result sets. Validate that UI charts/export queries use aggregates/streaming rather than loading entire historical datasets into memory.
