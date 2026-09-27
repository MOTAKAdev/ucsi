# Operations

1. Copy `.env.example` to `.env` and replace all secrets.
2. Start PostgreSQL, Redis and the application containers with Compose.
3. Run the database migration job.
4. Verify `/api/v1/system/health`.
5. Create a TLS scan against a hostname you own or are authorized to measure.
6. Inspect the scan record and result snapshot.

Backups: use `pg_dump` for logical PostgreSQL backups and test a restore into an isolated PostgreSQL 18 instance before relying on the backup.

Rollback: pin the previous container image tag and run only compatible migrations. Never mutate historical observations in place.
