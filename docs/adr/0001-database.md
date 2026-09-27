# ADR 0001 — PostgreSQL as system of record

Status: Accepted

PostgreSQL is the authoritative store because observations, history, job state and audit data require durable transactions, indexes, partitioning and immutable evidence semantics. A future analytical store may consume normalized observations without becoming the source of truth.
