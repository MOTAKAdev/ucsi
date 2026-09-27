# ADR 0007 — Single-VPS first, workers/probes later

Status: Accepted

The initial deployment uses separate stateless API, worker and scheduler processes. Interfaces preserve scan, candidate, observation and probe provenance so user-owned and dedicated probes can be added without redesigning the domain model.
