# ADR 0003 — Preserve per-origin observations

Status: Accepted

Measurements retain origin, probe ID, timestamp and resolved IP. Central-worker measurements are never mislabeled as measurements from the user's server. This prevents geographic inference from masquerading as path measurement.
