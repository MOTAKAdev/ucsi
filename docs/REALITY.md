# REALITY adapter policy

Current Xray documentation was checked before implementation. The adapter only permits RAW, XHTTP and gRPC as REALITY transports. A candidate hostname is not itself a REALITY validation result.

`CANDIDATE_ONLY` means prerequisite checks passed but no authorized compatibility handshake has been executed. `TEST_PASSED` must only be emitted by a future runtime harness that launches a pinned Xray binary against an explicitly authorized user-owned test environment and records the resulting evidence.

The repository therefore deliberately does not turn conventional TLS success into a REALITY result.
