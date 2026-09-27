# Security posture

UCSI treats DNS resolution and redirects as an SSRF boundary. Public API scans reject private, loopback, link-local, unspecified, multicast and unique-local destinations. Active checks are bounded by candidate, sample, timeout and concurrency policies.

Do not expose the development bearer token or public registration mode. Use a random high-entropy API token and place the service behind a TLS-terminating reverse proxy in any non-local deployment.

The Phase-1 foundation is not a substitute for a pre-production penetration test. Before public exposure, complete RBAC/session hardening, CSRF protections for cookie sessions, egress firewall policy, dependency scanning, centralized secret management, full redirect destination pinning, probe authentication, and an authorized REALITY harness audit.
