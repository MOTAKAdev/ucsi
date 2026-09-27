# Threat model

Primary threats are SSRF, DNS rebinding, redirect-to-private-IP, unbounded work, secret leakage, stale measurements and misleading rankings.

Controls implemented in the foundation:

- hostname normalization converts IDNs to canonical ASCII/punycode and rejects malformed/URL-like input
- public IP classification blocks loopback, private, link-local, multicast and unspecified addresses, including IPv4-mapped IPv6 forms
- TLS measurements resolve public addresses and connect to those accepted addresses directly, avoiding a second DNS lookup for the TLS transaction
- bounded HTTP re-resolves each redirect host, blocks non-standard ports and pins the accepted public IP set for each HTTP transaction
- request limits are bounded in API bodies and scan/sample counts
- no arbitrary shell execution or arbitrary destination injection is exposed by the probe agent
- API authentication uses constant-time bearer-token comparison; browser UI access uses a server-side proxy so the token is not bundled into client JavaScript
- REALITY compatibility is never fabricated by a prerequisite check
- measurements preserve origin, probe identity and timestamps

Required before public exposure: full multi-user RBAC/session and CSRF hardening, centralized secret storage, explicit egress firewall policy, complete source/probe health persistence, signed probe registration/job/results, full historical aggregation, dependency scanning, external penetration testing, and a separately audited authorized REALITY runtime harness.
