# UCSI — Universal SNI Intelligence Engine

UCSI is a self-hosted measurement platform for authorized TLS/SNI endpoint testing and evidence-based ranking.

## One-command installation

On a fresh supported Linux server:

    curl -fsSL https://raw.githubusercontent.com/MOTAKAdev/ucsi/main/install.sh | sudo bash

The installer installs Docker when needed, generates unique secrets, validates the server public IPv4, checks DNS, pulls prebuilt multi-architecture images, runs database migrations, starts the stack, and enables automatic HTTPS with Caddy.

You can also provide the domain non-interactively:

    curl -fsSL https://raw.githubusercontent.com/MOTAKAdev/ucsi/main/install.sh | sudo bash -s -- --domain ucsi.example.com

## Requirements

First-class support is Ubuntu and Debian on amd64 or arm64.

Automatic SNI scanning treats the entered public IPv4 as the remote destination. Outbound TCP/UDP probes use ephemeral local addresses, so the scanner can test arbitrary public IPv4 destinations.

Before installation:
- Create an A record for the chosen domain pointing to the server IPv4.
- Allow TCP 80 and 443 in both the OS firewall and provider/cloud firewall.
- Make sure ports 3000, 8080, 5432 and 6379 are free.

A small deployment can start around 2 CPU cores, 2 GB RAM and 20 GB disk. Scan concurrency should be benchmarked on the target provider.

## What installation creates

- /opt/ucsi — application and deployment files
- /opt/ucsi/.env — instance-specific secrets and settings, mode 600
- Docker volumes for PostgreSQL, Redis and Caddy state
- /usr/local/bin/ucsi — management command
- HTTPS at the configured domain

API, PostgreSQL and Redis are intended to be localhost-only. Caddy is the internet-facing entry point.

## Management

    ucsi status
    ucsi doctor
    ucsi logs api
    ucsi restart
    ucsi update
    ucsi update v1.0.0
    ucsi rollback v1.0.0
    ucsi backup
    ucsi uninstall
    ucsi uninstall --purge

Normal uninstall keeps persistent data. The purge option removes persistent volumes and the installation directory.

## Updates and rollback

Versioned releases use immutable image tags. The stable tag tracks the current released build.

For a normal update:

    ucsi update

For a pinned release:

    ucsi update v1.0.0

Rollback is performed against an existing version tag:

    ucsi rollback v1.0.0

Database migrations must remain backward-compatible for supported rollback paths.

## Architecture

Internet -> Caddy :80/:443 -> Next.js :3000 -> UCSI API :8080 -> PostgreSQL / Redis

The API uses host networking for predictable low-level network measurements. PostgreSQL and Redis are explicitly bound to localhost.

## Release model

GitHub Actions publishes amd64 and arm64 images to GHCR when a version tag such as v1.0.0 is created. Each image also receives the stable tag.

The installer pulls images instead of compiling Go and Node.js on the target server. This keeps installation deterministic and avoids requiring Go, Node.js or package registry access during installation.

## Security

Only scan systems and destinations that you own or are explicitly authorized to measure.

UCSI is a bounded measurement tool. It does not include credential attacks, exploitation, arbitrary shell execution or unrestricted CIDR scanning.

Never commit a real .env file or production credentials.

## Development

Use the repository CI for Go and web tests. Production servers use the published images.

## License

Apache-2.0
