#!/bin/sh
set -eu
: "${UCSI_DATABASE_URL:?UCSI_DATABASE_URL is required}"
out="${1:-ucsi-$(date -u +%Y%m%dT%H%M%SZ).dump}"
pg_dump "$UCSI_DATABASE_URL" --format=custom --file="$out"
printf '%s\n' "$out"
