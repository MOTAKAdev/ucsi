#!/bin/sh
set -eu
: "${UCSI_DATABASE_URL:?UCSI_DATABASE_URL is required}"
file="${1:?usage: restore.sh backup.dump}"
pg_restore "$UCSI_DATABASE_URL" --clean --if-exists --no-owner "$file"
