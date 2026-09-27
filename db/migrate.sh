#!/bin/sh
set -eu
BASE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -n "${UCSI_DATABASE_URL:-}" ]; then
  PSQL_ARGS="$UCSI_DATABASE_URL"
else
  PSQL_ARGS=""
fi
for f in "$BASE_DIR"/migrations/*.sql; do
  if [ -n "$PSQL_ARGS" ]; then
    psql "$PSQL_ARGS" -v ON_ERROR_STOP=1 -f "$f"
  else
    psql -v ON_ERROR_STOP=1 -f "$f"
  fi
done
