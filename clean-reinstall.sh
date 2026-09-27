#!/usr/bin/env bash
set -Eeuo pipefail

REPO="https://github.com/MOTAKAdev/ucsi.git"
DIR="/opt/ucsi"
DOMAIN="${UCSI_DOMAIN:-www.pikify.ir}"
ORIGIN_IP="${UCSI_ORIGIN_IP:-206.1.103.54}"

die() { printf '[UCSI-CLEAN][ERROR] %s\n' "$*" >&2; exit 1; }
log() { printf '[UCSI-CLEAN] %s\n' "$*"; }

[[ "$EUID" -eq 0 ]] || die "Run as root."

command -v docker >/dev/null 2>&1 || die "Docker is not installed."
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required."
command -v git >/dev/null 2>&1 || apt-get update -y >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y git ca-certificates openssl curl >/dev/null

log "Stopping and deleting old UCSI stack..."
if [[ -f "$DIR/docker-compose.yml" ]]; then
  docker compose -f "$DIR/docker-compose.yml" down -v --remove-orphans || true
fi
docker rm -f $(docker ps -aq --filter "label=com.docker.compose.project=ucsi") 2>/dev/null || true
docker volume rm $(docker volume ls -q --filter "label=com.docker.compose.project=ucsi") 2>/dev/null || true
docker image ls --format '{{.Repository}}:{{.Tag}}' | awk '/^ghcr\.io\/motakadev\/ucsi-(api|worker|scheduler|web):/ {print}' | xargs -r docker image rm -f || true
rm -rf "$DIR"

log "Cloning fresh GitHub main..."
git clone --depth 1 "$REPO" "$DIR" >/dev/null
cd "$DIR"

log "Writing fresh environment..."
DB_PASSWORD="$(openssl rand -hex 24)"
API_TOKEN="$(openssl rand -hex 32)"
cat > .env <<EOF
UCSI_VERSION=stable
UCSI_IMAGE_PREFIX=ghcr.io/motakadev
UCSI_DOMAIN=$DOMAIN
UCSI_DB_PASSWORD=$DB_PASSWORD
UCSI_API_TOKEN=$API_TOKEN
UCSI_CORS_ORIGINS=https://$DOMAIN
UCSI_CT_ENABLED=false
EOF
chmod 600 .env

log "Validating Compose..."
docker compose config >/dev/null

log "Pulling base images..."
docker compose pull postgres redis caddy

log "Building fresh application images from this Git commit..."
docker compose build --no-cache api worker scheduler web

log "Starting clean PostgreSQL/Redis..."
docker compose up -d postgres redis

for i in $(seq 1 60); do
  if docker exec ucsi-postgres-1 pg_isready -h 127.0.0.1 -U ucsi -d ucsi >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

log "Running fresh database migrations..."
docker compose run --rm migrate

log "Starting fresh UCSI stack..."
docker compose up -d api worker scheduler web caddy

log "Waiting for API..."
for i in $(seq 1 60); do
  if curl -fsS --max-time 3 http://127.0.0.1:8080/api/v1/system/health >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
curl -fsS --max-time 5 http://127.0.0.1:8080/api/v1/system/health >/dev/null || die "API health check failed."

log "Waiting for web..."
for i in $(seq 1 60); do
  if curl -fsS --max-time 3 http://127.0.0.1:3000/ >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
curl -fsS --max-time 5 http://127.0.0.1:3000/ >/dev/null || die "Web health check failed."

log "Waiting for public HTTPS/Caddy..."
for i in $(seq 1 60); do
  if curl -fsS --http2 --max-time 10 -o /dev/null "https://$DOMAIN/"; then
    break
  fi
  sleep 2
done
curl -fsS --http2 --max-time 15 -o /dev/null "https://$DOMAIN/" || die "Public HTTPS failed."

log "Fresh install complete."
git rev-parse --short HEAD
