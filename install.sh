#!/usr/bin/env bash
set -Eeuo pipefail

REPO="https://github.com/MOTAKAdev/ucsi.git"
DEFAULT_DIR="/opt/ucsi"
DEFAULT_VERSION="stable"

DOMAIN=""
INSTALL_DIR="$DEFAULT_DIR"
UCSI_VERSION="$DEFAULT_VERSION"
ORIGIN_IP=""
SKIP_DNS_CHECK="false"
NO_FIREWALL="false"
NON_INTERACTIVE="false"

log() { printf '[UCSI] %s\n' "$*"; }
die() { printf '[UCSI][ERROR] %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
UCSI one-click installer

Usage:
  curl -fsSL https://raw.githubusercontent.com/MOTAKAdev/ucsi/main/install.sh | sudo bash

Options:
  --domain DOMAIN
  --version stable|vX.Y.Z
  --dir PATH
  --origin-ip IPv4
  --skip-dns-check
  --no-firewall
  --non-interactive
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="${2:?missing domain}"; shift 2 ;;
    --version) UCSI_VERSION="${2:?missing version}"; shift 2 ;;
    --dir) INSTALL_DIR="${2:?missing directory}"; shift 2 ;;
    --origin-ip) ORIGIN_IP="${2:?missing origin IP}"; shift 2 ;;
    --skip-dns-check) SKIP_DNS_CHECK="true"; shift ;;
    --no-firewall) NO_FIREWALL="true"; shift ;;
    --non-interactive) NON_INTERACTIVE="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ "$EUID" -eq 0 ]] || die "Run this installer as root (sudo)."

source /etc/os-release || die "Cannot detect operating system."
case "${ID:-}" in
  ubuntu|debian) ;;
  *) die "Supported operating systems: Ubuntu and Debian." ;;
esac

case "$(uname -m)" in
  x86_64|amd64|aarch64|arm64) ;;
  *) die "Supported CPU architectures: amd64 and arm64." ;;
esac

apt-get update -y >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl git openssl iproute2 >/dev/null

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  log "Installing Docker..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
fi

docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required."

if [[ -z "$DOMAIN" && "$NON_INTERACTIVE" != "true" ]]; then
  [[ -e /dev/tty ]] || die "Interactive domain input requires a terminal. Use --domain DOMAIN."
  read -r -p "Domain for UCSI (example: ucsi.example.com): " DOMAIN </dev/tty
fi
[[ -n "$DOMAIN" ]] || die "A domain is required."

if ! [[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; then
  die "Invalid domain name: $DOMAIN"
fi

if [[ -z "$ORIGIN_IP" ]]; then
  ORIGIN_IP="$(curl -4fsS --max-time 10 https://api.ipify.org || true)"
fi
[[ "$ORIGIN_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "Could not detect a public IPv4 address. Use --origin-ip."

if ! ip -4 addr show | awk '{print $2}' | cut -d/ -f1 | grep -Fxq "$ORIGIN_IP"; then
  die "The origin IP ($ORIGIN_IP) is not assigned to a local interface. UCSI requires a directly assigned public IPv4 for source-bound measurements."
fi

if [[ "$SKIP_DNS_CHECK" != "true" ]]; then
  dns_match="false"
  while read -r ip; do
    [[ "$ip" == "$ORIGIN_IP" ]] && dns_match="true"
  done < <(getent ahostsv4 "$DOMAIN" | awk '{print $1}' | sort -u)
  [[ "$dns_match" == "true" ]] || die "DNS A record for $DOMAIN does not point to $ORIGIN_IP. Fix DNS first or use --skip-dns-check."
fi

for port in 80 443 5432 6379 8080 3000; do
  if ss -ltnH 2>/dev/null | awk -v p=":$port$" '$4 ~ p {found=1} END{exit !found}'; then
    die "TCP port $port is already in use. Free it before installing UCSI."
  fi
done

if [[ "$NO_FIREWALL" != "true" ]]; then
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw allow 80/tcp >/dev/null
    ufw allow 443/tcp >/dev/null
  elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-service=http >/dev/null
    firewall-cmd --permanent --add-service=https >/dev/null
    firewall-cmd --reload >/dev/null
  fi
fi

if [[ -e "$INSTALL_DIR" && ! -d "$INSTALL_DIR/.git" ]]; then
  die "Install directory exists but is not a UCSI checkout: $INSTALL_DIR"
fi

if [[ ! -d "$INSTALL_DIR/.git" ]]; then
  mkdir -p "$(dirname "$INSTALL_DIR")"
  log "Downloading UCSI..."
  if [[ "$UCSI_VERSION" == "stable" ]]; then
    git clone --depth 1 "$REPO" "$INSTALL_DIR" >/dev/null
  else
    git clone --depth 1 --branch "$UCSI_VERSION" "$REPO" "$INSTALL_DIR" >/dev/null
  fi
fi

cd "$INSTALL_DIR"
mkdir -p runtime backups
chmod 700 runtime backups

if [[ -f .env ]]; then
  log "Existing .env found; preserving it."
else
  DB_PASSWORD="$(openssl rand -hex 24)"
  API_TOKEN="$(openssl rand -hex 32)"
  cat > .env <<EOF
UCSI_VERSION=$UCSI_VERSION
UCSI_IMAGE_PREFIX=ghcr.io/motakadev
UCSI_DOMAIN=$DOMAIN
UCSI_DB_PASSWORD=$DB_PASSWORD
UCSI_API_TOKEN=$API_TOKEN
UCSI_CORS_ORIGINS=https://$DOMAIN
UCSI_CT_ENABLED=false
EOF
  chmod 600 .env
fi

ln -sf "$INSTALL_DIR/scripts/ucsi" /usr/local/bin/ucsi

log "Validating Compose..."
docker compose config >/dev/null

log "Pulling images..."
docker compose pull postgres redis api worker scheduler web caddy

log "Running migrations..."
docker compose run --rm migrate

log "Starting UCSI..."
docker compose up -d

log "Checking API..."
for _ in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:8080/api/v1/system/health >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
curl -fsS http://127.0.0.1:8080/api/v1/system/health >/dev/null || die "API did not become healthy."

log "UCSI installed successfully."
log "Dashboard: https://$DOMAIN"
log "Management: ucsi status"
