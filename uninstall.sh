#!/usr/bin/env bash
set -euo pipefail

PURGE=0
if [[ "${1:-}" == "--purge" ]]; then
  PURGE=1
elif [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  echo "Usage: ./uninstall.sh [--purge]"
  echo "  --purge   Also delete /etc/tailauth and /var/lib/tailauth"
  exit 0
fi

BLUE='\033[1;34m'
GREEN='\033[1;32m'
NC='\033[0m'
step() { echo -e "${BLUE}==>${NC} $*"; }
ok()   { echo -e "${GREEN}✔${NC} $*"; }

PAM_FILE="/etc/pam.d/sudo"
if [[ -f "$PAM_FILE" ]] && grep -q "tailauth" "$PAM_FILE"; then
  step "Removing TailAuth from $PAM_FILE"
  TMP_PAM="$(mktemp)"
  awk '
    BEGIN { skip=0 }
    /^# tailauth-begin$/ { skip=1; next }
    /^# tailauth-end$/ { skip=0; next }
    skip==0 && !/tailauth/ { print }
  ' "$PAM_FILE" > "$TMP_PAM"
  sudo install -m 0644 -o root -g root "$TMP_PAM" "$PAM_FILE"
  rm -f "$TMP_PAM"
  ok "Restored $PAM_FILE"
fi

PORT="8443"
if [[ -f /etc/tailauth/config.json ]] && command -v python3 >/dev/null 2>&1; then
  PORT="$(python3 -c 'import json; print(json.load(open("/etc/tailauth/config.json")).get("https_port", 8443))' 2>/dev/null || echo 8443)"
fi

if command -v tailscale >/dev/null 2>&1; then
  step "Removing Tailscale Serve rule on port $PORT"
  sudo tailscale serve --https="$PORT" off 2>/dev/null \
    || sudo tailscale serve clear "https:$PORT" 2>/dev/null \
    || true
fi

if systemctl list-unit-files tailauth.service >/dev/null 2>&1; then
  step "Stopping and disabling tailauth.service"
  sudo systemctl disable --now tailauth.service 2>/dev/null || true
  sudo rm -f /etc/systemd/system/tailauth.service
  sudo systemctl daemon-reload
  ok "Removed tailauth.service"
fi

if [[ -f /usr/local/bin/tailauth ]]; then
  step "Removing /usr/local/bin/tailauth"
  sudo rm -f /usr/local/bin/tailauth
fi

if [[ "$PURGE" -eq 1 ]]; then
  step "Purging /etc/tailauth and /var/lib/tailauth"
  sudo rm -rf /etc/tailauth /var/lib/tailauth
fi

ok "TailAuth uninstalled cleanly."
