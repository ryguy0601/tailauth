#!/usr/bin/env bash
set -euo pipefail

# TailAuth installer — works on Arch/Omarchy, Ubuntu/Debian, Fedora.
# Builds the Rust binary as the invoking user, configures tailscale serve HTTPS,
# installs the systemd daemon, enrolls a phone fingerprint, and enables PAM sudo.

PORT="${TAILAUTH_PORT:-8443}"
TIMEOUT="${TAILAUTH_TIMEOUT:-60}"
SKIP_ENROLL=0
NO_PAM=0
ALLOWED_TS_USERS=()

BLUE='\033[1;34m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
BOLD='\033[1m'
NC='\033[0m'

step() { echo -e "\n${BLUE}==>${NC} ${BOLD}$*${NC}"; }
ok()   { echo -e "${GREEN}✔${NC} $*"; }
warn() { echo -e "${YELLOW}!${NC} $*"; }
die()  { echo -e "${RED}✖${NC} $*" >&2; exit 1; }

usage() {
  cat <<EOF
Usage: ./install.sh [OPTIONS]

Options:
  --port <PORT>            Tailscale Serve HTTPS port (default: 8443)
  --timeout <SECS>         PAM QR approval timeout in seconds (default: 60)
  --allow-ts-user <LOGIN>  Restrict WebAuthn approval to specific Tailscale login (repeatable)
  --skip-enroll            Skip interactive phone fingerprint enrollment
  --no-pam                 Install daemon/CLI without modifying /etc/pam.d/sudo
  -h, --help               Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)
      PORT="${2:?--port requires a value}"
      shift 2
      ;;
    --timeout)
      TIMEOUT="${2:?--timeout requires a value}"
      shift 2
      ;;
    --allow-ts-user)
      ALLOWED_TS_USERS+=("${2:?--allow-ts-user requires a login}")
      shift 2
      ;;
    --skip-enroll)
      SKIP_ENROLL=1
      shift
      ;;
    --no-pam)
      NO_PAM=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "Unknown option: $1"
      ;;
  esac
done

TARGET_USER="${SUDO_USER:-$USER}"
if [[ "$TARGET_USER" == "root" ]]; then
  TARGET_USER="$(logname 2>/dev/null || echo root)"
fi

if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
  SCRIPT_DIR=""
fi

# Support `curl -fsSL ... | bash` when TAILAUTH_REPO is set
if [[ -z "$SCRIPT_DIR" || ! -f "$SCRIPT_DIR/Cargo.toml" ]]; then
  if [[ -n "${TAILAUTH_REPO:-}" ]]; then
    step "Cloning TailAuth from $TAILAUTH_REPO"
    CLONE_DIR="${HOME}/.local/share/tailauth-src"
    rm -rf "$CLONE_DIR"
    git clone --depth 1 "$TAILAUTH_REPO" "$CLONE_DIR"
    SCRIPT_DIR="$CLONE_DIR"
  else
    die "Run ./install.sh from the tailauth repository directory (or set TAILAUTH_REPO)."
  fi
fi

run_as_builder() {
  if [[ "$EUID" -eq 0 && -n "${SUDO_USER:-}" ]]; then
    sudo -u "$SUDO_USER" -H bash -lc "$*"
  else
    bash -lc "$*"
  fi
}

install_system_pkg() {
  local pkg="$1"
  if command -v pacman >/dev/null 2>&1; then
    sudo pacman -S --needed --noconfirm "$pkg"
  elif command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -qq && sudo apt-get install -y "$pkg"
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y "$pkg"
  else
    die "Please install '$pkg' manually using your distribution's package manager."
  fi
}

step "Checking prerequisites (tailscale, openssl, curl, Rust)"
command -v tailscale >/dev/null 2>&1 || die "tailscale CLI not found. Install Tailscale first: https://tailscale.com/download"
command -v systemctl >/dev/null 2>&1 || die "systemd is required."

if ! command -v openssl >/dev/null 2>&1; then
  warn "openssl not found; installing..."
  install_system_pkg openssl
fi
if ! command -v curl >/dev/null 2>&1; then
  warn "curl not found; installing..."
  install_system_pkg curl
fi

if ! run_as_builder 'command -v cargo >/dev/null 2>&1 && command -v rustc >/dev/null 2>&1'; then
  warn "Rust toolchain (cargo/rustc) not found for user $TARGET_USER."
  read -r -p "Install Rust via rustup now? [Y/n] " ans
  if [[ "${ans:-Y}" =~ ^[Yy]$ ]]; then
    run_as_builder 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y'
  else
    die "Rust toolchain is required to build tailauth."
  fi
fi

step "Verifying Tailscale connection and HTTPS certificate capability"
if ! sudo systemctl is-active --quiet tailscaled 2>/dev/null; then
  warn "tailscaled is not running; starting tailscaled..."
  sudo systemctl enable --now tailscaled
fi

parse_tailscale_json() {
  local json="$1"
  if command -v python3 >/dev/null 2>&1; then
    python3 -c '
import json, sys
d = json.load(sys.stdin)
state = d.get("BackendState", "")
dns = (d.get("Self") or {}).get("DNSName", "").rstrip(".")
certs = d.get("CertDomains") or []
print(state)
print(dns)
print(len(certs))
' <<< "$json"
  elif command -v jq >/dev/null 2>&1; then
    echo "$(jq -r '.BackendState // ""' <<< "$json")"
    echo "$(jq -r '.Self.DNSName // ""' <<< "$json" | sed 's/\.$//')"
    echo "$(jq -r '(.CertDomains // []) | length' <<< "$json")"
  else
    die "python3 or jq is required to parse 'tailscale status --json'."
  fi
}

while true; do
  TS_JSON="$(tailscale status --json 2>/dev/null || true)"
  if [[ -z "$TS_JSON" ]]; then
    die "Failed to query 'tailscale status --json'. Ensure tailscaled is running and logged in (sudo tailscale up)."
  fi

  mapfile -t TS_INFO < <(parse_tailscale_json "$TS_JSON")
  TS_STATE="${TS_INFO[0]:-}"
  TS_FQDN="${TS_INFO[1]:-}"
  TS_CERTS="${TS_INFO[2]:-0}"

  if [[ "$TS_STATE" != "Running" || -z "$TS_FQDN" ]]; then
    die "Tailscale is not connected (state=${TS_STATE:-unknown}). Run 'sudo tailscale up' and re-run ./install.sh."
  fi

  if [[ "$TS_CERTS" -gt 0 ]]; then
    break
  fi

  warn "Tailscale MagicDNS & HTTPS Certificates are not enabled on your tailnet yet."
  echo "  1. Open: https://login.tailscale.com/admin/dns"
  echo "  2. Enable 'MagicDNS' and 'HTTPS Certificates'"
  read -r -p "Press Enter once enabled to re-check (or Ctrl+C to abort)... " _
done
ok "Tailscale FQDN: $TS_FQDN"

step "Building tailauth release binary (as $TARGET_USER)"
run_as_builder "export PATH=\"\$HOME/.cargo/bin:\$PATH\"; cd \"$SCRIPT_DIR\" && cargo build --release"
BIN_PATH="$SCRIPT_DIR/target/release/tailauth"
[[ -x "$BIN_PATH" ]] || die "Build finished but $BIN_PATH was not found."
ok "Built $BIN_PATH"

step "Writing /etc/tailauth/config.json"
sudo mkdir -p /etc/tailauth
ALLOWED_JSON="[]"
if [[ ${#ALLOWED_TS_USERS[@]} -gt 0 ]]; then
  if command -v python3 >/dev/null 2>&1; then
    ALLOWED_JSON="$(python3 -c 'import json, sys; print(json.dumps(sys.argv[1:]))' "${ALLOWED_TS_USERS[@]}")"
  else
    ALLOWED_JSON="$(printf '"%s",' "${ALLOWED_TS_USERS[@]}" | sed 's/,$//; s/^/[/; s/$/]/')"
  fi
fi

TMP_CFG="$(mktemp)"
cat > "$TMP_CFG" <<EOF
{
  "fqdn": "$TS_FQDN",
  "https_port": $PORT,
  "listen_addr": "127.0.0.1:$PORT",
  "socket_path": "/run/tailauth/daemon.sock",
  "store_path": "/var/lib/tailauth/credentials.json",
  "timeout_secs": $TIMEOUT,
  "allowed_tailscale_users": $ALLOWED_JSON
}
EOF
sudo install -m 0644 -o root -g root "$TMP_CFG" /etc/tailauth/config.json
rm -f "$TMP_CFG"
ok "Saved /etc/tailauth/config.json"

step "Installing binary and systemd service"
sudo install -m 0755 -o root -g root "$BIN_PATH" /usr/local/bin/tailauth
sudo install -m 0644 -o root -g root "$SCRIPT_DIR/systemd/tailauth.service" /etc/systemd/system/tailauth.service
sudo systemctl daemon-reload
sudo systemctl enable --now tailauth.service
sudo systemctl restart tailauth.service
ok "tailauth.service is running"

step "Configuring Tailscale Serve HTTPS proxy on port $PORT"
if sudo tailscale serve --bg --yes --https="$PORT" "http://127.0.0.1:$PORT" 2>/dev/null; then
  :
else
  sudo tailscale serve --bg --https="$PORT" "http://127.0.0.1:$PORT"
fi
ok "Exposed https://${TS_FQDN}:${PORT} (Tailnet-only)"

step "Verifying local daemon health"
for _ in $(seq 1 15); do
  if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.3
done
curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null || die "Daemon health check failed on 127.0.0.1:${PORT}"
ok "Daemon health endpoint OK"

if [[ "$SKIP_ENROLL" -eq 0 ]]; then
  step "Enrolling phone fingerprint for user '$TARGET_USER'"
  echo "Make sure your phone is connected to the same Tailnet, then scan the QR code below."
  sudo /usr/local/bin/tailauth enroll --user "$TARGET_USER"
else
  warn "Skipping enrollment (--skip-enroll). Run 'sudo tailauth enroll --user $TARGET_USER' before relying on QR sudo."
fi

if [[ "$NO_PAM" -eq 0 ]]; then
  step "Configuring /etc/pam.d/sudo (QR phone fingerprint default, password fallback)"
  PAM_FILE="/etc/pam.d/sudo"
  [[ -f "$PAM_FILE" ]] || die "$PAM_FILE not found!"

  BACKUP_FILE="/etc/pam.d/sudo.tailauth-bak.$(date +%s)"
  sudo cp -a "$PAM_FILE" "$BACKUP_FILE"
  ok "Backed up $PAM_FILE -> $BACKUP_FILE"

  TMP_PAM="$(mktemp)"
  awk '
    BEGIN { skip=0 }
    /^# tailauth-begin$/ { skip=1; next }
    /^# tailauth-end$/ { skip=0; next }
    skip==0 { print }
  ' "$PAM_FILE" > "$TMP_PAM"

  FINAL_PAM="$(mktemp)"
  {
    echo "# tailauth-begin"
    echo "auth      sufficient pam_exec.so quiet quiet_log seteuid type=auth /usr/local/bin/tailauth pam"
    echo "# tailauth-end"
    cat "$TMP_PAM"
  } > "$FINAL_PAM"

  sudo install -m 0644 -o root -g root "$FINAL_PAM" "$PAM_FILE"
  rm -f "$TMP_PAM" "$FINAL_PAM"
  ok "Updated $PAM_FILE"
else
  warn "Skipping PAM modification (--no-pam)."
fi

echo ""
echo -e "${GREEN}${BOLD}TailAuth installation complete!${NC}"
echo "  • Test interactively: sudo tailauth test --user $TARGET_USER"
echo "  • Try sudo now:       sudo -k && sudo true"
echo "  • Press Enter at the QR prompt any time to fall back to your sudo password."
