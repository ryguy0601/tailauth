# 🔐 TailAuth

Cross-platform **Tailnet phone-fingerprint authentication** for **Linux `sudo`** and **Windows elevation**, written in **Rust** with **WebAuthn (ES256)** and **Tailscale Serve HTTPS** so computers without built-in fingerprint sensors can approve elevated commands from a phone—with instant fallback to standard passwords or Windows UAC.

<div align="center">

![Rust](https://img.shields.io/badge/Rust-1.80%2B-000000?style=for-the-badge&logo=rust&logoColor=white)
![Linux PAM](https://img.shields.io/badge/Linux-PAM%20%2B%20systemd-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Windows CNG](https://img.shields.io/badge/Windows-Service%20%2B%20CNG-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![WebAuthn](https://img.shields.io/badge/WebAuthn-ES256%20Biometrics-3B82F6?style=for-the-badge&logo=webauthn&logoColor=white)
![Tailscale](https://img.shields.io/badge/Tailscale-Serve%20HTTPS-242424?style=for-the-badge&logo=tailscale&logoColor=white)

</div>

---

## 🌟 Key Features
- **Zero-App Phone Biometrics:** Renders a compact, high-contrast UTF-8 half-block **QR code** directly in the terminal and authenticates via **WebAuthn** (`ES256`, `UP + UV` required) in Safari/Chrome over **Tailscale Serve** trusted HTTPS.
- **Linux PAM Integration:** Runs as a lightweight synchronous `pam_exec.so` helper (`tailauth pam`) backed by a root **systemd** daemon over a `0600` Unix domain socket, falling back immediately to `pam_fprintd` or password prompts on **Enter**, **Esc**, **`p`**, **`q`**, or non-interactive sessions.
- **Native Windows Elevation & CNG Crypto:** Runs as a **Windows Service (`LOCAL SYSTEM`)** over a SDDL-hardened Named Pipe (`\\.\pipe\tailauth`), verifies kernel process tokens (`GetNamedPipeClientProcessId`, `TokenLinkedToken`, `WinBuiltinAdministratorsSid`), validates ECDSA P-256 signatures natively via **Windows CNG (`bcrypt.dll`)**, and falls back cleanly to **Windows 11 `sudo.exe` / UAC**.
- **Strict Security Defaults:** Single-use 256-bit challenge tokens, immediate challenge invalidation on terminal disconnect/Ctrl+C, optional `Tailscale-User-Login` allowlist filtering, and monotonic signature counter checks.

---

## 🏗 Architecture & Tech Stack

### Linux (PAM + systemd + Unix Socket)
```text
sudo command
   │
   ▼
PAM (/etc/pam.d/sudo)
   └─▶ tailauth pam ──(Unix socket /run/tailauth/daemon.sock)──▶ tailauth daemon
          │                                                            ▲
          ▼                                                            │
   Terminal QR Code                                      Tailscale Serve HTTPS
   https://<host>.<tailnet>.ts.net:8443/auth/<token> ────▶ Phone Browser (WebAuthn)
                                                           Fingerprint / Face ID
```

### Windows (Windows Service + Named Pipe + CNG `bcrypt.dll`)
```text
sudo <cmd>  (or tsudo <cmd>)
   │
   ▼
tailauth.exe sudo <cmd> ──(Named Pipe \\.\pipe\tailauth)──▶ TailAuth Service (SYSTEM)
   │                                                              ▲
   ▼                                                              │
Terminal QR Code                                      Tailscale Serve HTTPS
https://<host>.<tailnet>.ts.net:8443/auth/<token> ────▶ Phone Browser (WebAuthn)
```

- **Daemon & HTTP Server:** **Rust**, **Tokio**, **Axum**, **serde / serde_json**, embedded zero-CDN mobile WebAuthn HTML/JS
- **Cryptography & WebAuthn:** Pure-Rust **FIPS 180-4 SHA-256** & **CBOR/COSE P-256** decoder; **OpenSSL** (Linux) and **Windows CNG `bcrypt.dll`** (Windows) for ES256 verification
- **System Integration:** **Linux PAM** (`pam_exec.so`, `termios`, `poll`), **Windows Win32 APIs** (`windows-sys`, `CreateProcessAsUserW`, `StartServiceCtrlDispatcherW`)
- **Networking:** **Tailscale MagicDNS** + **Tailscale Serve** (Tailnet-only TLS termination)

---

## 🚀 Setup & Installation

### Prerequisites
1. **Tailscale** installed and signed in on both the target computer and your phone.
2. **MagicDNS** and **HTTPS Certificates** enabled in the [Tailscale DNS Admin Console](https://login.tailscale.com/admin/dns).
3. **Linux**: `openssl` installed (default on Arch/Omarchy, Ubuntu, Debian, Fedora). **Windows**: no extra crypto dependencies required.

### Linux One-Line Install (Arch / Omarchy / Ubuntu / Debian / Fedora)
```bash
git clone https://github.com/ryguy0601/tailauth.git ~/tailauth && cd ~/tailauth && ./install.sh
```

Installer flags:
- `--port <PORT>` (default `8443`)
- `--timeout <SECS>` (default `60`)
- `--allow-ts-user <LOGIN>` (repeatable; restrict to specific `Tailscale-User-Login` emails)
- `--skip-enroll`
- `--no-pam`

### Windows One-Line Install (Run in an Administrator PowerShell)
```powershell
$d="$env:USERPROFILE\tailauth"; Remove-Item -Recurse -Force $d -ErrorAction SilentlyContinue; git clone https://github.com/ryguy0601/tailauth.git $d; Set-ExecutionPolicy -Scope Process Bypass -Force; Set-Location $d; .\install.ps1
```

Installer flags:
- `-Port <PORT>` (default `8443`)
- `-Timeout <SECS>` (default `60`)
- `-AllowTsUser <LOGIN[]>`
- `-SkipEnroll`
- `-NoProfile` (skip adding the `sudo` function to PowerShell profiles; `tsudo.cmd` is still installed)

---

## 💻 Daily Usage & Management

- **Linux:** `sudo <command>` → scan QR → touch phone fingerprint (press **Enter** for password).
- **Windows (PowerShell):** `sudo <command>` → scan QR → touch phone fingerprint (press **Enter** for UAC / PIN / password).
- **Windows (CMD):** `tsudo <command>`
- **Enroll another phone:** `sudo tailauth enroll --user $USER` (Linux) or `tailauth enroll --user $env:USERNAME` (Windows Admin)
- **List / Revoke / Test / Status:**
  - `tailauth list`
  - `tailauth revoke <ID_PREFIX>`
  - `tailauth test`
  - `tailauth status`
- **Uninstall:**
  - Linux: `./uninstall.sh` (`--purge` deletes `/etc/tailauth` and `/var/lib/tailauth`)
  - Windows (Admin PowerShell): `.\uninstall.ps1` (`-Purge` deletes `C:\ProgramData\TailAuth`)
