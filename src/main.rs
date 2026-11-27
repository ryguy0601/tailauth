mod config;
mod crypto;
mod daemon;
#[cfg(unix)]
mod pam;
mod protocol;
mod qr;
mod store;
mod webauthn;
#[cfg(windows)]
mod win;

use crate::config::{Config, DEFAULT_CONFIG_PATH};
use crate::protocol::{ClientRequest, ServerEvent};
#[cfg(unix)]
use crate::qr::render_terminal_qr;
use std::env;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io::{BufRead, BufReader, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process;

fn print_usage() {
    println!(
        "\
tailauth {} — Tailnet phone-fingerprint authentication for Linux sudo & Windows elevation

USAGE:
  tailauth [--config <PATH>] <COMMAND>

COMMANDS:
  daemon                    Run the TailAuth HTTP + IPC daemon in the foreground
  service                   Run as a native Windows Service (Windows SCM entrypoint)
  pam                       Linux PAM helper invoked by pam_exec.so (reads terminal)
  sudo <CMD> [ARGS...]      Windows elevated runner with QR prompt + UAC fallback
  enroll [--user <USER>]    Display a QR code to enroll a phone fingerprint
  list [--user <USER>]      List enrolled phone credentials
  revoke <ID_PREFIX> [--user <USER>]
                            Revoke an enrolled credential by ID prefix
  status                    Show daemon/service, credential, and integration status
  test [--user <USER>]      Run an interactive QR approval test
  help                      Show this help message

OPTIONS:
  --config <PATH>           Path to config JSON (default: {DEFAULT_CONFIG_PATH})
  -h, --help                Show help
  -V, --version             Show version",
        env!("CARGO_PKG_VERSION")
    );
}

fn default_target_user() -> Result<String, String> {
    #[cfg(unix)]
    {
        for key in ["SUDO_USER", "PAM_USER", "USER"] {
            if let Ok(val) = env::var(key) {
                let trimmed = val.trim();
                if !trimmed.is_empty() && (key != "USER" || trimmed != "root") {
                    return Ok(trimmed.to_string());
                }
            }
        }
        env::var("USER")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "could not determine target user; pass --user <USER>".to_string())
    }
    #[cfg(windows)]
    {
        env::var("USERNAME")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "could not determine Windows username; pass --user <USER>".to_string())
    }
}

fn send_ipc_request(socket_path: &str, req: &ClientRequest) -> Result<Vec<ServerEvent>, String> {
    #[cfg(unix)]
    {
        let mut stream = UnixStream::connect(socket_path).map_err(|e| {
            format!(
                "failed to connect to tailauth daemon at {socket_path}: {e} (is tailauth.service running?)"
            )
        })?;
        let mut line = serde_json::to_string(req).map_err(|e| e.to_string())?;
        line.push('\n');
        stream
            .write_all(line.as_bytes())
            .and_then(|_| stream.flush())
            .map_err(|e| format!("failed to write request: {e}"))?;

        let mut reader = BufReader::new(stream);
        let mut events = Vec::new();
        let mut resp = String::new();
        while reader
            .read_line(&mut resp)
            .map_err(|e| format!("failed to read daemon response: {e}"))?
            > 0
        {
            let ev: ServerEvent = serde_json::from_str(resp.trim())
                .map_err(|e| format!("invalid daemon response: {e}"))?;
            events.push(ev);
            resp.clear();
        }
        Ok(events)
    }

    #[cfg(windows)]
    {
        win::send_pipe_request(socket_path, req)
    }
}

#[cfg(unix)]
fn run_enroll(config: &Config, user: String) -> i32 {
    let Ok(mut stream) = UnixStream::connect(&config.socket_path) else {
        eprintln!(
            "tailauth: failed to connect to daemon at {} (try: sudo systemctl start tailauth)",
            config.socket_path
        );
        return 1;
    };

    let req = ClientRequest::StartEnroll { user: user.clone() };
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    if let Err(e) = stream.write_all(line.as_bytes()).and_then(|_| stream.flush()) {
        eprintln!("tailauth: failed to send enroll request: {e}");
        return 1;
    }

    let mut reader = BufReader::new(stream);
    let mut resp = String::new();
    if reader.read_line(&mut resp).is_err() || resp.is_empty() {
        eprintln!("tailauth: no response from daemon");
        return 1;
    }

    let pending: ServerEvent = match serde_json::from_str(resp.trim()) {
        Ok(ev) => ev,
        Err(e) => {
            eprintln!("tailauth: invalid daemon response: {e}");
            return 1;
        }
    };

    let (url, timeout_secs) = match pending {
        ServerEvent::Pending {
            url, timeout_secs, ..
        } => (url, timeout_secs),
        ServerEvent::Error { message } => {
            eprintln!("tailauth: {message}");
            return 1;
        }
        other => {
            eprintln!("tailauth: unexpected response: {other:?}");
            return 1;
        }
    };

    let rendered = match render_terminal_qr(&url) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("tailauth: failed to render QR code: {e}");
            return 1;
        }
    };

    println!();
    println!(
        "\x1b[1;34mTailAuth Enrollment\x1b[0m — scan with your phone to enroll \x1b[1m{user}\x1b[0m ({timeout_secs}s timeout):"
    );
    print!("{}", rendered.text);
    println!("\x1b[2mOpen on phone (Tailnet required): {url}\x1b[0m");
    println!("Waiting for phone passkey registration (Ctrl+C to cancel)...");

    resp.clear();
    if reader.read_line(&mut resp).is_err() || resp.is_empty() {
        eprintln!("tailauth: daemon closed connection before enrollment completed");
        return 1;
    }

    match serde_json::from_str::<ServerEvent>(resp.trim()) {
        Ok(ServerEvent::Enrolled {
            id,
            label,
            tailscale_user,
        }) => {
            let short_id: String = id.chars().take(12).collect();
            let who = tailscale_user
                .map(|u| format!(" ({u})"))
                .unwrap_or_default();
            println!(
                "\x1b[32m✔ Enrolled '{label}'{who} [id: {short_id}...] for user '{user}'\x1b[0m"
            );
            0
        }
        Ok(ServerEvent::Timeout) => {
            eprintln!("tailauth: enrollment timed out");
            1
        }
        Ok(ServerEvent::Error { message }) => {
            eprintln!("tailauth: {message}");
            1
        }
        _ => {
            eprintln!("tailauth: unexpected enrollment outcome");
            1
        }
    }
}

#[cfg(windows)]
fn run_enroll(config: &Config, user: String) -> i32 {
    win::run_windows_enroll(config, user)
}

fn run_list(config: &Config, user: Option<String>) -> i32 {
    match send_ipc_request(&config.socket_path, &ClientRequest::ListCredentials { user }) {
        Ok(events) => {
            for ev in events {
                match ev {
                    ServerEvent::Credentials { credentials } => {
                        if credentials.is_empty() {
                            println!("No enrolled phone credentials found.");
                            return 0;
                        }
                        println!(
                            "{:<14} {:<16} {:<18} {:<24} {:<8}",
                            "USER", "ID_PREFIX", "DEVICE", "TAILSCALE_USER", "USES"
                        );
                        for c in credentials {
                            let prefix: String = c.id.chars().take(12).collect();
                            let ts = c.tailscale_user.unwrap_or_else(|| "-".to_string());
                            println!(
                                "{:<14} {:<16} {:<18} {:<24} {:<8}",
                                c.user, prefix, c.label, ts, c.sign_count
                            );
                        }
                        return 0;
                    }
                    ServerEvent::Error { message } => {
                        eprintln!("tailauth: {message}");
                        return 1;
                    }
                    _ => {}
                }
            }
            1
        }
        Err(e) => {
            eprintln!("tailauth: {e}");
            1
        }
    }
}

fn run_revoke(config: &Config, user: Option<String>, id_prefix: String) -> i32 {
    match send_ipc_request(
        &config.socket_path,
        &ClientRequest::RevokeCredential { user, id_prefix },
    ) {
        Ok(events) => {
            for ev in events {
                match ev {
                    ServerEvent::Revoked { id } => {
                        let short_id: String = id.chars().take(12).collect();
                        println!("Revoked credential {short_id}...");
                        return 0;
                    }
                    ServerEvent::Error { message } => {
                        eprintln!("tailauth: {message}");
                        return 1;
                    }
                    _ => {}
                }
            }
            1
        }
        Err(e) => {
            eprintln!("tailauth: {e}");
            1
        }
    }
}

fn run_status(config_path: &Path) -> i32 {
    println!("Config path: {}", config_path.display());
    let cfg = match Config::load(config_path) {
        Ok(c) => {
            println!("FQDN:        {}", c.rp_id());
            println!("Origin:      {}", c.expected_origin());
            println!("Listen addr: {}", c.listen_addr);
            println!("IPC path:    {}", c.socket_path);
            println!("Store path:  {}", c.store_path);
            println!("Timeout:     {}s", c.timeout_secs);
            c
        }
        Err(e) => {
            println!("Config:      NOT READY ({e})");
            return 1;
        }
    };

    match send_ipc_request(&cfg.socket_path, &ClientRequest::Status) {
        Ok(events) => {
            for ev in events {
                if let ServerEvent::StatusInfo {
                    enrolled_users,
                    total_credentials,
                    ..
                } = ev
                {
                    println!("Daemon:      CONNECTED");
                    println!(
                        "Enrolled:    {total_credentials} credential(s) across {enrolled_users} user(s)"
                    );
                }
            }
        }
        Err(e) => {
            println!("Daemon:      UNAVAILABLE ({e})");
        }
    }

    #[cfg(unix)]
    {
        let pam_configured = fs::read_to_string("/etc/pam.d/sudo")
            .map(|s| s.contains("tailauth"))
            .unwrap_or(false);
        println!(
            "PAM sudo:    {}",
            if pam_configured {
                "ENABLED (/etc/pam.d/sudo)"
            } else {
                "NOT ENABLED"
            }
        );
    }
    0
}

fn parse_user_flag(args: &[String]) -> Result<Option<String>, String> {
    let mut i = 0;
    let mut user = None;
    while i < args.len() {
        match args[i].as_str() {
            "--user" | "-u" => {
                let val = args
                    .get(i + 1)
                    .ok_or_else(|| "--user requires a username".to_string())?;
                user = Some(val.clone());
                i += 2;
            }
            other => return Err(format!("unexpected argument: {other}")),
        }
    }
    Ok(user)
}

fn main() {
    let mut raw_args: Vec<String> = env::args().skip(1).collect();
    let mut config_path = PathBuf::from(DEFAULT_CONFIG_PATH);

    if raw_args.len() >= 2 && raw_args[0] == "--config" {
        config_path = PathBuf::from(&raw_args[1]);
        raw_args.drain(0..2);
    }

    let Some(cmd) = raw_args.first().map(String::as_str) else {
        print_usage();
        process::exit(0);
    };

    let rest = &raw_args[1..];
    match cmd {
        "-h" | "--help" | "help" => {
            print_usage();
            process::exit(0);
        }
        "-V" | "--version" | "version" => {
            println!("tailauth {}", env!("CARGO_PKG_VERSION"));
            process::exit(0);
        }
        "status" => {
            process::exit(run_status(&config_path));
        }
        "pam" => {
            #[cfg(unix)]
            {
                let Ok(cfg) = Config::load(&config_path) else {
                    process::exit(1);
                };
                process::exit(pam::run_pam(&cfg));
            }
            #[cfg(not(unix))]
            {
                eprintln!("tailauth: 'pam' subcommand is only supported on Linux");
                process::exit(1);
            }
        }
        "service" => {
            #[cfg(windows)]
            {
                let cfg = match Config::load(&config_path) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("tailauth: {e}");
                        process::exit(1);
                    }
                };
                if let Err(e) = win::run_windows_service(cfg) {
                    eprintln!("tailauth service failed: {e}");
                    process::exit(1);
                }
            }
            #[cfg(not(windows))]
            {
                eprintln!("tailauth: 'service' subcommand is only supported on Windows");
                process::exit(1);
            }
        }
        "sudo" => {
            #[cfg(windows)]
            {
                let cfg = Config::load(&config_path).unwrap_or_default();
                process::exit(win::run_windows_sudo(&cfg, rest.to_vec()));
            }
            #[cfg(not(windows))]
            {
                eprintln!("tailauth: on Linux, use standard 'sudo' via PAM (not 'tailauth sudo')");
                process::exit(1);
            }
        }
        "daemon" => {
            let cfg = match Config::load(&config_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("tailauth: {e}");
                    process::exit(1);
                }
            };
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap_or_else(|e| {
                    eprintln!("tailauth: failed to start Tokio runtime: {e}");
                    process::exit(1);
                });
            if let Err(e) = rt.block_on(daemon::run_daemon(cfg)) {
                eprintln!("tailauth daemon failed: {e}");
                process::exit(1);
            }
        }
        "enroll" => {
            let cfg = Config::load(&config_path).unwrap_or_else(|e| {
                eprintln!("tailauth: {e}");
                process::exit(1);
            });
            let user_flag = parse_user_flag(rest).unwrap_or_else(|e| {
                eprintln!("tailauth: {e}");
                process::exit(2);
            });
            let user = user_flag
                .or_else(|| default_target_user().ok())
                .unwrap_or_else(|| {
                    eprintln!("tailauth: could not determine user; pass --user <USER>");
                    process::exit(2);
                });
            process::exit(run_enroll(&cfg, user));
        }
        "test" => {
            let cfg = Config::load(&config_path).unwrap_or_else(|e| {
                eprintln!("tailauth: {e}");
                process::exit(1);
            });
            let user_flag = parse_user_flag(rest).unwrap_or_else(|e| {
                eprintln!("tailauth: {e}");
                process::exit(2);
            });
            #[cfg(unix)]
            {
                let user = user_flag.or_else(|| default_target_user().ok());
                process::exit(pam::run_test_auth(&cfg, user));
            }
            #[cfg(windows)]
            {
                let user = user_flag
                    .or_else(|| default_target_user().ok())
                    .unwrap_or_else(|| {
                        eprintln!("tailauth: could not determine user; pass --user <USER>");
                        process::exit(2);
                    });
                process::exit(win::run_windows_test(&cfg, user));
            }
        }
        "list" => {
            let cfg = Config::load(&config_path).unwrap_or_else(|e| {
                eprintln!("tailauth: {e}");
                process::exit(1);
            });
            let user = parse_user_flag(rest).unwrap_or_else(|e| {
                eprintln!("tailauth: {e}");
                process::exit(2);
            });
            process::exit(run_list(&cfg, user));
        }
        "revoke" => {
            let cfg = Config::load(&config_path).unwrap_or_else(|e| {
                eprintln!("tailauth: {e}");
                process::exit(1);
            });
            let mut id_prefix: Option<String> = None;
            let mut user: Option<String> = None;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--user" | "-u" => {
                        let Some(val) = rest.get(i + 1) else {
                            eprintln!("tailauth: --user requires a username");
                            process::exit(2);
                        };
                        user = Some(val.clone());
                        i += 2;
                    }
                    arg if id_prefix.is_none() && !arg.starts_with('-') => {
                        id_prefix = Some(arg.to_string());
                        i += 1;
                    }
                    other => {
                        eprintln!("tailauth: unexpected argument: {other}");
                        process::exit(2);
                    }
                }
            }
            let Some(prefix) = id_prefix else {
                eprintln!("tailauth: usage: tailauth revoke <ID_PREFIX> [--user <USER>]");
                process::exit(2);
            };
            process::exit(run_revoke(&cfg, user, prefix));
        }
        other => {
            eprintln!("tailauth: unknown subcommand '{other}'");
            print_usage();
            process::exit(2);
        }
    }
}
