use crate::config::Config;
use crate::protocol::{ClientRequest, ServerEvent};
use crate::qr::render_terminal_qr;
use std::env;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_signal(_sig: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

fn install_signal_handlers() {
    INTERRUPTED.store(false, Ordering::SeqCst);
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handle_signal as *const () as usize;
        // Intentionally omit SA_RESTART so poll() returns EINTR cleanly on SIGINT / SIGTERM.
        sa.sa_flags = 0;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
}

struct TtyGuard {
    fd: RawFd,
    orig: libc::termios,
    active: bool,
}

impl TtyGuard {
    fn enable_cbreak(fd: RawFd) -> Option<Self> {
        unsafe {
            if libc::isatty(fd) != 1 {
                return None;
            }
            let mut orig: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut orig) != 0 {
                return None;
            }
            let mut raw = orig;
            // Disable ISIG too so Ctrl+C arrives as 0x03 in our poll() loop even when
            // pam_exec.so has detached us from the controlling terminal via setsid().
            raw.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG);
            raw.c_cc[libc::VMIN] = 1;
            raw.c_cc[libc::VTIME] = 0;
            if libc::tcsetattr(fd, libc::TCSANOW, &raw) != 0 {
                return None;
            }
            Some(Self {
                fd,
                orig,
                active: true,
            })
        }
    }
}

impl Drop for TtyGuard {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSANOW, &self.orig);
            }
            self.active = false;
        }
    }
}

fn write_tty(tty: &mut std::fs::File, s: &str) {
    let _ = tty.write_all(s.as_bytes());
    let _ = tty.flush();
}

fn clear_lines(tty: &mut std::fs::File, lines: usize) {
    if lines > 0 {
        let seq = format!("\r\x1b[{lines}A\x1b[J");
        write_tty(tty, &seq);
    }
}

/// Validates and normalizes `PAM_TTY` to an explicit `/dev/...` terminal device path.
pub(crate) fn normalize_and_validate_pam_tty(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let rest = s.strip_prefix("/dev/").unwrap_or(s);

    if let Some(digits) = rest.strip_prefix("pts/") {
        if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
            return Some(format!("/dev/pts/{digits}"));
        }
        return None;
    }

    for prefix in ["ttyS", "ttyAMA", "ttyUSB", "tty"] {
        if let Some(digits) = rest.strip_prefix(prefix) {
            if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                return Some(format!("/dev/{prefix}{digits}"));
            }
            return None;
        }
    }

    None
}

fn open_validated_tty_path(path: &str) -> Option<std::fs::File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY | libc::O_NOFOLLOW)
        .open(path)
        .ok()?;

    let fd = file.as_raw_fd();
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut st) != 0 {
            return None;
        }
        if (st.st_mode & libc::S_IFMT) != libc::S_IFCHR {
            return None;
        }
        if libc::isatty(fd) != 1 {
            return None;
        }
    }
    Some(file)
}

fn open_interactive_tty() -> Option<std::fs::File> {
    if let Ok(file) = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY)
        .open("/dev/tty")
    {
        if unsafe { libc::isatty(file.as_raw_fd()) } == 1 {
            return Some(file);
        }
    }

    // pam_exec.so calls setsid() before execve(), detaching /dev/tty; fall back to PAM_TTY.
    let pam_tty = env::var("PAM_TTY").ok()?;
    let validated = normalize_and_validate_pam_tty(&pam_tty)?;
    open_validated_tty_path(&validated)
}

/// Executes the interactive PAM QR-code authentication helper.
/// Returns process exit code: `0` = PAM_SUCCESS, `1` = fallback to password, `130` = interrupted.
pub fn run_pam(config: &Config) -> i32 {
    run_interactive_auth(config, None, true)
}

/// Executes an interactive test authentication flow without requiring PAM environment vars.
pub fn run_test_auth(config: &Config, user_override: Option<String>) -> i32 {
    run_interactive_auth(config, user_override, false)
}

fn resolve_target_user(user_override: Option<String>) -> Option<String> {
    user_override
        .or_else(|| env::var("PAM_USER").ok())
        .or_else(|| env::var("SUDO_USER").ok())
        .or_else(|| env::var("USER").ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn run_interactive_auth(config: &Config, user_override: Option<String>, silent_fast_fail: bool) -> i32 {
    let Some(user) = resolve_target_user(user_override) else {
        if !silent_fast_fail {
            eprintln!("tailauth: unable to determine target username");
        }
        return 1;
    };

    let Some(mut tty) = open_interactive_tty() else {
        if !silent_fast_fail {
            eprintln!("tailauth: no interactive terminal (/dev/tty or PAM_TTY) available");
        }
        return 1;
    };

    let Ok(mut stream) = UnixStream::connect(&config.socket_path) else {
        if !silent_fast_fail {
            eprintln!(
                "tailauth: cannot connect to daemon socket {}",
                config.socket_path
            );
        }
        return 1;
    };

    let _ = stream.set_read_timeout(Some(Duration::from_millis(1500)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(1500)));

    let pam_service = env::var("PAM_SERVICE").ok();
    let is_pam = silent_fast_fail && pam_service.is_some();

    let req = ClientRequest::StartAuth {
        user: user.clone(),
        ruser: env::var("PAM_RUSER").ok(),
        service: pam_service,
    };
    let Ok(mut req_line) = serde_json::to_string(&req) else {
        return 1;
    };
    req_line.push('\n');
    if stream.write_all(req_line.as_bytes()).is_err() || stream.flush().is_err() {
        return 1;
    }

    let read_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return 1,
    };
    let mut reader = BufReader::new(read_stream);
    let mut initial_line = String::new();
    if reader.read_line(&mut initial_line).is_err() || initial_line.is_empty() {
        return 1;
    }

    let initial_event: ServerEvent = match serde_json::from_str(initial_line.trim()) {
        Ok(ev) => ev,
        Err(_) => return 1,
    };

    let (url, timeout_secs) = match initial_event {
        ServerEvent::Pending {
            url, timeout_secs, ..
        } => (url, timeout_secs),
        ServerEvent::NoCredentials => {
            if !silent_fast_fail {
                eprintln!(
                    "tailauth: user '{user}' has no enrolled phone credentials. Run: sudo tailauth enroll --user {user}"
                );
            }
            return 1;
        }
        ServerEvent::Error { message } => {
            if !silent_fast_fail {
                eprintln!("tailauth: {message}");
            }
            return 1;
        }
        _ => return 1,
    };

    let Ok(rendered) = render_terminal_qr(&url) else {
        return 1;
    };

    install_signal_handlers();

    let header = format!(
        "\r\n\x1b[1;34mTailAuth\x1b[0m — scan with your phone to approve \x1b[1m{user}\x1b[0m ({timeout_secs}s timeout):\r\n"
    );
    let footer = format!(
        "\x1b[2mLink: {url}\r\nPress Enter (or 'p' / Esc) for sudo password...\x1b[0m\r\n"
    );
    // Header has 2 newlines (1 leading + 1 trailing), footer has 2 newlines.
    let total_lines = 2 + rendered.line_count + 2;

    write_tty(&mut tty, &header);
    write_tty(&mut tty, &rendered.text);
    write_tty(&mut tty, &footer);

    let tty_guard = TtyGuard::enable_cbreak(tty.as_raw_fd());
    let _ = stream.set_read_timeout(None);

    let tty_fd = tty.as_raw_fd();
    let sock_fd = stream.as_raw_fd();
    let mut fds = [
        libc::pollfd {
            fd: tty_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: sock_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    loop {
        if INTERRUPTED.load(Ordering::SeqCst) {
            drop(reader);
            drop(stream);
            clear_lines(&mut tty, total_lines);
            write_tty(&mut tty, "TailAuth: Cancelled.\n");
            drop(tty_guard);
            return 130;
        }

        fds[0].revents = 0;
        fds[1].revents = 0;
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, 500) };

        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                if INTERRUPTED.load(Ordering::SeqCst) {
                    drop(reader);
                    drop(stream);
                    clear_lines(&mut tty, total_lines);
                    write_tty(&mut tty, "TailAuth: Cancelled.\n");
                    drop(tty_guard);
                    return 130;
                }
                continue;
            }
            clear_lines(&mut tty, total_lines);
            drop(tty_guard);
            return 1;
        }

        if (fds[0].revents & libc::POLLIN) != 0 {
            let mut buf = [0u8; 32];
            let n = unsafe { libc::read(tty_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n > 0 {
                let slice = &buf[..n as usize];
                if slice.contains(&0x03) {
                    drop(reader);
                    drop(stream);
                    clear_lines(&mut tty, total_lines);
                    write_tty(&mut tty, "TailAuth: Cancelled.\n");
                    drop(tty_guard);
                    if is_pam {
                        unsafe {
                            libc::kill(libc::getppid(), libc::SIGINT);
                        }
                    }
                    return 130;
                }
                if slice
                    .iter()
                    .any(|&b| matches!(b, b'\r' | b'\n' | 0x1b | b'p' | b'P' | b'q' | b'Q'))
                {
                    drop(reader);
                    drop(stream);
                    clear_lines(&mut tty, total_lines);
                    write_tty(&mut tty, "TailAuth: Falling back to password.\n");
                    drop(tty_guard);
                    return 1;
                }
            }
        }

        if (fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0 {
            let mut resp_line = String::new();
            match reader.read_line(&mut resp_line) {
                Ok(0) | Err(_) => {
                    clear_lines(&mut tty, total_lines);
                    write_tty(&mut tty, "TailAuth: Connection closed — falling back to password.\n");
                    drop(tty_guard);
                    return 1;
                }
                Ok(_) => match serde_json::from_str::<ServerEvent>(resp_line.trim()) {
                    Ok(ServerEvent::Approved { label, .. }) => {
                        clear_lines(&mut tty, total_lines);
                        write_tty(
                            &mut tty,
                            &format!("\x1b[32m✔ TailAuth: Approved via {label}\x1b[0m\n"),
                        );
                        drop(tty_guard);
                        return 0;
                    }
                    Ok(ServerEvent::Denied) => {
                        clear_lines(&mut tty, total_lines);
                        write_tty(
                            &mut tty,
                            "\x1b[31m✖ TailAuth: Denied on phone — falling back to password.\x1b[0m\n",
                        );
                        drop(tty_guard);
                        return 1;
                    }
                    Ok(ServerEvent::Timeout) => {
                        clear_lines(&mut tty, total_lines);
                        write_tty(
                            &mut tty,
                            "\x1b[33m⏱ TailAuth: Timed out — falling back to password.\x1b[0m\n",
                        );
                        drop(tty_guard);
                        return 1;
                    }
                    Ok(ServerEvent::Error { message }) => {
                        clear_lines(&mut tty, total_lines);
                        write_tty(&mut tty, &format!("TailAuth: {message}\n"));
                        drop(tty_guard);
                        return 1;
                    }
                    _ => {
                        clear_lines(&mut tty, total_lines);
                        drop(tty_guard);
                        return 1;
                    }
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn pam_tty_validation_accepts_known_devices_and_rejects_traversal_or_other_paths() {
        assert_eq!(
            normalize_and_validate_pam_tty("/dev/pts/3"),
            Some("/dev/pts/3".to_string())
        );
        assert_eq!(
            normalize_and_validate_pam_tty("pts/12"),
            Some("/dev/pts/12".to_string())
        );
        assert_eq!(
            normalize_and_validate_pam_tty(" /dev/tty1 \n"),
            Some("/dev/tty1".to_string())
        );
        assert_eq!(
            normalize_and_validate_pam_tty("tty2"),
            Some("/dev/tty2".to_string())
        );
        assert_eq!(
            normalize_and_validate_pam_tty("/dev/ttyS0"),
            Some("/dev/ttyS0".to_string())
        );
        assert_eq!(
            normalize_and_validate_pam_tty("ttyAMA0"),
            Some("/dev/ttyAMA0".to_string())
        );
        assert_eq!(
            normalize_and_validate_pam_tty("ttyUSB1"),
            Some("/dev/ttyUSB1".to_string())
        );

        for invalid in [
            "",
            "   ",
            "ssh",
            "unknown",
            "/dev/null",
            "/etc/passwd",
            "/dev/pts/../tty1",
            "/dev/pts/",
            "pts/1a",
            "tty",
            "/dev/ttyX",
            "../pts/0",
        ] {
            assert_eq!(
                normalize_and_validate_pam_tty(invalid),
                None,
                "expected '{invalid}' to be rejected"
            );
        }
    }

    #[test]
    fn open_validated_tty_path_handles_pty_and_termios_guard() {
        unsafe {
            let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            if master < 0 {
                // PTY allocation may be unavailable in restricted container environments.
                return;
            }
            assert_eq!(libc::grantpt(master), 0);
            assert_eq!(libc::unlockpt(master), 0);
            let name_ptr = libc::ptsname(master);
            assert!(!name_ptr.is_null());
            let slave_path = CStr::from_ptr(name_ptr).to_str().unwrap().to_string();

            let normalized = normalize_and_validate_pam_tty(&slave_path).unwrap();
            assert_eq!(normalized, slave_path);

            let slave_file = open_validated_tty_path(&normalized).expect("failed to open slave PTY");
            let slave_fd = slave_file.as_raw_fd();

            let mut orig_before: libc::termios = std::mem::zeroed();
            assert_eq!(libc::tcgetattr(slave_fd, &mut orig_before), 0);

            {
                let guard = TtyGuard::enable_cbreak(slave_fd).expect("TtyGuard failed");
                let mut active_mode: libc::termios = std::mem::zeroed();
                assert_eq!(libc::tcgetattr(slave_fd, &mut active_mode), 0);
                assert_eq!(active_mode.c_lflag & (libc::ICANON | libc::ECHO | libc::ISIG), 0);
                drop(guard);
            }

            let mut restored: libc::termios = std::mem::zeroed();
            assert_eq!(libc::tcgetattr(slave_fd, &mut restored), 0);
            assert_eq!(restored.c_lflag, orig_before.c_lflag);

            drop(slave_file);
            libc::close(master);

            assert!(open_validated_tty_path("/dev/null").is_none());
        }
    }
}
