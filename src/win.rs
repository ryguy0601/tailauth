use crate::config::Config;
use crate::crypto::b64url_decode;
use crate::protocol::{build_windows_command_line, quote_windows_arg, ClientRequest, ServerEvent};
use crate::qr::render_terminal_qr;
use std::env;
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::FromRawHandle;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::{mpsc as tokio_mpsc, oneshot};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER,
    ERROR_PIPE_BUSY, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
    WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, DuplicateTokenEx, GetTokenInformation,
    LookupAccountSidW, SecurityImpersonation, TokenElevation, TokenImpersonation, TokenLinkedToken,
    TokenPrimary, TokenUser, WinBuiltinAdministratorsSid, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, TOKEN_ALL_ACCESS, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
    TOKEN_ELEVATION, TOKEN_IMPERSONATE, TOKEN_LINKED_TOKEN, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, ReadConsoleInputW, SetConsoleMode,
    ENABLE_VIRTUAL_TERMINAL_PROCESSING, INPUT_RECORD, KEY_EVENT, STD_INPUT_HANDLE,
    STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::Pipes::{CreatePipe, GetNamedPipeClientProcessId, WaitNamedPipeW};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
    SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, GetExitCodeProcess, OpenProcess, OpenProcessToken, WaitForSingleObject,
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, INFINITE, PROCESS_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
};

#[derive(Debug)]
pub struct OwnedHandle(pub HANDLE);

unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

pub struct PipeCallerInfo {
    pub username: String,
    pub is_admin: bool,
    pub elevated_token: Option<OwnedHandle>,
}

fn to_wide_null(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn token_is_admin_member(token: HANDLE) -> bool {
    unsafe {
        let mut imp_token: HANDLE = std::ptr::null_mut();
        if DuplicateTokenEx(
            token,
            TOKEN_QUERY | TOKEN_IMPERSONATE,
            std::ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &mut imp_token,
        ) == 0
        {
            return false;
        }
        let _imp_guard = OwnedHandle(imp_token);

        let mut sid_buf = [0u8; 64];
        let mut sid_len = sid_buf.len() as u32;
        if CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            std::ptr::null_mut(),
            sid_buf.as_mut_ptr() as PSID,
            &mut sid_len,
        ) == 0
        {
            return false;
        }

        let mut is_member: i32 = 0;
        if CheckTokenMembership(imp_token, sid_buf.as_mut_ptr() as PSID, &mut is_member) == 0 {
            return false;
        }
        is_member != 0
    }
}

fn duplicate_primary_token(token: HANDLE) -> Result<OwnedHandle, String> {
    unsafe {
        let mut primary: HANDLE = std::ptr::null_mut();
        if DuplicateTokenEx(
            token,
            TOKEN_ALL_ACCESS,
            std::ptr::null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut primary,
        ) == 0
        {
            return Err(format!(
                "DuplicateTokenEx(TokenPrimary) failed: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(OwnedHandle(primary))
    }
}

fn lookup_token_username(token: HANDLE) -> Result<String, String> {
    unsafe {
        let mut needed: u32 = 0;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
        if needed == 0 {
            return Err(format!(
                "GetTokenInformation(TokenUser) size query failed: {}",
                io::Error::last_os_error()
            ));
        }
        let mut buf = vec![0u8; needed as usize];
        if GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr() as *mut c_void,
            needed,
            &mut needed,
        ) == 0
        {
            return Err(format!(
                "GetTokenInformation(TokenUser) failed: {}",
                io::Error::last_os_error()
            ));
        }

        let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut name_len: u32 = 0;
        let mut domain_len: u32 = 0;
        let mut sid_use: i32 = 0;
        LookupAccountSidW(
            std::ptr::null(),
            token_user.User.Sid,
            std::ptr::null_mut(),
            &mut name_len,
            std::ptr::null_mut(),
            &mut domain_len,
            &mut sid_use,
        );
        if GetLastError() != ERROR_INSUFFICIENT_BUFFER || name_len == 0 {
            return Err(format!(
                "LookupAccountSidW size failed: {}",
                io::Error::last_os_error()
            ));
        }

        let mut name = vec![0u16; name_len as usize];
        let mut domain = vec![0u16; domain_len.max(1) as usize];
        if LookupAccountSidW(
            std::ptr::null(),
            token_user.User.Sid,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut sid_use,
        ) == 0
        {
            return Err(format!(
                "LookupAccountSidW failed: {}",
                io::Error::last_os_error()
            ));
        }

        let os_name = std::ffi::OsString::from_wide(&name[..name_len as usize]);
        Ok(os_name.to_string_lossy().into_owned())
    }
}

/// Inspects the Named Pipe client process via the kernel to determine its verified Windows
/// username, whether it is currently elevated (`is_admin`), and an elevated primary token.
pub fn inspect_pipe_client(pipe_handle: HANDLE) -> Result<PipeCallerInfo, String> {
    unsafe {
        let mut pid: u32 = 0;
        if GetNamedPipeClientProcessId(pipe_handle, &mut pid) == 0 {
            return Err(format!(
                "GetNamedPipeClientProcessId failed: {}",
                io::Error::last_os_error()
            ));
        }

        let proc_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if proc_handle.is_null() {
            return Err(format!(
                "OpenProcess({pid}) failed: {}",
                io::Error::last_os_error()
            ));
        }
        let _proc_guard = OwnedHandle(proc_handle);

        let mut token_handle: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(
            proc_handle,
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
            &mut token_handle,
        ) == 0
        {
            return Err(format!(
                "OpenProcessToken failed: {}",
                io::Error::last_os_error()
            ));
        }
        let token_guard = OwnedHandle(token_handle);

        let username = lookup_token_username(token_guard.0)?;

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut out_len: u32 = 0;
        if GetTokenInformation(
            token_guard.0,
            TokenElevation,
            &mut elevation as *mut TOKEN_ELEVATION as *mut c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut out_len,
        ) == 0
        {
            return Err(format!(
                "GetTokenInformation(TokenElevation) failed: {}",
                io::Error::last_os_error()
            ));
        }

        if elevation.TokenIsElevated != 0 {
            let is_admin = token_is_admin_member(token_guard.0);
            let elevated_token = if is_admin {
                Some(duplicate_primary_token(token_guard.0)?)
            } else {
                None
            };
            return Ok(PipeCallerInfo {
                username,
                is_admin,
                elevated_token,
            });
        }

        // Standard (split-token) UAC session: inspect TokenLinkedToken for the Administrator token.
        let mut linked = TOKEN_LINKED_TOKEN {
            LinkedToken: std::ptr::null_mut(),
        };
        if GetTokenInformation(
            token_guard.0,
            TokenLinkedToken,
            &mut linked as *mut TOKEN_LINKED_TOKEN as *mut c_void,
            std::mem::size_of::<TOKEN_LINKED_TOKEN>() as u32,
            &mut out_len,
        ) != 0
            && !linked.LinkedToken.is_null()
        {
            let linked_guard = OwnedHandle(linked.LinkedToken);
            if token_is_admin_member(linked_guard.0) {
                let elevated_token = duplicate_primary_token(linked_guard.0)?;
                return Ok(PipeCallerInfo {
                    username,
                    is_admin: false,
                    elevated_token: Some(elevated_token),
                });
            }
        }

        Ok(PipeCallerInfo {
            username,
            is_admin: false,
            elevated_token: None,
        })
    }
}

/// Creates a Named Pipe server instance locked down so SYSTEM/Administrators have full control
/// and Authenticated Users can connect to submit elevation requests.
pub fn create_secure_pipe_server(pipe_name: &str, first: bool) -> Result<NamedPipeServer, String> {
    let sddl = to_wide_null("D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)");
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(format!(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {}",
                io::Error::last_os_error()
            ));
        }

        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };

        let mut opts = ServerOptions::new();
        opts.first_pipe_instance(first);
        let res = opts.create_with_security_attributes_raw(
            pipe_name,
            &mut sa as *mut SECURITY_ATTRIBUTES as *mut c_void,
        );
        LocalFree(sd as _);
        res.map_err(|e| format!("failed to create named pipe {pipe_name}: {e}"))
    }
}

/// Executes `command` under the caller's elevated primary token and streams stdout/stderr chunks.
pub fn execute_elevated_command(
    elevated_token: HANDLE,
    command: &[String],
    cwd: Option<&str>,
    output_tx: tokio_mpsc::UnboundedSender<(String, Vec<u8>)>,
) -> Result<i32, String> {
    if command.is_empty() {
        return Err("command must not be empty".to_string());
    }

    unsafe {
        let mut pipe_sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: 1,
        };

        let mut stdout_read: HANDLE = std::ptr::null_mut();
        let mut stdout_write: HANDLE = std::ptr::null_mut();
        if CreatePipe(&mut stdout_read, &mut stdout_write, &mut pipe_sa, 0) == 0 {
            return Err(format!("CreatePipe(stdout) failed: {}", io::Error::last_os_error()));
        }
        let stdout_read_guard = OwnedHandle(stdout_read);
        let stdout_write_guard = OwnedHandle(stdout_write);
        SetHandleInformation(stdout_read_guard.0, HANDLE_FLAG_INHERIT, 0);

        let mut stderr_read: HANDLE = std::ptr::null_mut();
        let mut stderr_write: HANDLE = std::ptr::null_mut();
        if CreatePipe(&mut stderr_read, &mut stderr_write, &mut pipe_sa, 0) == 0 {
            return Err(format!("CreatePipe(stderr) failed: {}", io::Error::last_os_error()));
        }
        let stderr_read_guard = OwnedHandle(stderr_read);
        let stderr_write_guard = OwnedHandle(stderr_write);
        SetHandleInformation(stderr_read_guard.0, HANDLE_FLAG_INHERIT, 0);

        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: INVALID_HANDLE_VALUE,
            hStdOutput: stdout_write_guard.0,
            hStdError: stderr_write_guard.0,
            ..std::mem::zeroed()
        };
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        let cwd_wide = cwd.filter(|s| !s.trim().is_empty()).map(to_wide_null);
        let cwd_ptr = cwd_wide
            .as_ref()
            .map_or(std::ptr::null(), |v| v.as_ptr());

        let cmdline_str = build_windows_command_line(command);
        let mut cmdline_wide = to_wide_null(&cmdline_str);

        let mut ok = CreateProcessAsUserW(
            elevated_token,
            std::ptr::null(),
            cmdline_wide.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            std::ptr::null(),
            cwd_ptr,
            &si,
            &mut pi,
        );

        if ok == 0 && GetLastError() == ERROR_FILE_NOT_FOUND {
            let mut shell_cmd = Vec::with_capacity(command.len() + 3);
            shell_cmd.push("cmd.exe".to_string());
            shell_cmd.push("/D".to_string());
            shell_cmd.push("/C".to_string());
            shell_cmd.extend_from_slice(command);
            let fallback_line = build_windows_command_line(&shell_cmd);
            let mut fallback_wide = to_wide_null(&fallback_line);
            ok = CreateProcessAsUserW(
                elevated_token,
                std::ptr::null(),
                fallback_wide.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                std::ptr::null(),
                cwd_ptr,
                &si,
                &mut pi,
            );
        }

        if ok == 0 {
            return Err(format!(
                "CreateProcessAsUserW failed: {}",
                io::Error::last_os_error()
            ));
        }

        let proc_guard = OwnedHandle(pi.hProcess);
        let _thread_guard = OwnedHandle(pi.hThread);

        // Close parent-side write ends so readers observe EOF when the child finishes.
        drop(stdout_write_guard);
        drop(stderr_write_guard);

        let out_handle = stdout_read_guard.0;
        std::mem::forget(stdout_read_guard);
        let mut out_file = File::from_raw_handle(out_handle as _);

        let err_handle = stderr_read_guard.0;
        std::mem::forget(stderr_read_guard);
        let mut err_file = File::from_raw_handle(err_handle as _);

        let tx_out = output_tx.clone();
        let out_thread = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = out_file.read(&mut buf) {
                if n == 0 {
                    break;
                }
                if tx_out.send(("stdout".to_string(), buf[..n].to_vec())).is_err() {
                    break;
                }
            }
        });

        let tx_err = output_tx;
        let err_thread = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = err_file.read(&mut buf) {
                if n == 0 {
                    break;
                }
                if tx_err.send(("stderr".to_string(), buf[..n].to_vec())).is_err() {
                    break;
                }
            }
        });

        WaitForSingleObject(proc_guard.0, INFINITE);
        let mut exit_code: u32 = 1;
        GetExitCodeProcess(proc_guard.0, &mut exit_code);

        let _ = out_thread.join();
        let _ = err_thread.join();

        Ok(exit_code as i32)
    }
}

static SERVICE_CONFIG: OnceLock<Config> = OnceLock::new();
static SERVICE_STATUS_H: Mutex<Option<usize>> = Mutex::new(None);
static SERVICE_SHUTDOWN: Mutex<Option<oneshot::Sender<()>>> = Mutex::new(None);

fn report_service_status(state: u32, exit_code: u32, wait_hint_ms: u32) {
    let Ok(guard) = SERVICE_STATUS_H.lock() else {
        return;
    };
    let Some(raw_handle) = *guard else {
        return;
    };
    let controls = if state == SERVICE_START_PENDING || state == SERVICE_STOPPED {
        0
    } else {
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
    };
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: controls,
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: wait_hint_ms,
    };
    unsafe {
        SetServiceStatus(raw_handle as SERVICE_STATUS_HANDLE, &status);
    }
}

unsafe extern "system" fn service_ctrl_handler(
    dwcontrol: u32,
    _dweventtype: u32,
    _lpeventdata: *mut c_void,
    _lpcontext: *mut c_void,
) -> u32 {
    match dwcontrol {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            report_service_status(SERVICE_STOP_PENDING, 0, 5000);
            if let Ok(mut guard) = SERVICE_SHUTDOWN.lock() {
                if let Some(tx) = guard.take() {
                    let _ = tx.send(());
                }
            }
            0
        }
        SERVICE_CONTROL_INTERROGATE => 0,
        _ => 0,
    }
}

fn append_service_log(msg: &str) {
    let ts = crate::store::now_unix_secs();
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(r"C:\ProgramData\TailAuth\service.log")
    {
        let _ = writeln!(file, "[{ts}] {msg}");
    }
}

unsafe extern "system" fn service_main(
    _argc: u32,
    _argv: *mut windows_sys::core::PWSTR,
) {
    append_service_log("service_main entered");
    let svc_name = to_wide_null("TailAuth");
    let handle = RegisterServiceCtrlHandlerExW(
        svc_name.as_ptr(),
        Some(service_ctrl_handler),
        std::ptr::null(),
    );
    if handle.is_null() {
        append_service_log(&format!(
            "RegisterServiceCtrlHandlerExW failed: {}",
            io::Error::last_os_error()
        ));
        return;
    }

    if let Ok(mut guard) = SERVICE_STATUS_H.lock() {
        *guard = Some(handle as usize);
    }
    report_service_status(SERVICE_START_PENDING, 0, 3000);

    let Some(cfg) = SERVICE_CONFIG.get().cloned() else {
        append_service_log("missing SERVICE_CONFIG");
        report_service_status(SERVICE_STOPPED, 1, 0);
        return;
    };

    let (tx, rx) = oneshot::channel();
    if let Ok(mut guard) = SERVICE_SHUTDOWN.lock() {
        *guard = Some(tx);
    }

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            append_service_log(&format!("tokio runtime error: {e}"));
            report_service_status(SERVICE_STOPPED, 1, 0);
            return;
        }
    };

    report_service_status(SERVICE_RUNNING, 0, 0);
    append_service_log("service running");
    let res = rt.block_on(crate::daemon::run_daemon_with_shutdown(cfg, rx));
    let exit_code = match res {
        Ok(()) => {
            append_service_log("service stopped cleanly");
            0
        }
        Err(e) => {
            append_service_log(&format!("daemon error: {e}"));
            1
        }
    };
    report_service_status(SERVICE_STOPPED, exit_code, 0);
}

/// Runs TailAuth as a native Windows Service managed by the Service Control Manager (SCM).
pub fn run_windows_service(config: Config) -> Result<(), String> {
    let _ = SERVICE_CONFIG.set(config);
    let svc_name = to_wide_null("TailAuth");
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: svc_name.as_ptr() as *mut u16,
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];

    let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    if ok == 0 {
        return Err(format!(
            "StartServiceCtrlDispatcherW failed (use 'tailauth daemon' for foreground mode): {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn enable_vt_output() {
    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return;
        }
        let mut mode: u32 = 0;
        if GetConsoleMode(handle, &mut mode) != 0 {
            SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
}

fn clear_stdout_lines(lines: usize) {
    if lines > 0 {
        let mut out = io::stdout();
        let _ = write!(out, "\r\x1b[{lines}A\x1b[J");
        let _ = out.flush();
    }
}

fn open_pipe_client(pipe_name: &str) -> io::Result<File> {
    let wide = to_wide_null(pipe_name);
    for _ in 0..10 {
        match OpenOptions::new().read(true).write(true).open(pipe_name) {
            Ok(f) => return Ok(f),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                unsafe {
                    WaitNamedPipeW(wide.as_ptr(), 500);
                }
            }
            Err(e) => return Err(e),
        }
    }
    OpenOptions::new().read(true).write(true).open(pipe_name)
}

pub fn send_pipe_request(pipe_name: &str, req: &ClientRequest) -> Result<Vec<ServerEvent>, String> {
    let mut file = open_pipe_client(pipe_name).map_err(|e| {
        format!("failed to connect to TailAuth service at {pipe_name}: {e} (is TailAuth service running?)")
    })?;
    let mut line = serde_json::to_string(req).map_err(|e| e.to_string())?;
    line.push('\n');
    file.write_all(line.as_bytes())
        .and_then(|_| file.flush())
        .map_err(|e| format!("failed to write request: {e}"))?;

    let mut reader = BufReader::new(file);
    let mut events = Vec::new();
    let mut resp = String::new();
    while reader
        .read_line(&mut resp)
        .map_err(|e| format!("failed to read response: {e}"))?
        > 0
    {
        let ev: ServerEvent = serde_json::from_str(resp.trim())
            .map_err(|e| format!("invalid response: {e}"))?;
        events.push(ev);
        resp.clear();
    }
    Ok(events)
}

pub fn run_windows_enroll(config: &Config, user: String) -> i32 {
    enable_vt_output();
    let mut file = match open_pipe_client(&config.socket_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("tailauth: failed to connect to service ({e})");
            return 1;
        }
    };

    let req = ClientRequest::StartEnroll { user: user.clone() };
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    if let Err(e) = file.write_all(line.as_bytes()).and_then(|_| file.flush()) {
        eprintln!("tailauth: failed to send enroll request: {e}");
        return 1;
    }

    let mut reader = BufReader::new(file);
    let mut resp = String::new();
    if reader.read_line(&mut resp).is_err() || resp.is_empty() {
        eprintln!("tailauth: no response from service");
        return 1;
    }

    let pending: ServerEvent = match serde_json::from_str(resp.trim()) {
        Ok(ev) => ev,
        Err(e) => {
            eprintln!("tailauth: invalid response: {e}");
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
        eprintln!("tailauth: service closed connection before enrollment completed");
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

enum SudoMsg {
    Event(ServerEvent),
    Eof,
    KeyFallback,
    KeyCancel,
}

fn spawn_console_key_watcher(tx: mpsc::Sender<SudoMsg>, stop: Arc<AtomicBool>) {
    std::thread::spawn(move || unsafe {
        let stdin_handle = GetStdHandle(STD_INPUT_HANDLE);
        if stdin_handle.is_null() || stdin_handle == INVALID_HANDLE_VALUE {
            return;
        }
        while !stop.load(Ordering::Relaxed) {
            let wait = WaitForSingleObject(stdin_handle, 200);
            if stop.load(Ordering::Relaxed) {
                break;
            }
            if wait != WAIT_OBJECT_0 {
                continue;
            }
            let mut rec: INPUT_RECORD = std::mem::zeroed();
            let mut read_count: u32 = 0;
            if ReadConsoleInputW(stdin_handle, &mut rec, 1, &mut read_count) == 0
                || read_count == 0
            {
                break;
            }
            if rec.EventType as u32 == KEY_EVENT && rec.Event.KeyEvent.bKeyDown != 0 {
                let ch = rec.Event.KeyEvent.uChar.UnicodeChar;
                if ch == 0x03 {
                    let _ = tx.send(SudoMsg::KeyCancel);
                    break;
                }
                if matches!(ch, 0x0d | 0x0a | 0x1b)
                    || ch == (b'p' as u16)
                    || ch == (b'P' as u16)
                    || ch == (b'q' as u16)
                    || ch == (b'Q' as u16)
                {
                    let _ = tx.send(SudoMsg::KeyFallback);
                    break;
                }
            }
        }
    });
}

/// Interactive QR approval test on Windows without running an elevated command.
pub fn run_windows_test(config: &Config, user: String) -> i32 {
    enable_vt_output();
    let mut write_file = match open_pipe_client(&config.socket_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("tailauth: {e}");
            return 1;
        }
    };
    let read_file = match write_file.try_clone() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("tailauth: pipe clone failed: {e}");
            return 1;
        }
    };

    let req = ClientRequest::StartAuth {
        user: user.clone(),
        ruser: None,
        service: Some("windows-test".to_string()),
    };
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    if write_file.write_all(line.as_bytes()).is_err() || write_file.flush().is_err() {
        eprintln!("tailauth: failed to send request");
        return 1;
    }

    let mut reader = BufReader::new(read_file);
    let mut resp = String::new();
    if reader.read_line(&mut resp).is_err() || resp.is_empty() {
        eprintln!("tailauth: no response from service");
        return 1;
    }

    let (url, timeout_secs) = match serde_json::from_str::<ServerEvent>(resp.trim()) {
        Ok(ServerEvent::Pending {
            url, timeout_secs, ..
        }) => (url, timeout_secs),
        Ok(ServerEvent::NoCredentials) => {
            eprintln!("tailauth: user '{user}' has no enrolled credentials.");
            return 1;
        }
        Ok(ServerEvent::Error { message }) => {
            eprintln!("tailauth: {message}");
            return 1;
        }
        _ => return 1,
    };

    let Ok(rendered) = render_terminal_qr(&url) else {
        return 1;
    };

    println!();
    println!(
        "\x1b[1;34mTailAuth\x1b[0m — scan with your phone to test \x1b[1m{user}\x1b[0m ({timeout_secs}s timeout):"
    );
    print!("{}", rendered.text);
    println!("\x1b[2mLink: {url}");
    println!("Press Enter (or 'p' / Esc) to cancel...\x1b[0m");
    let total_lines = 2 + rendered.line_count + 2;

    let (tx, rx) = mpsc::channel();
    let stop_keys = Arc::new(AtomicBool::new(false));
    spawn_console_key_watcher(tx.clone(), Arc::clone(&stop_keys));

    std::thread::spawn(move || {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => {
                let _ = tx.send(SudoMsg::Eof);
            }
            Ok(_) => {
                if let Ok(ev) = serde_json::from_str::<ServerEvent>(line.trim()) {
                    let _ = tx.send(SudoMsg::Event(ev));
                } else {
                    let _ = tx.send(SudoMsg::Eof);
                }
            }
        }
    });

    match rx.recv() {
        Ok(SudoMsg::Event(ServerEvent::Approved { label, .. })) => {
            stop_keys.store(true, Ordering::Relaxed);
            clear_stdout_lines(total_lines);
            println!("\x1b[32m✔ TailAuth: Approved via {label}\x1b[0m");
            0
        }
        Ok(SudoMsg::Event(ServerEvent::Denied)) => {
            stop_keys.store(true, Ordering::Relaxed);
            clear_stdout_lines(total_lines);
            println!("\x1b[31m✖ TailAuth: Denied on phone.\x1b[0m");
            1
        }
        Ok(SudoMsg::Event(ServerEvent::Timeout)) => {
            stop_keys.store(true, Ordering::Relaxed);
            clear_stdout_lines(total_lines);
            println!("\x1b[33m⏱ TailAuth: Timed out.\x1b[0m");
            1
        }
        Ok(SudoMsg::KeyCancel) => {
            stop_keys.store(true, Ordering::Relaxed);
            drop(write_file);
            clear_stdout_lines(total_lines);
            println!("TailAuth: Cancelled.");
            130
        }
        _ => {
            stop_keys.store(true, Ordering::Relaxed);
            drop(write_file);
            clear_stdout_lines(total_lines);
            println!("TailAuth: Cancelled.");
            1
        }
    }
}

/// Runs an elevated Windows command after QR phone-fingerprint approval,
/// falling back cleanly to Windows 11 `sudo.exe` or standard UAC if skipped or unavailable.
pub fn run_windows_sudo(config: &Config, command: Vec<String>) -> i32 {
    if command.is_empty() {
        eprintln!("tailauth: usage: tailauth sudo <COMMAND> [ARGS...]");
        return 2;
    }

    enable_vt_output();

    let mut write_file = match open_pipe_client(&config.socket_path) {
        Ok(f) => f,
        Err(_) => return fallback_uac(&command),
    };
    let read_file = match write_file.try_clone() {
        Ok(f) => f,
        Err(_) => return fallback_uac(&command),
    };

    let cwd = env::current_dir()
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    let req = ClientRequest::RunElevated {
        command: command.clone(),
        cwd,
    };
    let Ok(mut req_line) = serde_json::to_string(&req) else {
        return fallback_uac(&command);
    };
    req_line.push('\n');
    if write_file.write_all(req_line.as_bytes()).is_err() || write_file.flush().is_err() {
        return fallback_uac(&command);
    }

    let mut reader = BufReader::new(read_file);
    let mut initial_line = String::new();
    if reader.read_line(&mut initial_line).is_err() || initial_line.is_empty() {
        return fallback_uac(&command);
    }

    let (url, timeout_secs) = match serde_json::from_str::<ServerEvent>(initial_line.trim()) {
        Ok(ServerEvent::Pending {
            url, timeout_secs, ..
        }) => (url, timeout_secs),
        Ok(ServerEvent::NoCredentials) | Ok(ServerEvent::Error { .. }) | Err(_) => {
            return fallback_uac(&command);
        }
        _ => return fallback_uac(&command),
    };

    let Ok(rendered) = render_terminal_qr(&url) else {
        return fallback_uac(&command);
    };

    println!();
    println!(
        "\x1b[1;34mTailAuth\x1b[0m — scan with your phone to elevate ({timeout_secs}s timeout):"
    );
    print!("{}", rendered.text);
    println!("\x1b[2mLink: {url}");
    println!("Press Enter (or 'p' / Esc) for Windows UAC / password...\x1b[0m");
    let total_lines = 2 + rendered.line_count + 2;

    let (tx, rx) = mpsc::channel();
    let stop_keys = Arc::new(AtomicBool::new(false));
    spawn_console_key_watcher(tx.clone(), Arc::clone(&stop_keys));

    std::thread::spawn(move || {
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => {
                    let _ = tx.send(SudoMsg::Eof);
                    break;
                }
                Ok(_) => {
                    if let Ok(ev) = serde_json::from_str::<ServerEvent>(line.trim()) {
                        let done = matches!(
                            ev,
                            ServerEvent::Denied
                                | ServerEvent::Timeout
                                | ServerEvent::Exited { .. }
                                | ServerEvent::Error { .. }
                        );
                        if tx.send(SudoMsg::Event(ev)).is_err() || done {
                            break;
                        }
                    }
                }
            }
        }
    });

    let mut approved = false;
    loop {
        match rx.recv() {
            Ok(SudoMsg::KeyCancel) if !approved => {
                stop_keys.store(true, Ordering::Relaxed);
                drop(write_file);
                clear_stdout_lines(total_lines);
                println!("TailAuth: Cancelled.");
                return 130;
            }
            Ok(SudoMsg::KeyFallback) if !approved => {
                stop_keys.store(true, Ordering::Relaxed);
                drop(write_file);
                clear_stdout_lines(total_lines);
                println!("TailAuth: Falling back to Windows UAC.");
                return fallback_uac(&command);
            }
            Ok(SudoMsg::Event(ServerEvent::Approved { label, .. })) => {
                approved = true;
                stop_keys.store(true, Ordering::Relaxed);
                clear_stdout_lines(total_lines);
                println!("\x1b[32m✔ TailAuth: Approved via {label}\x1b[0m");
            }
            Ok(SudoMsg::Event(ServerEvent::Output { stream, data_b64 })) => {
                if let Ok(bytes) = b64url_decode(&data_b64) {
                    if stream == "stderr" {
                        let mut err = io::stderr();
                        let _ = err.write_all(&bytes);
                        let _ = err.flush();
                    } else {
                        let mut out = io::stdout();
                        let _ = out.write_all(&bytes);
                        let _ = out.flush();
                    }
                }
            }
            Ok(SudoMsg::Event(ServerEvent::Exited { code })) => {
                return code;
            }
            Ok(SudoMsg::Event(ServerEvent::Denied)) => {
                stop_keys.store(true, Ordering::Relaxed);
                clear_stdout_lines(total_lines);
                println!("\x1b[31m✖ TailAuth: Denied on phone — falling back to Windows UAC.\x1b[0m");
                return fallback_uac(&command);
            }
            Ok(SudoMsg::Event(ServerEvent::Timeout)) => {
                stop_keys.store(true, Ordering::Relaxed);
                clear_stdout_lines(total_lines);
                println!("\x1b[33m⏱ TailAuth: Timed out — falling back to Windows UAC.\x1b[0m");
                return fallback_uac(&command);
            }
            Ok(SudoMsg::Event(ServerEvent::Error { message })) => {
                stop_keys.store(true, Ordering::Relaxed);
                if !approved {
                    clear_stdout_lines(total_lines);
                }
                eprintln!("tailauth: {message}");
                return if approved { 1 } else { fallback_uac(&command) };
            }
            Ok(SudoMsg::Eof) | Err(_) => {
                stop_keys.store(true, Ordering::Relaxed);
                if !approved {
                    clear_stdout_lines(total_lines);
                    return fallback_uac(&command);
                }
                return 1;
            }
            _ => {}
        }
    }
}

fn ps_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn is_windows_sudo_enabled() -> bool {
    let Ok(output) = Command::new("reg.exe")
        .args([
            "query",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo",
            "/v",
            "Enabled",
        ])
        .stderr(std::process::Stdio::null())
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if line.contains("Enabled") {
            if let Some(val) = line.split_whitespace().last() {
                let hex = val.trim_start_matches("0x").trim_start_matches("0X");
                if let Ok(num) = u32::from_str_radix(hex, 16) {
                    return num != 0;
                }
            }
        }
    }
    false
}

fn fallback_uac(command: &[String]) -> i32 {
    let win_sudo = Path::new(r"C:\Windows\System32\sudo.exe");
    if win_sudo.exists() && is_windows_sudo_enabled() {
        if let Ok(status) = Command::new(win_sudo).args(command).status() {
            return status.code().unwrap_or(1);
        }
    }

    let file = &command[0];
    let args_joined = if command.len() > 1 {
        command[1..]
            .iter()
            .map(|a| quote_windows_arg(a))
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        String::new()
    };

    let ps_script = if args_joined.is_empty() {
        format!(
            "$p = Start-Process -FilePath {} -Verb RunAs -PassThru -Wait; exit $p.ExitCode",
            ps_single_quote(file)
        )
    } else {
        format!(
            "$p = Start-Process -FilePath {} -ArgumentList {} -Verb RunAs -PassThru -Wait; exit $p.ExitCode",
            ps_single_quote(file),
            ps_single_quote(&args_joined)
        )
    };

    match Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", &ps_script])
        .status()
    {
        Ok(status) => status.code().unwrap_or(1),
        Err(e) => {
            eprintln!("tailauth: fallback UAC failed: {e}");
            1
        }
    }
}
