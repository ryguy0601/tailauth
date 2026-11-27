use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientRequest {
    StartAuth {
        user: String,
        ruser: Option<String>,
        service: Option<String>,
    },
    StartEnroll {
        user: String,
    },
    ListCredentials {
        user: Option<String>,
    },
    RevokeCredential {
        user: Option<String>,
        id_prefix: String,
    },
    RunElevated {
        command: Vec<String>,
        cwd: Option<String>,
    },
    Status,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialSummary {
    pub user: String,
    pub id: String,
    pub label: String,
    pub tailscale_user: Option<String>,
    pub sign_count: u32,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerEvent {
    Pending {
        token: String,
        url: String,
        timeout_secs: u64,
    },
    Approved {
        label: String,
        tailscale_user: Option<String>,
    },
    Denied,
    Timeout,
    NoCredentials,
    Enrolled {
        id: String,
        label: String,
        tailscale_user: Option<String>,
    },
    Credentials {
        credentials: Vec<CredentialSummary>,
    },
    Revoked {
        id: String,
    },
    Output {
        stream: String,
        data_b64: String,
    },
    Exited {
        code: i32,
    },
    StatusInfo {
        fqdn: String,
        https_port: u16,
        enrolled_users: usize,
        total_credentials: usize,
    },
    Error {
        message: String,
    },
}

/// Quotes a single argument according to Windows `CommandLineToArgvW` / MSVCRT rules.
#[allow(dead_code)]
pub fn quote_windows_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.bytes().any(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\x0b' | b'"')) {
        return arg.to_string();
    }

    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        if ch == '\\' {
            backslashes += 1;
        } else if ch == '"' {
            for _ in 0..(backslashes * 2 + 1) {
                out.push('\\');
            }
            out.push('"');
            backslashes = 0;
        } else {
            for _ in 0..backslashes {
                out.push('\\');
            }
            out.push(ch);
            backslashes = 0;
        }
    }
    for _ in 0..(backslashes * 2) {
        out.push('\\');
    }
    out.push('"');
    out
}

#[allow(dead_code)]
pub fn build_windows_command_line(args: &[String]) -> String {
    args.iter()
        .map(|a| quote_windows_arg(a))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_command_line_quoting_handles_spaces_quotes_and_backslashes() {
        assert_eq!(quote_windows_arg("whoami"), "whoami");
        assert_eq!(quote_windows_arg(""), "\"\"");
        assert_eq!(
            quote_windows_arg(r#"C:\Program Files\App\"#),
            r#""C:\Program Files\App\\""#
        );
        assert_eq!(
            quote_windows_arg(r#"say "hello""#),
            r#""say \"hello\"""#
        );
        assert_eq!(
            build_windows_command_line(&[
                "powershell".to_string(),
                "-Command".to_string(),
                "Get-Service \"TailAuth\"".to_string(),
            ]),
            r#"powershell -Command "Get-Service \"TailAuth\"""#
        );
    }
}
