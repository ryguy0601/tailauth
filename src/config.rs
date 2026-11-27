use serde::{Deserialize, Serialize};
use std::fs;
#[cfg(test)]
use std::io::Write;
#[cfg(all(test, unix))]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use thiserror::Error;

#[cfg(unix)]
pub const DEFAULT_CONFIG_PATH: &str = "/etc/tailauth/config.json";
#[cfg(unix)]
pub const DEFAULT_SOCKET_PATH: &str = "/run/tailauth/daemon.sock";
#[cfg(unix)]
pub const DEFAULT_STORE_PATH: &str = "/var/lib/tailauth/credentials.json";

#[cfg(windows)]
pub const DEFAULT_CONFIG_PATH: &str = r"C:\ProgramData\TailAuth\config.json";
#[cfg(windows)]
pub const DEFAULT_SOCKET_PATH: &str = r"\\.\pipe\tailauth";
#[cfg(windows)]
pub const DEFAULT_STORE_PATH: &str = r"C:\ProgramData\TailAuth\credentials.json";

pub const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:8443";
pub const DEFAULT_HTTPS_PORT: u16 = 8443;
pub const DEFAULT_TIMEOUT_SECS: u64 = 60;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to parse config {path}: {source}")]
    Parse {
        path: String,
        source: serde_json::Error,
    },
    #[cfg(test)]
    #[error("failed to write config {path}: {source}")]
    Write {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid config: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Config {
    pub fqdn: String,
    pub https_port: u16,
    pub listen_addr: String,
    pub socket_path: String,
    pub store_path: String,
    pub timeout_secs: u64,
    pub allowed_tailscale_users: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            fqdn: String::new(),
            https_port: DEFAULT_HTTPS_PORT,
            listen_addr: DEFAULT_LISTEN_ADDR.to_string(),
            socket_path: DEFAULT_SOCKET_PATH.to_string(),
            store_path: DEFAULT_STORE_PATH.to_string(),
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            allowed_tailscale_users: Vec::new(),
        }
    }
}

impl Config {
    /// Returns the normalized Tailscale MagicDNS FQDN without trailing dot or whitespace.
    pub fn rp_id(&self) -> &str {
        self.fqdn.trim().trim_end_matches('.')
    }

    /// Returns the public HTTPS base URL (omitting `:443` for standard HTTPS).
    pub fn base_url(&self) -> String {
        let host = self.rp_id();
        if self.https_port == 443 {
            format!("https://{host}")
        } else {
            format!("https://{host}:{}", self.https_port)
        }
    }

    /// Returns the exact WebAuthn origin expected from the mobile browser.
    pub fn expected_origin(&self) -> String {
        self.base_url()
    }

    /// Loads configuration from disk and validates required fields.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        let mut cfg: Self = serde_json::from_str(&raw).map_err(|source| ConfigError::Parse {
            path: path.display().to_string(),
            source,
        })?;
        cfg.fqdn = cfg.rp_id().to_string();
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validates configuration invariants.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.rp_id().is_empty() {
            return Err(ConfigError::Invalid("fqdn must not be empty".to_string()));
        }
        if self.https_port == 0 {
            return Err(ConfigError::Invalid(
                "https_port must be non-zero".to_string(),
            ));
        }
        if self.timeout_secs == 0 {
            return Err(ConfigError::Invalid(
                "timeout_secs must be greater than zero".to_string(),
            ));
        }
        if self.listen_addr.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "listen_addr must not be empty".to_string(),
            ));
        }
        if self.socket_path.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "socket_path must not be empty".to_string(),
            ));
        }
        if self.store_path.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "store_path must not be empty".to_string(),
            ));
        }
        Ok(())
    }

    /// Atomically saves configuration to disk.
    #[cfg(test)]
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        self.validate()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| ConfigError::Write {
                path: path.display().to_string(),
                source,
            })?;
        }

        let json = serde_json::to_string_pretty(self).map_err(|source| ConfigError::Parse {
            path: path.display().to_string(),
            source,
        })?;

        let tmp_path = path.with_extension(format!("json.tmp.{}", std::process::id()));
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o644);

        let mut file = opts.open(&tmp_path).map_err(|source| ConfigError::Write {
            path: tmp_path.display().to_string(),
            source,
        })?;

        file.write_all(json.as_bytes())
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.sync_all())
            .map_err(|source| ConfigError::Write {
                path: tmp_path.display().to_string(),
                source,
            })?;

        drop(file);
        #[cfg(windows)]
        let _ = fs::remove_file(path);
        fs::rename(&tmp_path, path).map_err(|source| ConfigError::Write {
            path: path.display().to_string(),
            source,
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_and_origin_handle_ports_and_trailing_dots() {
        let cfg = Config {
            fqdn: "laptop.tailnet-abc.ts.net.".to_string(),
            https_port: 8443,
            ..Config::default()
        };
        assert_eq!(cfg.rp_id(), "laptop.tailnet-abc.ts.net");
        assert_eq!(cfg.base_url(), "https://laptop.tailnet-abc.ts.net:8443");
        assert_eq!(
            cfg.expected_origin(),
            "https://laptop.tailnet-abc.ts.net:8443"
        );

        let cfg_443 = Config {
            fqdn: "laptop.tailnet-abc.ts.net".to_string(),
            https_port: 443,
            ..Config::default()
        };
        assert_eq!(cfg_443.base_url(), "https://laptop.tailnet-abc.ts.net");
        assert_eq!(
            cfg_443.expected_origin(),
            "https://laptop.tailnet-abc.ts.net"
        );
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("tailauth_cfg_test_{}", std::process::id()));
        let path = dir.join("config.json");
        let cfg = Config {
            fqdn: "workstation.tail123.ts.net.".to_string(),
            https_port: 9443,
            timeout_secs: 45,
            allowed_tailscale_users: vec!["alice@example".to_string()],
            ..Config::default()
        };
        cfg.save(&path).unwrap();
        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.fqdn, "workstation.tail123.ts.net");
        assert_eq!(loaded.https_port, 9443);
        assert_eq!(loaded.timeout_secs, 45);
        assert_eq!(loaded.allowed_tailscale_users, vec!["alice@example"]);
        let _ = fs::remove_dir_all(&dir);
    }
}
