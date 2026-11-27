use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("failed to read credential store {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to parse credential store {path}: {source}")]
    Parse {
        path: String,
        source: serde_json::Error,
    },
    #[error("failed to write credential store {path}: {source}")]
    Write {
        path: String,
        source: std::io::Error,
    },
    #[error("credential not found matching prefix '{0}'")]
    NotFound(String),
    #[error("ambiguous credential prefix '{0}' matches multiple credentials")]
    AmbiguousPrefix(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialRecord {
    pub id: String,
    pub public_key_pem: String,
    pub sign_count: u32,
    pub label: String,
    pub tailscale_user: Option<String>,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct CredentialStore {
    pub users: BTreeMap<String, Vec<CredentialRecord>>,
}

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn normalize_username_key(user: &str) -> String {
    #[cfg(windows)]
    {
        user.trim().to_ascii_lowercase()
    }
    #[cfg(not(windows))]
    {
        user.to_string()
    }
}

pub fn user_matches(stored_key: &str, query: &str) -> bool {
    #[cfg(windows)]
    {
        stored_key.eq_ignore_ascii_case(query.trim())
    }
    #[cfg(not(windows))]
    {
        stored_key == query
    }
}

#[cfg(windows)]
fn replace_file_atomic(tmp_path: &Path, dest_path: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let src: Vec<u16> = tmp_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let dst: Vec<u16> = dest_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let ok = unsafe {
        MoveFileExW(
            src.as_ptr(),
            dst.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

impl CredentialStore {
    /// Loads the credential store from disk, returning an empty store if the file does not exist.
    pub fn load(path: &Path) -> Result<Self, StoreError> {
        match fs::read_to_string(path) {
            Ok(raw) => {
                if raw.trim().is_empty() {
                    return Ok(Self::default());
                }
                serde_json::from_str(&raw).map_err(|source| StoreError::Parse {
                    path: path.display().to_string(),
                    source,
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(StoreError::Read {
                path: path.display().to_string(),
                source,
            }),
        }
    }

    /// Atomically persists the credential store to disk (`0600` on Unix, atomic replace on Windows).
    pub fn save(&self, path: &Path) -> Result<(), StoreError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                let mut builder = fs::DirBuilder::new();
                builder.recursive(true);
                #[cfg(unix)]
                builder.mode(0o700);
                builder.create(parent).map_err(|source| StoreError::Write {
                    path: parent.display().to_string(),
                    source,
                })?;
            }
        }

        let json = serde_json::to_string_pretty(self).map_err(|source| StoreError::Parse {
            path: path.display().to_string(),
            source,
        })?;

        let tmp_path = path.with_extension(format!("json.tmp.{}", std::process::id()));
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);

        let mut file = opts.open(&tmp_path).map_err(|source| StoreError::Write {
            path: tmp_path.display().to_string(),
            source,
        })?;

        file.write_all(json.as_bytes())
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.sync_all())
            .map_err(|source| StoreError::Write {
                path: tmp_path.display().to_string(),
                source,
            })?;

        drop(file);

        #[cfg(unix)]
        {
            fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600)).map_err(|source| {
                StoreError::Write {
                    path: tmp_path.display().to_string(),
                    source,
                }
            })?;
            fs::rename(&tmp_path, path).map_err(|source| StoreError::Write {
                path: path.display().to_string(),
                source,
            })?;
        }

        #[cfg(windows)]
        replace_file_atomic(&tmp_path, path).map_err(|source| StoreError::Write {
            path: path.display().to_string(),
            source,
        })?;

        Ok(())
    }

    pub fn add_credential(&mut self, user: &str, record: CredentialRecord) {
        let key = normalize_username_key(user);
        let existing_key = self
            .users
            .keys()
            .find(|k| user_matches(k, &key))
            .cloned()
            .unwrap_or(key);

        let entries = self.users.entry(existing_key).or_default();
        if let Some(existing) = entries.iter_mut().find(|c| c.id == record.id) {
            *existing = record;
        } else {
            entries.push(record);
        }
    }

    pub fn get_user_credentials(&self, user: &str) -> &[CredentialRecord] {
        if let Some(exact) = self.users.get(user) {
            return exact.as_slice();
        }
        #[cfg(windows)]
        {
            for (k, v) in &self.users {
                if k.eq_ignore_ascii_case(user.trim()) {
                    return v.as_slice();
                }
            }
        }
        &[]
    }

    /// Case-insensitive lookup helper (tested cross-platform).
    #[cfg(test)]
    pub fn get_user_credentials_ci(&self, user: &str) -> &[CredentialRecord] {
        let trimmed = user.trim();
        for (k, v) in &self.users {
            if k.eq_ignore_ascii_case(trimmed) {
                return v.as_slice();
            }
        }
        &[]
    }

    pub fn update_sign_count(&mut self, user: &str, credential_id: &str, new_sign_count: u32) -> bool {
        for (uname, entries) in &mut self.users {
            if user_matches(uname, user) {
                if let Some(cred) = entries.iter_mut().find(|c| c.id == credential_id) {
                    cred.sign_count = new_sign_count;
                    return true;
                }
            }
        }
        false
    }

    pub fn revoke_by_prefix(
        &mut self,
        user: Option<&str>,
        id_prefix: &str,
    ) -> Result<String, StoreError> {
        let mut matches: Vec<(String, String)> = Vec::new();
        for (uname, creds) in &self.users {
            if let Some(target_user) = user {
                if !user_matches(uname, target_user) {
                    continue;
                }
            }
            for cred in creds {
                if cred.id.starts_with(id_prefix) {
                    matches.push((uname.clone(), cred.id.clone()));
                }
            }
        }

        if matches.is_empty() {
            return Err(StoreError::NotFound(id_prefix.to_string()));
        }
        if matches.len() > 1 {
            return Err(StoreError::AmbiguousPrefix(id_prefix.to_string()));
        }

        let (owner, full_id) = matches.remove(0);
        if let Some(creds) = self.users.get_mut(&owner) {
            creds.retain(|c| c.id != full_id);
            if creds.is_empty() {
                self.users.remove(&owner);
            }
        }
        Ok(full_id)
    }

    pub fn enrolled_user_count(&self) -> usize {
        self.users.values().filter(|v| !v.is_empty()).count()
    }

    pub fn total_credentials(&self) -> usize {
        self.users.values().map(Vec::len).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn store_atomic_save_permissions_and_crud() {
        let dir = std::env::temp_dir().join(format!("tailauth_store_test_{}", std::process::id()));
        let path = dir.join("credentials.json");

        let mut store = CredentialStore::load(&path).unwrap();
        assert_eq!(store.total_credentials(), 0);

        store.add_credential(
            "alice",
            CredentialRecord {
                id: "cred-alpha-1234".to_string(),
                public_key_pem: "PEM1".to_string(),
                sign_count: 0,
                label: "Pixel 9".to_string(),
                tailscale_user: Some("alice@example".to_string()),
                created_at_unix: 1700000000,
            },
        );
        store.add_credential(
            "alice",
            CredentialRecord {
                id: "cred-beta-5678".to_string(),
                public_key_pem: "PEM2".to_string(),
                sign_count: 5,
                label: "iPhone".to_string(),
                tailscale_user: None,
                created_at_unix: 1700000100,
            },
        );
        assert!(store.update_sign_count("alice", "cred-beta-5678", 6));

        store.save(&path).unwrap();
        #[cfg(unix)]
        {
            let mode = fs::metadata(&path).unwrap().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let loaded = CredentialStore::load(&path).unwrap();
        assert_eq!(loaded.enrolled_user_count(), 1);
        assert_eq!(loaded.total_credentials(), 2);
        assert_eq!(loaded.get_user_credentials("alice")[1].sign_count, 6);
        assert_eq!(loaded.get_user_credentials_ci("ALICE").len(), 2);

        let mut mutable = loaded;
        // Ambiguous prefix fails
        assert!(matches!(
            mutable.revoke_by_prefix(Some("alice"), "cred-"),
            Err(StoreError::AmbiguousPrefix(_))
        ));
        let removed = mutable.revoke_by_prefix(Some("alice"), "cred-alpha").unwrap();
        assert_eq!(removed, "cred-alpha-1234");
        assert_eq!(mutable.total_credentials(), 1);

        let _ = fs::remove_dir_all(&dir);
    }
}
