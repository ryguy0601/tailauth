use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use rand::RngCore;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::{Command, Stdio};
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

#[cfg(unix)]
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// ASN.1 DER SubjectPublicKeyInfo header for an uncompressed EC P-256 public key (26 bytes).
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid base64url input: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invalid CBOR encoding: {0}")]
    Cbor(String),
    #[error("invalid COSE P-256 key: {0}")]
    InvalidCoseKey(String),
    #[cfg(any(windows, test))]
    #[error("invalid P-256 SPKI PEM or DER signature: {0}")]
    InvalidEncoding(String),
    #[error("signature verification backend error: {0}")]
    VerifyBackend(String),
}

/// Computes a FIPS 180-4 SHA-256 digest in pure Rust.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let j = i * 4;
            *word = u32::from_be_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Generates a cryptographically random base64url (unpadded) string.
pub fn random_b64url(num_bytes: usize) -> String {
    let mut buf = vec![0u8; num_bytes];
    rand::rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(&buf)
}

pub fn b64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn b64url_decode(input: &str) -> Result<Vec<u8>, CryptoError> {
    let trimmed = input.trim().trim_end_matches('=');
    Ok(URL_SAFE_NO_PAD.decode(trimmed)?)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborValue {
    Uint(u64),
    NegInt(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborValue>),
    Map(Vec<(CborValue, CborValue)>),
    Simple(u8),
}

impl CborValue {
    pub fn as_int(&self) -> Option<i128> {
        match self {
            CborValue::Uint(v) => Some(*v as i128),
            CborValue::NegInt(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            CborValue::Bytes(b) => Some(b.as_slice()),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&[(CborValue, CborValue)]> {
        match self {
            CborValue::Map(m) => Some(m.as_slice()),
            _ => None,
        }
    }
}

pub fn cbor_map_get_text<'a>(
    entries: &'a [(CborValue, CborValue)],
    key: &str,
) -> Option<&'a CborValue> {
    entries
        .iter()
        .find(|(k, _)| matches!(k, CborValue::Text(s) if s == key))
        .map(|(_, v)| v)
}

pub fn cbor_map_get_int<'a>(
    entries: &'a [(CborValue, CborValue)],
    key: i128,
) -> Option<&'a CborValue> {
    entries
        .iter()
        .find(|(k, _)| k.as_int() == Some(key))
        .map(|(_, v)| v)
}

/// Decodes a single CBOR item and returns `(value, bytes_consumed)`.
pub fn decode_cbor_prefix(data: &[u8]) -> Result<(CborValue, usize), CryptoError> {
    let mut pos = 0usize;
    let value = decode_item(data, &mut pos, 0)?;
    Ok((value, pos))
}

/// Decodes a complete CBOR buffer, rejecting trailing garbage bytes.
pub fn decode_cbor_exact(data: &[u8]) -> Result<CborValue, CryptoError> {
    let (value, consumed) = decode_cbor_prefix(data)?;
    if consumed != data.len() {
        return Err(CryptoError::Cbor(format!(
            "trailing bytes after CBOR object ({consumed} != {})",
            data.len()
        )));
    }
    Ok(value)
}

const MAX_CBOR_DEPTH: usize = 16;

fn read_uint_arg(data: &[u8], pos: &mut usize, info: u8) -> Result<u64, CryptoError> {
    match info {
        0..=23 => Ok(info as u64),
        24 => {
            if *pos + 1 > data.len() {
                return Err(CryptoError::Cbor("truncated 1-byte arg".into()));
            }
            let v = data[*pos] as u64;
            *pos += 1;
            Ok(v)
        }
        25 => {
            if *pos + 2 > data.len() {
                return Err(CryptoError::Cbor("truncated 2-byte arg".into()));
            }
            let v = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as u64;
            *pos += 2;
            Ok(v)
        }
        26 => {
            if *pos + 4 > data.len() {
                return Err(CryptoError::Cbor("truncated 4-byte arg".into()));
            }
            let v = u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]])
                as u64;
            *pos += 4;
            Ok(v)
        }
        27 => {
            if *pos + 8 > data.len() {
                return Err(CryptoError::Cbor("truncated 8-byte arg".into()));
            }
            let v = u64::from_be_bytes([
                data[*pos],
                data[*pos + 1],
                data[*pos + 2],
                data[*pos + 3],
                data[*pos + 4],
                data[*pos + 5],
                data[*pos + 6],
                data[*pos + 7],
            ]);
            *pos += 8;
            Ok(v)
        }
        _ => Err(CryptoError::Cbor(format!(
            "unsupported CBOR additional info {info}"
        ))),
    }
}

fn decode_item(data: &[u8], pos: &mut usize, depth: usize) -> Result<CborValue, CryptoError> {
    if depth > MAX_CBOR_DEPTH {
        return Err(CryptoError::Cbor("CBOR nesting limit exceeded".into()));
    }
    if *pos >= data.len() {
        return Err(CryptoError::Cbor("unexpected end of CBOR input".into()));
    }

    let initial = data[*pos];
    *pos += 1;
    let major = initial >> 5;
    let info = initial & 0x1f;
    let arg = read_uint_arg(data, pos, info)?;

    match major {
        0 => Ok(CborValue::Uint(arg)),
        1 => Ok(CborValue::NegInt(-1 - (arg as i128))),
        2 => {
            let len = usize::try_from(arg)
                .map_err(|_| CryptoError::Cbor("byte string length overflow".into()))?;
            let end = pos
                .checked_add(len)
                .ok_or_else(|| CryptoError::Cbor("byte string offset overflow".into()))?;
            if end > data.len() {
                return Err(CryptoError::Cbor("truncated byte string".into()));
            }
            let slice = data[*pos..end].to_vec();
            *pos = end;
            Ok(CborValue::Bytes(slice))
        }
        3 => {
            let len = usize::try_from(arg)
                .map_err(|_| CryptoError::Cbor("text string length overflow".into()))?;
            let end = pos
                .checked_add(len)
                .ok_or_else(|| CryptoError::Cbor("text string offset overflow".into()))?;
            if end > data.len() {
                return Err(CryptoError::Cbor("truncated text string".into()));
            }
            let text = std::str::from_utf8(&data[*pos..end])
                .map_err(|_| CryptoError::Cbor("invalid UTF-8 in text string".into()))?
                .to_string();
            *pos = end;
            Ok(CborValue::Text(text))
        }
        4 => {
            let count = usize::try_from(arg)
                .map_err(|_| CryptoError::Cbor("array length overflow".into()))?;
            if count > data.len().saturating_sub(*pos) {
                return Err(CryptoError::Cbor("CBOR array exceeds remaining input".into()));
            }
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                items.push(decode_item(data, pos, depth + 1)?);
            }
            Ok(CborValue::Array(items))
        }
        5 => {
            let count = usize::try_from(arg)
                .map_err(|_| CryptoError::Cbor("map length overflow".into()))?;
            if count.saturating_mul(2) > data.len().saturating_sub(*pos) {
                return Err(CryptoError::Cbor("CBOR map exceeds remaining input".into()));
            }
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                let k = decode_item(data, pos, depth + 1)?;
                let v = decode_item(data, pos, depth + 1)?;
                entries.push((k, v));
            }
            Ok(CborValue::Map(entries))
        }
        6 => Err(CryptoError::Cbor("unsupported CBOR tag".into())),
        7 => {
            if info == 24 {
                Ok(CborValue::Simple(arg as u8))
            } else if info < 24 {
                Ok(CborValue::Simple(info))
            } else {
                Err(CryptoError::Cbor("unsupported CBOR float/simple".into()))
            }
        }
        _ => unreachable!(),
    }
}

/// Converts a COSE EC2 ES256 (P-256) public key into ASN.1 DER SubjectPublicKeyInfo bytes.
pub fn cose_p256_to_spki_der(cose_bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let val = decode_cbor_exact(cose_bytes)?;
    let map = val
        .as_map()
        .ok_or_else(|| CryptoError::InvalidCoseKey("expected CBOR map".into()))?;

    let kty = cbor_map_get_int(map, 1)
        .and_then(CborValue::as_int)
        .ok_or_else(|| CryptoError::InvalidCoseKey("missing kty (1)".into()))?;
    if kty != 2 {
        return Err(CryptoError::InvalidCoseKey(format!(
            "expected EC2 kty=2, got {kty}"
        )));
    }

    let alg = cbor_map_get_int(map, 3)
        .and_then(CborValue::as_int)
        .ok_or_else(|| CryptoError::InvalidCoseKey("missing alg (3)".into()))?;
    if alg != -7 {
        return Err(CryptoError::InvalidCoseKey(format!(
            "expected ES256 alg=-7, got {alg}"
        )));
    }

    let crv = cbor_map_get_int(map, -1)
        .and_then(CborValue::as_int)
        .ok_or_else(|| CryptoError::InvalidCoseKey("missing crv (-1)".into()))?;
    if crv != 1 {
        return Err(CryptoError::InvalidCoseKey(format!(
            "expected P-256 crv=1, got {crv}"
        )));
    }

    let x = cbor_map_get_int(map, -2)
        .and_then(CborValue::as_bytes)
        .ok_or_else(|| CryptoError::InvalidCoseKey("missing x (-2)".into()))?;
    let y = cbor_map_get_int(map, -3)
        .and_then(CborValue::as_bytes)
        .ok_or_else(|| CryptoError::InvalidCoseKey("missing y (-3)".into()))?;

    if x.len() != 32 || y.len() != 32 {
        return Err(CryptoError::InvalidCoseKey(format!(
            "expected 32-byte P-256 coordinates, got x={}, y={}",
            x.len(),
            y.len()
        )));
    }

    let mut der = Vec::with_capacity(P256_SPKI_PREFIX.len() + 1 + 32 + 32);
    der.extend_from_slice(&P256_SPKI_PREFIX);
    der.push(0x04); // Uncompressed EC point
    der.extend_from_slice(x);
    der.extend_from_slice(y);
    Ok(der)
}

/// Encodes DER SubjectPublicKeyInfo bytes into PEM format.
pub fn spki_der_to_pem(der: &[u8]) -> String {
    let b64 = STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        let line = std::str::from_utf8(chunk).expect("base64 is ASCII");
        pem.push_str(line);
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem
}

/// Extracts uncompressed P-256 `(x, y)` coordinates from an SPKI PEM public key.
#[cfg(any(windows, test))]
pub fn spki_pem_to_p256_xy(public_key_pem: &str) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let mut body = String::new();
    let mut in_block = false;
    for line in public_key_pem.lines() {
        let trimmed = line.trim();
        if trimmed == "-----BEGIN PUBLIC KEY-----" {
            in_block = true;
            continue;
        }
        if trimmed == "-----END PUBLIC KEY-----" {
            break;
        }
        if in_block {
            body.push_str(trimmed);
        }
    }

    if body.is_empty() {
        return Err(CryptoError::InvalidEncoding(
            "missing PEM public key body".into(),
        ));
    }

    let der = STANDARD
        .decode(body.as_bytes())
        .map_err(|e| CryptoError::InvalidEncoding(format!("invalid PEM base64: {e}")))?;

    if der.len() != 91 || der[..26] != P256_SPKI_PREFIX || der[26] != 0x04 {
        return Err(CryptoError::InvalidEncoding(
            "expected 91-byte uncompressed P-256 SPKI DER".into(),
        ));
    }

    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&der[27..59]);
    y.copy_from_slice(&der[59..91]);
    Ok((x, y))
}

#[cfg(any(windows, test))]
fn read_der_len(data: &[u8], pos: &mut usize) -> Result<usize, CryptoError> {
    if *pos >= data.len() {
        return Err(CryptoError::InvalidEncoding("truncated DER length".into()));
    }
    let first = data[*pos];
    *pos += 1;
    if first < 0x80 {
        return Ok(first as usize);
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > 2 || *pos + count > data.len() {
        return Err(CryptoError::InvalidEncoding("unsupported DER length".into()));
    }
    let mut len = 0usize;
    for _ in 0..count {
        len = (len << 8) | (data[*pos] as usize);
        *pos += 1;
    }
    Ok(len)
}

#[cfg(any(windows, test))]
fn read_der_p256_int(data: &[u8], pos: &mut usize) -> Result<[u8; 32], CryptoError> {
    if *pos >= data.len() || data[*pos] != 0x02 {
        return Err(CryptoError::InvalidEncoding(
            "expected ASN.1 INTEGER tag".into(),
        ));
    }
    *pos += 1;
    let len = read_der_len(data, pos)?;
    if len == 0 || *pos + len > data.len() {
        return Err(CryptoError::InvalidEncoding(
            "invalid ASN.1 INTEGER length".into(),
        ));
    }
    let raw = &data[*pos..*pos + len];
    *pos += len;

    // Reject negative DER integers
    if (raw[0] & 0x80) != 0 {
        return Err(CryptoError::InvalidEncoding(
            "negative ASN.1 INTEGER in ECDSA signature".into(),
        ));
    }

    // Strip a single leading sign-padding 0x00 byte if present.
    let trimmed = if raw.len() > 1 && raw[0] == 0x00 {
        if (raw[1] & 0x80) == 0 {
            return Err(CryptoError::InvalidEncoding(
                "non-minimal ASN.1 INTEGER padding".into(),
            ));
        }
        &raw[1..]
    } else {
        raw
    };

    if trimmed.len() > 32 {
        return Err(CryptoError::InvalidEncoding(format!(
            "ECDSA scalar exceeds 32 bytes ({})",
            trimmed.len()
        )));
    }
    if trimmed.iter().all(|&b| b == 0) {
        return Err(CryptoError::InvalidEncoding(
            "zero ECDSA signature scalar".into(),
        ));
    }

    let mut out = [0u8; 32];
    out[32 - trimmed.len()..].copy_from_slice(trimmed);
    Ok(out)
}

/// Converts an ASN.1 DER ECDSA signature (`SEQUENCE { INTEGER r, INTEGER s }`)
/// into the fixed 64-byte IEEE P1363 `r || s` representation required by Windows CNG.
#[cfg(any(windows, test))]
pub fn ecdsa_der_to_p1363_64(der_sig: &[u8]) -> Result<[u8; 64], CryptoError> {
    let mut pos = 0usize;
    if der_sig.is_empty() || der_sig[pos] != 0x30 {
        return Err(CryptoError::InvalidEncoding(
            "expected ASN.1 SEQUENCE tag".into(),
        ));
    }
    pos += 1;
    let seq_len = read_der_len(der_sig, &mut pos)?;
    if pos + seq_len != der_sig.len() {
        return Err(CryptoError::InvalidEncoding(
            "ASN.1 SEQUENCE length mismatch or trailing bytes".into(),
        ));
    }

    let r = read_der_p256_int(der_sig, &mut pos)?;
    let s = read_der_p256_int(der_sig, &mut pos)?;
    if pos != der_sig.len() {
        return Err(CryptoError::InvalidEncoding(
            "trailing bytes inside ECDSA SEQUENCE".into(),
        ));
    }

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&r);
    out[32..].copy_from_slice(&s);
    Ok(out)
}

#[cfg(unix)]
struct TempFileGuard {
    path: PathBuf,
}

#[cfg(unix)]
impl TempFileGuard {
    fn create_private(prefix: &str, bytes: &[u8]) -> Result<Self, CryptoError> {
        let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("tailauth_{prefix}_{pid}_{seq}.tmp"));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| {
                CryptoError::VerifyBackend(format!("create temp file {}: {e}", path.display()))
            })?;
        file.write_all(bytes)
            .and_then(|_| file.flush())
            .map_err(|e| {
                CryptoError::VerifyBackend(format!("write temp file {}: {e}", path.display()))
            })?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(unix)]
impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
fn find_openssl_bin() -> &'static str {
    if Path::new("/usr/bin/openssl").exists() {
        "/usr/bin/openssl"
    } else {
        "openssl"
    }
}

/// Verifies an ASN.1 DER-encoded ECDSA SHA-256 signature against a PEM public key using OpenSSL.
#[cfg(unix)]
pub fn verify_es256_signature(
    public_key_pem: &str,
    message: &[u8],
    der_signature: &[u8],
) -> Result<bool, CryptoError> {
    let pub_file = TempFileGuard::create_private("pub", public_key_pem.as_bytes())?;
    let sig_file = TempFileGuard::create_private("sig", der_signature)?;

    let mut child = Command::new(find_openssl_bin())
        .arg("dgst")
        .arg("-sha256")
        .arg("-verify")
        .arg(pub_file.path())
        .arg("-signature")
        .arg(sig_file.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| CryptoError::VerifyBackend(format!("failed to spawn openssl: {e}")))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(message).map_err(|e| {
            CryptoError::VerifyBackend(format!("failed writing message to openssl: {e}"))
        })?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| CryptoError::VerifyBackend(format!("openssl wait failed: {e}")))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.success() && stdout.contains("Verified OK") {
        Ok(true)
    } else if stdout.contains("Verification failure") || stderr.contains("Verification failure") {
        Ok(false)
    } else if !output.status.success() {
        if stderr.to_ascii_lowercase().contains("error") {
            Ok(false)
        } else {
            Err(CryptoError::VerifyBackend(format!(
                "openssl exited with {}: stdout={:?}, stderr={:?}",
                output.status, stdout, stderr
            )))
        }
    } else {
        Ok(false)
    }
}

/// Verifies an ASN.1 DER-encoded ECDSA SHA-256 signature using native Windows CNG (`bcrypt.dll`).
#[cfg(windows)]
pub fn verify_es256_signature(
    public_key_pem: &str,
    message: &[u8],
    der_signature: &[u8],
) -> Result<bool, CryptoError> {
    use windows_sys::Win32::Security::Cryptography::{
        BCryptCloseAlgorithmProvider, BCryptDestroyKey, BCryptImportKeyPair,
        BCryptOpenAlgorithmProvider, BCryptVerifySignature, BCRYPT_ALG_HANDLE, BCRYPT_ECCKEY_BLOB,
        BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
        BCRYPT_KEY_HANDLE,
    };

    const STATUS_SUCCESS: i32 = 0;
    const STATUS_INVALID_SIGNATURE: i32 = 0xC000_A000u32 as i32;

    struct AlgGuard(BCRYPT_ALG_HANDLE);
    impl Drop for AlgGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    BCryptCloseAlgorithmProvider(self.0, 0);
                }
            }
        }
    }

    struct KeyGuard(BCRYPT_KEY_HANDLE);
    impl Drop for KeyGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    BCryptDestroyKey(self.0);
                }
            }
        }
    }

    let (x, y) = spki_pem_to_p256_xy(public_key_pem)?;
    let raw_sig = match ecdsa_der_to_p1363_64(der_signature) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    let digest = sha256(message);

    let mut alg_handle: BCRYPT_ALG_HANDLE = std::ptr::null_mut();
    let status = unsafe {
        BCryptOpenAlgorithmProvider(
            &mut alg_handle,
            BCRYPT_ECDSA_P256_ALGORITHM,
            std::ptr::null(),
            0,
        )
    };
    if status != STATUS_SUCCESS {
        return Err(CryptoError::VerifyBackend(format!(
            "BCryptOpenAlgorithmProvider failed: 0x{:08x}",
            status as u32
        )));
    }
    let _alg_guard = AlgGuard(alg_handle);

    let header = BCRYPT_ECCKEY_BLOB {
        dwMagic: BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
        cbKey: 32,
    };
    let mut blob = Vec::with_capacity(std::mem::size_of::<BCRYPT_ECCKEY_BLOB>() + 64);
    let header_bytes = unsafe {
        std::slice::from_raw_parts(
            (&header as *const BCRYPT_ECCKEY_BLOB) as *const u8,
            std::mem::size_of::<BCRYPT_ECCKEY_BLOB>(),
        )
    };
    blob.extend_from_slice(header_bytes);
    blob.extend_from_slice(&x);
    blob.extend_from_slice(&y);

    let mut key_handle: BCRYPT_KEY_HANDLE = std::ptr::null_mut();
    let status = unsafe {
        BCryptImportKeyPair(
            alg_handle,
            std::ptr::null_mut(),
            BCRYPT_ECCPUBLIC_BLOB,
            &mut key_handle,
            blob.as_mut_ptr(),
            blob.len() as u32,
            0,
        )
    };
    if status != STATUS_SUCCESS {
        return Err(CryptoError::VerifyBackend(format!(
            "BCryptImportKeyPair failed: 0x{:08x}",
            status as u32
        )));
    }
    let _key_guard = KeyGuard(key_handle);

    let status = unsafe {
        BCryptVerifySignature(
            key_handle,
            std::ptr::null(),
            digest.as_ptr(),
            digest.len() as u32,
            raw_sig.as_ptr(),
            raw_sig.len() as u32,
            0,
        )
    };

    match status {
        STATUS_SUCCESS => Ok(true),
        STATUS_INVALID_SIGNATURE => Ok(false),
        other => Err(CryptoError::VerifyBackend(format!(
            "BCryptVerifySignature failed: 0x{:08x}",
            other as u32
        ))),
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;

    /// Generates an ephemeral P-256 keypair via OpenSSL and returns `(priv_pem, pub_pem, pub_spki_der, x, y)`.
    #[cfg(unix)]
    pub fn generate_p256_keypair() -> (String, String, Vec<u8>, [u8; 32], [u8; 32]) {
        let priv_guard = TempFileGuard::create_private("test_priv", b"").unwrap();
        let pub_guard = TempFileGuard::create_private("test_pub", b"").unwrap();
        let der_guard = TempFileGuard::create_private("test_der", b"").unwrap();

        let status = Command::new(find_openssl_bin())
            .args([
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
            ])
            .arg(priv_guard.path())
            .status()
            .unwrap();
        assert!(status.success(), "openssl ecparam failed");

        let status = Command::new(find_openssl_bin())
            .args(["pkey", "-in"])
            .arg(priv_guard.path())
            .args(["-pubout", "-out"])
            .arg(pub_guard.path())
            .status()
            .unwrap();
        assert!(status.success(), "openssl pkey -pubout failed");

        let status = Command::new(find_openssl_bin())
            .args(["pkey", "-pubin", "-in"])
            .arg(pub_guard.path())
            .args(["-outform", "DER", "-out"])
            .arg(der_guard.path())
            .status()
            .unwrap();
        assert!(status.success(), "openssl pkey -outform DER failed");

        let priv_pem = fs::read_to_string(priv_guard.path()).unwrap();
        let pub_pem = fs::read_to_string(pub_guard.path()).unwrap();
        let spki_der = fs::read(der_guard.path()).unwrap();
        assert_eq!(spki_der.len(), 91);
        assert_eq!(spki_der[26], 0x04);
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&spki_der[27..59]);
        y.copy_from_slice(&spki_der[59..91]);
        (priv_pem, pub_pem, spki_der, x, y)
    }

    /// Signs a message with an EC P-256 private PEM key via OpenSSL and returns the DER signature.
    #[cfg(unix)]
    pub fn sign_es256(priv_pem: &str, message: &[u8]) -> Vec<u8> {
        let priv_guard =
            TempFileGuard::create_private("test_sign_priv", priv_pem.as_bytes()).unwrap();
        let sig_guard = TempFileGuard::create_private("test_sign_sig", b"").unwrap();

        let mut child = Command::new(find_openssl_bin())
            .args(["dgst", "-sha256", "-sign"])
            .arg(priv_guard.path())
            .arg("-out")
            .arg(sig_guard.path())
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(message).unwrap();
        let status = child.wait().unwrap();
        assert!(status.success(), "openssl sign failed");
        fs::read(sig_guard.path()).unwrap()
    }

    /// Builds a valid COSE_Key CBOR map for an ES256 P-256 public key.
    #[cfg(unix)]
    pub fn encode_cose_p256_key(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
        let mut out = vec![0xa5];
        out.extend_from_slice(&[0x01, 0x02]);
        out.extend_from_slice(&[0x03, 0x26]);
        out.extend_from_slice(&[0x20, 0x01]);
        out.extend_from_slice(&[0x21, 0x58, 0x20]);
        out.extend_from_slice(x);
        out.extend_from_slice(&[0x22, 0x58, 0x20]);
        out.extend_from_slice(y);
        out
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::test_helpers::*;
    use super::*;

    #[test]
    fn sha256_nist_vectors() {
        let empty = sha256(b"");
        assert_eq!(
            empty
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let abc = sha256(b"abc");
        assert_eq!(
            abc.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cose_p256_conversion_matches_openssl_spki() {
        let (_priv_pem, pub_pem, expected_der, x, y) = generate_p256_keypair();
        let cose = encode_cose_p256_key(&x, &y);
        let derived_der = cose_p256_to_spki_der(&cose).unwrap();
        assert_eq!(derived_der, expected_der);
        let derived_pem = spki_der_to_pem(&derived_der);
        assert_eq!(derived_pem, pub_pem);

        let (parsed_x, parsed_y) = spki_pem_to_p256_xy(&derived_pem).unwrap();
        assert_eq!(parsed_x, x);
        assert_eq!(parsed_y, y);
    }

    #[cfg(unix)]
    #[test]
    fn es256_verification_accepts_valid_and_rejects_tampered() {
        let (priv_pem, pub_pem, _, _, _) = generate_p256_keypair();
        let (_other_priv, other_pub, _, _, _) = generate_p256_keypair();

        let msg = b"tailauth-authenticator-data-plus-client-hash";
        let sig = sign_es256(&priv_pem, msg);

        assert!(verify_es256_signature(&pub_pem, msg, &sig).unwrap());
        assert!(!verify_es256_signature(&pub_pem, b"tampered-message", &sig).unwrap());
        assert!(!verify_es256_signature(&other_pub, msg, &sig).unwrap());

        let p1363 = ecdsa_der_to_p1363_64(&sig).unwrap();
        assert_eq!(p1363.len(), 64);
    }

    #[test]
    fn der_to_p1363_handles_padding_and_rejects_malformed() {
        // r = 0x80.. (33 bytes with 0x00 prefix), s = 0x01 (1 byte) => 35 + 3 = 38 (0x26)
        let mut valid_der = vec![0x30, 0x26, 0x02, 0x21, 0x00, 0x80];
        valid_der.extend_from_slice(&[0x11; 31]);
        valid_der.extend_from_slice(&[0x02, 0x01, 0x01]);
        let p1363 = ecdsa_der_to_p1363_64(&valid_der).unwrap();
        assert_eq!(p1363[0], 0x80);
        assert_eq!(p1363[1..32], [0x11; 31]);
        assert_eq!(p1363[32..63], [0x00; 31]);
        assert_eq!(p1363[63], 0x01);

        // Trailing bytes rejected
        let mut trailing = valid_der.clone();
        trailing.push(0x00);
        assert!(ecdsa_der_to_p1363_64(&trailing).is_err());

        // Negative integer rejected
        let neg = [0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01];
        assert!(ecdsa_der_to_p1363_64(&neg).is_err());

        // Oversized (>32 bytes without leading 0x00) rejected
        let mut big = vec![0x30, 0x26, 0x02, 0x21];
        big.extend_from_slice(&[0x01; 33]);
        big.extend_from_slice(&[0x02, 0x01, 0x01]);
        assert!(ecdsa_der_to_p1363_64(&big).is_err());

        // Zero scalar rejected
        let zero = [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01];
        assert!(ecdsa_der_to_p1363_64(&zero).is_err());
    }
}
