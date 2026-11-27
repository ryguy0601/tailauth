use crate::crypto::{
    b64url_decode, b64url_encode, cbor_map_get_text, cose_p256_to_spki_der, decode_cbor_exact,
    decode_cbor_prefix, sha256, spki_der_to_pem, verify_es256_signature, CborValue, CryptoError,
};
use serde::Deserialize;
use thiserror::Error;

const FLAG_UP: u8 = 0x01; // User Present
const FLAG_UV: u8 = 0x04; // User Verified (biometric / device PIN)
const FLAG_AT: u8 = 0x40; // Attested Credential Data included

#[derive(Debug, Error)]
pub enum WebAuthnError {
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("invalid clientDataJSON: {0}")]
    ClientData(String),
    #[error("invalid attestationObject: {0}")]
    Attestation(String),
    #[error("invalid authenticatorData: {0}")]
    AuthenticatorData(String),
    #[error("user verification flag (UV) was not set by the phone authenticator")]
    UserNotVerified,
    #[error("origin mismatch: expected {expected}, got {actual}")]
    OriginMismatch { expected: String, actual: String },
    #[error("challenge mismatch")]
    ChallengeMismatch,
    #[error("rpIdHash mismatch")]
    RpIdMismatch,
    #[error("signature counter regression: stored {stored}, got {got}")]
    SignCountRegression { stored: u32, got: u32 },
    #[error("invalid signature")]
    InvalidSignature,
}

#[derive(Debug, Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
}

#[derive(Debug, Clone)]
pub struct VerifiedRegistration {
    pub credential_id_b64url: String,
    pub public_key_pem: String,
    pub sign_count: u32,
}

fn verify_client_data(
    client_data_json_b64url: &str,
    expected_type: &str,
    expected_challenge: &str,
    expected_origin: &str,
) -> Result<Vec<u8>, WebAuthnError> {
    let raw_bytes = b64url_decode(client_data_json_b64url)?;
    let parsed: ClientData = serde_json::from_slice(&raw_bytes)
        .map_err(|e| WebAuthnError::ClientData(format!("JSON parse failed: {e}")))?;

    if parsed.kind != expected_type {
        return Err(WebAuthnError::ClientData(format!(
            "expected type {expected_type}, got {}",
            parsed.kind
        )));
    }
    if parsed.challenge != expected_challenge {
        return Err(WebAuthnError::ChallengeMismatch);
    }
    if parsed.origin != expected_origin {
        return Err(WebAuthnError::OriginMismatch {
            expected: expected_origin.to_string(),
            actual: parsed.origin,
        });
    }

    Ok(raw_bytes)
}

/// Verifies a WebAuthn `navigator.credentials.create` registration payload and returns
/// the verified credential ID, SPKI PEM public key, and initial signature counter.
pub fn verify_registration(
    rp_id: &str,
    expected_origin: &str,
    expected_challenge_b64url: &str,
    client_data_json_b64url: &str,
    attestation_object_b64url: &str,
    optional_public_key_spki_b64url: Option<&str>,
) -> Result<VerifiedRegistration, WebAuthnError> {
    verify_client_data(
        client_data_json_b64url,
        "webauthn.create",
        expected_challenge_b64url,
        expected_origin,
    )?;

    let att_bytes = b64url_decode(attestation_object_b64url)?;
    let att_cbor = decode_cbor_exact(&att_bytes)?;
    let att_map = att_cbor
        .as_map()
        .ok_or_else(|| WebAuthnError::Attestation("attestationObject must be a CBOR map".into()))?;

    let auth_data = cbor_map_get_text(att_map, "authData")
        .and_then(CborValue::as_bytes)
        .ok_or_else(|| WebAuthnError::Attestation("missing authData in attestationObject".into()))?;

    if auth_data.len() < 55 {
        return Err(WebAuthnError::AuthenticatorData(format!(
            "authData too short for attested credential: {}",
            auth_data.len()
        )));
    }

    let expected_rp_hash = sha256(rp_id.as_bytes());
    if auth_data[..32] != expected_rp_hash {
        return Err(WebAuthnError::RpIdMismatch);
    }

    let flags = auth_data[32];
    if (flags & FLAG_UP) == 0 {
        return Err(WebAuthnError::AuthenticatorData(
            "user presence flag (UP) not set".into(),
        ));
    }
    if (flags & FLAG_UV) == 0 {
        return Err(WebAuthnError::UserNotVerified);
    }
    if (flags & FLAG_AT) == 0 {
        return Err(WebAuthnError::Attestation(
            "attested credential data flag (AT) not set".into(),
        ));
    }

    let sign_count = u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);

    // Bytes 37..53 are AAGUID (16 bytes). Bytes 53..55 are credentialIdLength (big-endian u16).
    let cred_id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    if cred_id_len == 0 || 55 + cred_id_len > auth_data.len() {
        return Err(WebAuthnError::Attestation(format!(
            "invalid credentialIdLength {cred_id_len}"
        )));
    }

    let cred_id = &auth_data[55..55 + cred_id_len];
    let cose_slice = &auth_data[55 + cred_id_len..];
    if cose_slice.is_empty() {
        return Err(WebAuthnError::Attestation(
            "missing COSE public key in authData".into(),
        ));
    }

    // authData may include extensions after the COSE key, so parse the prefix of the COSE map.
    let (_cose_val, cose_consumed) = decode_cbor_prefix(cose_slice)?;
    let spki_der = cose_p256_to_spki_der(&cose_slice[..cose_consumed])?;

    if let Some(browser_spki_b64) = optional_public_key_spki_b64url {
        let browser_spki = b64url_decode(browser_spki_b64)?;
        if browser_spki != spki_der {
            return Err(WebAuthnError::Attestation(
                "browser getPublicKey() SPKI bytes do not match COSE key".into(),
            ));
        }
    }

    Ok(VerifiedRegistration {
        credential_id_b64url: b64url_encode(cred_id),
        public_key_pem: spki_der_to_pem(&spki_der),
        sign_count,
    })
}

/// Verifies a WebAuthn `navigator.credentials.get` assertion against a stored credential.
/// Returns the updated `sign_count` on success.
pub fn verify_assertion(
    rp_id: &str,
    expected_origin: &str,
    expected_challenge_b64url: &str,
    stored_public_key_pem: &str,
    stored_sign_count: u32,
    client_data_json_b64url: &str,
    authenticator_data_b64url: &str,
    signature_b64url: &str,
) -> Result<u32, WebAuthnError> {
    let raw_client_data = verify_client_data(
        client_data_json_b64url,
        "webauthn.get",
        expected_challenge_b64url,
        expected_origin,
    )?;

    let auth_data = b64url_decode(authenticator_data_b64url)?;
    if auth_data.len() < 37 {
        return Err(WebAuthnError::AuthenticatorData(format!(
            "authenticatorData too short: {}",
            auth_data.len()
        )));
    }

    let expected_rp_hash = sha256(rp_id.as_bytes());
    if auth_data[..32] != expected_rp_hash {
        return Err(WebAuthnError::RpIdMismatch);
    }

    let flags = auth_data[32];
    if (flags & FLAG_UP) == 0 {
        return Err(WebAuthnError::AuthenticatorData(
            "user presence flag (UP) not set".into(),
        ));
    }
    if (flags & FLAG_UV) == 0 {
        return Err(WebAuthnError::UserNotVerified);
    }

    let new_sign_count =
        u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    if (stored_sign_count > 0 || new_sign_count > 0) && new_sign_count <= stored_sign_count {
        return Err(WebAuthnError::SignCountRegression {
            stored: stored_sign_count,
            got: new_sign_count,
        });
    }

    let signature_der = b64url_decode(signature_b64url)?;
    let client_data_hash = sha256(&raw_client_data);
    let mut signed_data = Vec::with_capacity(auth_data.len() + 32);
    signed_data.extend_from_slice(&auth_data);
    signed_data.extend_from_slice(&client_data_hash);

    if !verify_es256_signature(stored_public_key_pem, &signed_data, &signature_der)? {
        return Err(WebAuthnError::InvalidSignature);
    }

    Ok(new_sign_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_helpers::{encode_cose_p256_key, generate_p256_keypair, sign_es256};

    fn encode_cbor_bstr(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        if bytes.len() < 24 {
            out.push(0x40 | (bytes.len() as u8));
        } else if bytes.len() < 256 {
            out.push(0x58);
            out.push(bytes.len() as u8);
        } else {
            out.push(0x59);
            out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(bytes);
        out
    }

    fn build_attestation_object(rp_id: &str, flags: u8, cred_id: &[u8], cose_key: &[u8]) -> Vec<u8> {
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&sha256(rp_id.as_bytes()));
        auth_data.push(flags);
        auth_data.extend_from_slice(&1u32.to_be_bytes()); // signCount = 1
        auth_data.extend_from_slice(&[0xaa; 16]); // AAGUID
        auth_data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(cred_id);
        auth_data.extend_from_slice(cose_key);

        // CBOR map {"fmt": "none", "authData": bstr}
        let mut att = vec![0xa2];
        att.extend_from_slice(&[0x63]);
        att.extend_from_slice(b"fmt");
        att.extend_from_slice(&[0x64]);
        att.extend_from_slice(b"none");
        att.extend_from_slice(&[0x68]);
        att.extend_from_slice(b"authData");
        att.extend_from_slice(&encode_cbor_bstr(&auth_data));
        att
    }

    fn build_assertion_payload(
        rp_id: &str,
        origin: &str,
        challenge: &str,
        flags: u8,
        sign_count: u32,
        priv_pem: &str,
    ) -> (String, String, String) {
        let client_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{origin}","crossOrigin":false}}"#
        );
        let client_b64 = b64url_encode(client_json.as_bytes());

        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&sha256(rp_id.as_bytes()));
        auth_data.push(flags);
        auth_data.extend_from_slice(&sign_count.to_be_bytes());
        let auth_b64 = b64url_encode(&auth_data);

        let mut signed = Vec::new();
        signed.extend_from_slice(&auth_data);
        signed.extend_from_slice(&sha256(client_json.as_bytes()));
        let sig = sign_es256(priv_pem, &signed);
        let sig_b64 = b64url_encode(&sig);
        (client_b64, auth_b64, sig_b64)
    }

    #[test]
    fn registration_and_assertion_happy_path_and_failures() {
        let rp_id = "box.tailnet.ts.net";
        let origin_8443 = "https://box.tailnet.ts.net:8443";
        let reg_challenge = "reg-challenge-123";
        let cred_id = b"test-credential-id-001";

        let (priv_pem, pub_pem, spki_der, x, y) = generate_p256_keypair();
        let cose = encode_cose_p256_key(&x, &y);
        let att_obj = build_attestation_object(rp_id, FLAG_UP | FLAG_UV | FLAG_AT, cred_id, &cose);
        let client_reg = format!(
            r#"{{"type":"webauthn.create","challenge":"{reg_challenge}","origin":"{origin_8443}"}}"#
        );

        let verified = verify_registration(
            rp_id,
            origin_8443,
            reg_challenge,
            &b64url_encode(client_reg.as_bytes()),
            &b64url_encode(&att_obj),
            Some(&b64url_encode(&spki_der)),
        )
        .unwrap();
        assert_eq!(verified.credential_id_b64url, b64url_encode(cred_id));
        assert_eq!(verified.public_key_pem, pub_pem);
        assert_eq!(verified.sign_count, 1);

        // UV=0 must be rejected during registration
        let att_no_uv = build_attestation_object(rp_id, FLAG_UP | FLAG_AT, cred_id, &cose);
        let err = verify_registration(
            rp_id,
            origin_8443,
            reg_challenge,
            &b64url_encode(client_reg.as_bytes()),
            &b64url_encode(&att_no_uv),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, WebAuthnError::UserNotVerified));

        // Happy-path assertion on port 8443
        let auth_challenge = "auth-challenge-456";
        let (cd, ad, sig) = build_assertion_payload(
            rp_id,
            origin_8443,
            auth_challenge,
            FLAG_UP | FLAG_UV,
            2,
            &priv_pem,
        );
        let new_cnt = verify_assertion(
            rp_id,
            origin_8443,
            auth_challenge,
            &verified.public_key_pem,
            1,
            &cd,
            &ad,
            &sig,
        )
        .unwrap();
        assert_eq!(new_cnt, 2);

        // Port 443 origin omits :443
        let origin_443 = "https://box.tailnet.ts.net";
        let (cd_443, ad_443, sig_443) = build_assertion_payload(
            rp_id,
            origin_443,
            auth_challenge,
            FLAG_UP | FLAG_UV,
            3,
            &priv_pem,
        );
        assert_eq!(
            verify_assertion(
                rp_id,
                origin_443,
                auth_challenge,
                &verified.public_key_pem,
                2,
                &cd_443,
                &ad_443,
                &sig_443,
            )
            .unwrap(),
            3
        );

        // Wrong origin rejected
        let err = verify_assertion(
            rp_id,
            "https://evil.tailnet.ts.net:8443",
            auth_challenge,
            &verified.public_key_pem,
            2,
            &cd,
            &ad,
            &sig,
        )
        .unwrap_err();
        assert!(matches!(err, WebAuthnError::OriginMismatch { .. }));

        // Wrong challenge rejected
        let err = verify_assertion(
            rp_id,
            origin_8443,
            "different-challenge",
            &verified.public_key_pem,
            2,
            &cd,
            &ad,
            &sig,
        )
        .unwrap_err();
        assert!(matches!(err, WebAuthnError::ChallengeMismatch));

        // Wrong rpIdHash rejected
        let err = verify_assertion(
            "other.tailnet.ts.net",
            origin_8443,
            auth_challenge,
            &verified.public_key_pem,
            2,
            &cd,
            &ad,
            &sig,
        )
        .unwrap_err();
        assert!(matches!(err, WebAuthnError::RpIdMismatch));

        // UV=0 rejected on assertion
        let (cd_nouv, ad_nouv, sig_nouv) =
            build_assertion_payload(rp_id, origin_8443, auth_challenge, FLAG_UP, 3, &priv_pem);
        let err = verify_assertion(
            rp_id,
            origin_8443,
            auth_challenge,
            &verified.public_key_pem,
            2,
            &cd_nouv,
            &ad_nouv,
            &sig_nouv,
        )
        .unwrap_err();
        assert!(matches!(err, WebAuthnError::UserNotVerified));

        // SignCount regression rejected (stored=2, got=2)
        let err = verify_assertion(
            rp_id,
            origin_8443,
            auth_challenge,
            &verified.public_key_pem,
            2,
            &cd,
            &ad,
            &sig,
        )
        .unwrap_err();
        assert!(matches!(err, WebAuthnError::SignCountRegression { .. }));

        // Synced passkey signCount 0 -> 0 is allowed per WebAuthn spec
        let (cd_zero, ad_zero, sig_zero) = build_assertion_payload(
            rp_id,
            origin_8443,
            auth_challenge,
            FLAG_UP | FLAG_UV,
            0,
            &priv_pem,
        );
        assert_eq!(
            verify_assertion(
                rp_id,
                origin_8443,
                auth_challenge,
                &verified.public_key_pem,
                0,
                &cd_zero,
                &ad_zero,
                &sig_zero,
            )
            .unwrap(),
            0
        );
    }
}
