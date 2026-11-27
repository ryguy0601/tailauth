use crate::config::Config;
#[cfg(windows)]
use crate::crypto::b64url_encode;
use crate::crypto::random_b64url;
use crate::protocol::{ClientRequest, CredentialSummary, ServerEvent};
use crate::store::{now_unix_secs, user_matches, CredentialRecord, CredentialStore};
use crate::webauthn::{verify_assertion, verify_registration};
use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{oneshot, Mutex};

const AUTH_HTML: &str = include_str!("web/auth.html");
const ENROLL_HTML: &str = include_str!("web/enroll.html");
const ENROLL_TIMEOUT_SECS: u64 = 180;

#[derive(Debug)]
enum AuthOutcome {
    Approved {
        label: String,
        tailscale_user: Option<String>,
    },
    Denied,
    Timeout,
}

#[derive(Debug)]
enum EnrollOutcome {
    Enrolled {
        id: String,
        label: String,
        tailscale_user: Option<String>,
    },
    Timeout,
}

struct AuthSession {
    challenge: String,
    user: String,
    service: String,
    allow_credentials: Vec<String>,
    expires_at: Instant,
    responder: Option<oneshot::Sender<AuthOutcome>>,
}

struct EnrollSession {
    challenge: String,
    user: String,
    expires_at: Instant,
    responder: Option<oneshot::Sender<EnrollOutcome>>,
}

pub struct AppState {
    pub config: Config,
    pub hostname: String,
    pub store: Mutex<CredentialStore>,
    auth_sessions: Mutex<HashMap<String, AuthSession>>,
    enroll_sessions: Mutex<HashMap<String, EnrollSession>>,
}

impl AppState {
    pub fn new(config: Config, store: CredentialStore) -> Self {
        let hostname = read_hostname(&config);
        Self {
            config,
            hostname,
            store: Mutex::new(store),
            auth_sessions: Mutex::new(HashMap::new()),
            enroll_sessions: Mutex::new(HashMap::new()),
        }
    }

    pub async fn prune_expired(&self) {
        let now = Instant::now();
        {
            let mut sessions = self.auth_sessions.lock().await;
            let expired: Vec<String> = sessions
                .iter()
                .filter(|(_, s)| s.expires_at <= now)
                .map(|(k, _)| k.clone())
                .collect();
            for key in expired {
                if let Some(mut s) = sessions.remove(&key) {
                    if let Some(tx) = s.responder.take() {
                        let _ = tx.send(AuthOutcome::Timeout);
                    }
                }
            }
        }
        {
            let mut sessions = self.enroll_sessions.lock().await;
            let expired: Vec<String> = sessions
                .iter()
                .filter(|(_, s)| s.expires_at <= now)
                .map(|(k, _)| k.clone())
                .collect();
            for key in expired {
                if let Some(mut s) = sessions.remove(&key) {
                    if let Some(tx) = s.responder.take() {
                        let _ = tx.send(EnrollOutcome::Timeout);
                    }
                }
            }
        }
    }
}

fn read_hostname(config: &Config) -> String {
    #[cfg(windows)]
    if let Ok(name) = std::env::var("COMPUTERNAME") {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Ok(name) = fs::read_to_string("/etc/hostname") {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    config
        .rp_id()
        .split('.')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("localhost")
        .to_string()
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/auth/{token}", get(auth_page_handler))
        .route("/api/auth/{token}/options", get(auth_options_handler))
        .route("/api/auth/{token}/verify", post(auth_verify_handler))
        .route("/api/auth/{token}/deny", post(auth_deny_handler))
        .route("/enroll/{token}", get(enroll_page_handler))
        .route("/api/enroll/{token}/options", get(enroll_options_handler))
        .route("/api/enroll/{token}/complete", post(enroll_complete_handler))
        .with_state(state)
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

fn json_error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(ErrorBody { error: msg.into() })).into_response()
}

fn extract_tailscale_user(headers: &HeaderMap) -> Option<String> {
    headers
        .get("tailscale-user-login")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

fn check_allowed_tailscale_user(config: &Config, headers: &HeaderMap) -> Result<Option<String>, Response> {
    let ts_user = extract_tailscale_user(headers);
    if !config.allowed_tailscale_users.is_empty() {
        match &ts_user {
            Some(login)
                if config
                    .allowed_tailscale_users
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(login)) => {}
            Some(login) => {
                return Err(json_error(
                    StatusCode::FORBIDDEN,
                    format!("tailscale user '{login}' is not authorized"),
                ));
            }
            None => {
                return Err(json_error(
                    StatusCode::FORBIDDEN,
                    "missing Tailscale-User-Login identity header",
                ));
            }
        }
    }
    Ok(ts_user)
}

async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true, "service": "tailauth" }))
}

async fn auth_page_handler() -> Html<&'static str> {
    Html(AUTH_HTML)
}

async fn enroll_page_handler() -> Html<&'static str> {
    Html(ENROLL_HTML)
}

#[derive(Serialize)]
struct AuthOptionsResponse {
    challenge: String,
    rp_id: String,
    user: String,
    hostname: String,
    service: String,
    allow_credentials: Vec<String>,
    remaining_secs: u64,
}

async fn auth_options_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(token): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = check_allowed_tailscale_user(&state.config, &headers) {
        return resp;
    }

    let now = Instant::now();
    let mut sessions = state.auth_sessions.lock().await;
    let Some(session) = sessions.get(&token) else {
        return json_error(StatusCode::NOT_FOUND, "session not found or already closed");
    };
    if session.expires_at <= now {
        if let Some(mut expired) = sessions.remove(&token) {
            if let Some(tx) = expired.responder.take() {
                let _ = tx.send(AuthOutcome::Timeout);
            }
        }
        return json_error(StatusCode::GONE, "session expired");
    }

    let remaining_secs = session.expires_at.saturating_duration_since(now).as_secs().max(1);
    Json(AuthOptionsResponse {
        challenge: session.challenge.clone(),
        rp_id: state.config.rp_id().to_string(),
        user: session.user.clone(),
        hostname: state.hostname.clone(),
        service: session.service.clone(),
        allow_credentials: session.allow_credentials.clone(),
        remaining_secs,
    })
    .into_response()
}

#[derive(Deserialize)]
struct AuthVerifyRequest {
    id: String,
    #[serde(rename = "authenticatorData")]
    authenticator_data: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    signature: String,
}

async fn auth_verify_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(token): AxumPath<String>,
    headers: HeaderMap,
    Json(payload): Json<AuthVerifyRequest>,
) -> Response {
    let ts_user = match check_allowed_tailscale_user(&state.config, &headers) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    // Atomically remove the session so each challenge token is strictly single-use.
    let mut session = {
        let mut sessions = state.auth_sessions.lock().await;
        match sessions.remove(&token) {
            Some(s) => s,
            None => return json_error(StatusCode::NOT_FOUND, "session not found or already used"),
        }
    };

    if session.expires_at <= Instant::now() {
        if let Some(tx) = session.responder.take() {
            let _ = tx.send(AuthOutcome::Timeout);
        }
        return json_error(StatusCode::GONE, "session expired");
    }

    let verify_result: Result<(String, u32), (StatusCode, String)> = {
        let store = state.store.lock().await;
        let creds = store.get_user_credentials(&session.user);
        let Some(cred) = creds.iter().find(|c| c.id == payload.id) else {
            drop(store);
            if let Some(tx) = session.responder.take() {
                let _ = tx.send(AuthOutcome::Denied);
            }
            return json_error(StatusCode::FORBIDDEN, "unknown credential id");
        };

        match verify_assertion(
            state.config.rp_id(),
            &state.config.expected_origin(),
            &session.challenge,
            &cred.public_key_pem,
            cred.sign_count,
            &payload.client_data_json,
            &payload.authenticator_data,
            &payload.signature,
        ) {
            Ok(new_sign_count) => Ok((cred.label.clone(), new_sign_count)),
            Err(err) => Err((StatusCode::FORBIDDEN, err.to_string())),
        }
    };

    match verify_result {
        Ok((label, new_sign_count)) => {
            {
                let mut store = state.store.lock().await;
                if store.update_sign_count(&session.user, &payload.id, new_sign_count) {
                    if let Err(e) = store.save(Path::new(&state.config.store_path)) {
                        eprintln!("tailauth: warning: failed to save updated sign_count: {e}");
                    }
                }
            }
            if let Some(tx) = session.responder.take() {
                let _ = tx.send(AuthOutcome::Approved {
                    label,
                    tailscale_user: ts_user,
                });
            }
            Json(serde_json::json!({ "ok": true })).into_response()
        }
        Err((status, msg)) => {
            if let Some(tx) = session.responder.take() {
                let _ = tx.send(AuthOutcome::Denied);
            }
            json_error(status, msg)
        }
    }
}

async fn auth_deny_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(token): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = check_allowed_tailscale_user(&state.config, &headers) {
        return resp;
    }

    let mut session = {
        let mut sessions = state.auth_sessions.lock().await;
        match sessions.remove(&token) {
            Some(s) => s,
            None => return json_error(StatusCode::NOT_FOUND, "session not found"),
        }
    };

    if let Some(tx) = session.responder.take() {
        let _ = tx.send(AuthOutcome::Denied);
    }
    Json(serde_json::json!({ "ok": true })).into_response()
}

#[derive(Serialize)]
struct EnrollOptionsResponse {
    challenge: String,
    rp_id: String,
    user: String,
    hostname: String,
}

async fn enroll_options_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(token): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = check_allowed_tailscale_user(&state.config, &headers) {
        return resp;
    }

    let now = Instant::now();
    let mut sessions = state.enroll_sessions.lock().await;
    let Some(session) = sessions.get(&token) else {
        return json_error(StatusCode::NOT_FOUND, "enrollment session not found");
    };
    if session.expires_at <= now {
        if let Some(mut expired) = sessions.remove(&token) {
            if let Some(tx) = expired.responder.take() {
                let _ = tx.send(EnrollOutcome::Timeout);
            }
        }
        return json_error(StatusCode::GONE, "enrollment session expired");
    }

    Json(EnrollOptionsResponse {
        challenge: session.challenge.clone(),
        rp_id: state.config.rp_id().to_string(),
        user: session.user.clone(),
        hostname: state.hostname.clone(),
    })
    .into_response()
}

#[derive(Deserialize)]
struct EnrollCompleteRequest {
    id: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "attestationObject")]
    attestation_object: String,
    #[serde(rename = "publicKeySpki")]
    public_key_spki: Option<String>,
    label: Option<String>,
}

async fn enroll_complete_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(token): AxumPath<String>,
    headers: HeaderMap,
    Json(payload): Json<EnrollCompleteRequest>,
) -> Response {
    let ts_user = match check_allowed_tailscale_user(&state.config, &headers) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let mut session = {
        let mut sessions = state.enroll_sessions.lock().await;
        match sessions.remove(&token) {
            Some(s) => s,
            None => return json_error(StatusCode::NOT_FOUND, "enrollment session not found or already used"),
        }
    };

    if session.expires_at <= Instant::now() {
        if let Some(tx) = session.responder.take() {
            let _ = tx.send(EnrollOutcome::Timeout);
        }
        return json_error(StatusCode::GONE, "enrollment session expired");
    }

    let verified = match verify_registration(
        state.config.rp_id(),
        &state.config.expected_origin(),
        &session.challenge,
        &payload.client_data_json,
        &payload.attestation_object,
        payload.public_key_spki.as_deref(),
    ) {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e.to_string()),
    };

    if !payload.id.is_empty() && payload.id != verified.credential_id_b64url {
        return json_error(StatusCode::BAD_REQUEST, "credential id mismatch");
    }

    let label = payload
        .label
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("Phone")
        .to_string();

    let record = CredentialRecord {
        id: verified.credential_id_b64url.clone(),
        public_key_pem: verified.public_key_pem,
        sign_count: verified.sign_count,
        label: label.clone(),
        tailscale_user: ts_user.clone(),
        created_at_unix: now_unix_secs(),
    };

    {
        let mut store = state.store.lock().await;
        store.add_credential(&session.user, record);
        if let Err(e) = store.save(Path::new(&state.config.store_path)) {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to save credential: {e}"),
            );
        }
    }

    if let Some(tx) = session.responder.take() {
        let _ = tx.send(EnrollOutcome::Enrolled {
            id: verified.credential_id_b64url.clone(),
            label,
            tailscale_user: ts_user,
        });
    }

    Json(serde_json::json!({
        "ok": true,
        "id": verified.credential_id_b64url
    }))
    .into_response()
}

async fn send_event<W: AsyncWriteExt + Unpin>(writer: &mut W, event: &ServerEvent) -> std::io::Result<()> {
    let mut line = serde_json::to_string(event).unwrap_or_else(|_| {
        r#"{"type":"error","message":"serialization error"}"#.to_string()
    });
    line.push('\n');
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await
}

async fn read_until_cancel_or_eof<R: AsyncBufReadExt + Unpin>(reader: &mut R) {
    let mut buf = [0u8; 64];
    match tokio::io::AsyncReadExt::read(reader, &mut buf).await {
        Ok(0) | Ok(_) | Err(_) => {}
    }
}

pub struct CallerContext {
    pub is_admin: bool,
    #[cfg(windows)]
    pub verified_user: Option<String>,
    #[cfg(windows)]
    pub elevated_token: Option<crate::win::OwnedHandle>,
}

#[cfg(unix)]
pub async fn handle_unix_client(stream: UnixStream, state: Arc<AppState>) {
    handle_ipc_stream(stream, state, CallerContext { is_admin: true }).await;
}

pub async fn handle_ipc_stream<S>(stream: S, state: Arc<AppState>, caller: CallerContext)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    match reader.read_line(&mut line).await {
        Ok(0) | Err(_) => return,
        Ok(_) => {}
    }

    let req: ClientRequest = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => {
            let _ = send_event(
                &mut write_half,
                &ServerEvent::Error {
                    message: format!("invalid request: {e}"),
                },
            )
            .await;
            return;
        }
    };

    match req {
        ClientRequest::StartAuth { user, ruser: _, service } => {
            #[cfg(windows)]
            let target_user = if !caller.is_admin {
                caller.verified_user.clone().unwrap_or(user)
            } else {
                user
            };
            #[cfg(not(windows))]
            let target_user = user;

            let service_name = service
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("sudo")
                .to_string();

            let allow_credentials: Vec<String> = {
                let store = state.store.lock().await;
                store
                    .get_user_credentials(&target_user)
                    .iter()
                    .map(|c| c.id.clone())
                    .collect()
            };

            if allow_credentials.is_empty() {
                eprintln!(
                    "tailauth: auth skipped for '{target_user}' ({service_name}): no enrolled credentials"
                );
                let _ = send_event(&mut write_half, &ServerEvent::NoCredentials).await;
                return;
            }

            let token = random_b64url(24);
            let challenge = random_b64url(32);
            let timeout_secs = state.config.timeout_secs;
            let (tx, rx) = oneshot::channel();

            {
                let mut sessions = state.auth_sessions.lock().await;
                sessions.insert(
                    token.clone(),
                    AuthSession {
                        challenge,
                        user: target_user.clone(),
                        service: service_name.clone(),
                        allow_credentials,
                        expires_at: Instant::now() + Duration::from_secs(timeout_secs),
                        responder: Some(tx),
                    },
                );
            }

            eprintln!("tailauth: auth started for '{target_user}' ({service_name})");

            let url = format!("{}/auth/{}", state.config.base_url(), token);
            if send_event(
                &mut write_half,
                &ServerEvent::Pending {
                    token: token.clone(),
                    url,
                    timeout_secs,
                },
            )
            .await
            .is_err()
            {
                state.auth_sessions.lock().await.remove(&token);
                eprintln!("tailauth: auth cancelled for '{target_user}' (socket write failed)");
                return;
            }

            let outcome = tokio::select! {
                res = rx => res.unwrap_or(AuthOutcome::Timeout),
                _ = tokio::time::sleep(Duration::from_secs(timeout_secs)) => {
                    state.auth_sessions.lock().await.remove(&token);
                    AuthOutcome::Timeout
                }
                _ = read_until_cancel_or_eof(&mut reader) => {
                    state.auth_sessions.lock().await.remove(&token);
                    eprintln!("tailauth: auth cancelled by client for '{target_user}'");
                    return;
                }
            };

            let event = match outcome {
                AuthOutcome::Approved {
                    label,
                    tailscale_user,
                } => {
                    eprintln!("tailauth: auth approved for '{target_user}' via '{label}'");
                    ServerEvent::Approved {
                        label,
                        tailscale_user,
                    }
                }
                AuthOutcome::Denied => {
                    eprintln!("tailauth: auth denied for '{target_user}'");
                    ServerEvent::Denied
                }
                AuthOutcome::Timeout => {
                    eprintln!("tailauth: auth timed out for '{target_user}'");
                    ServerEvent::Timeout
                }
            };
            let _ = send_event(&mut write_half, &event).await;
        }

        ClientRequest::StartEnroll { user } => {
            if !caller.is_admin {
                let _ = send_event(
                    &mut write_half,
                    &ServerEvent::Error {
                        message: "Administrator privileges are required to enroll credentials".to_string(),
                    },
                )
                .await;
                return;
            }

            let token = random_b64url(24);
            let challenge = random_b64url(32);
            let (tx, rx) = oneshot::channel();

            {
                let mut sessions = state.enroll_sessions.lock().await;
                sessions.insert(
                    token.clone(),
                    EnrollSession {
                        challenge,
                        user: user.clone(),
                        expires_at: Instant::now() + Duration::from_secs(ENROLL_TIMEOUT_SECS),
                        responder: Some(tx),
                    },
                );
            }

            eprintln!("tailauth: enrollment started for '{user}'");

            let url = format!("{}/enroll/{}", state.config.base_url(), token);
            if send_event(
                &mut write_half,
                &ServerEvent::Pending {
                    token: token.clone(),
                    url,
                    timeout_secs: ENROLL_TIMEOUT_SECS,
                },
            )
            .await
            .is_err()
            {
                state.enroll_sessions.lock().await.remove(&token);
                eprintln!("tailauth: enrollment cancelled for '{user}' (socket write failed)");
                return;
            }

            let outcome = tokio::select! {
                res = rx => res.unwrap_or(EnrollOutcome::Timeout),
                _ = tokio::time::sleep(Duration::from_secs(ENROLL_TIMEOUT_SECS)) => {
                    state.enroll_sessions.lock().await.remove(&token);
                    EnrollOutcome::Timeout
                }
                _ = read_until_cancel_or_eof(&mut reader) => {
                    state.enroll_sessions.lock().await.remove(&token);
                    eprintln!("tailauth: enrollment cancelled by client for '{user}'");
                    return;
                }
            };

            let event = match outcome {
                EnrollOutcome::Enrolled {
                    id,
                    label,
                    tailscale_user,
                } => {
                    eprintln!("tailauth: enrolled '{label}' for '{user}'");
                    ServerEvent::Enrolled {
                        id,
                        label,
                        tailscale_user,
                    }
                }
                EnrollOutcome::Timeout => {
                    eprintln!("tailauth: enrollment timed out for '{user}'");
                    ServerEvent::Timeout
                }
            };
            let _ = send_event(&mut write_half, &event).await;
        }

        ClientRequest::ListCredentials { user } => {
            if !caller.is_admin {
                let _ = send_event(
                    &mut write_half,
                    &ServerEvent::Error {
                        message: "Administrator privileges are required to list credentials".to_string(),
                    },
                )
                .await;
                return;
            }

            let store = state.store.lock().await;
            let mut credentials = Vec::new();
            for (uname, recs) in &store.users {
                if let Some(ref target) = user {
                    if !user_matches(uname, target) {
                        continue;
                    }
                }
                for rec in recs {
                    credentials.push(CredentialSummary {
                        user: uname.clone(),
                        id: rec.id.clone(),
                        label: rec.label.clone(),
                        tailscale_user: rec.tailscale_user.clone(),
                        sign_count: rec.sign_count,
                        created_at_unix: rec.created_at_unix,
                    });
                }
            }
            let _ = send_event(&mut write_half, &ServerEvent::Credentials { credentials }).await;
        }

        ClientRequest::RevokeCredential { user, id_prefix } => {
            if !caller.is_admin {
                let _ = send_event(
                    &mut write_half,
                    &ServerEvent::Error {
                        message: "Administrator privileges are required to revoke credentials".to_string(),
                    },
                )
                .await;
                return;
            }

            let mut store = state.store.lock().await;
            match store.revoke_by_prefix(user.as_deref(), &id_prefix) {
                Ok(id) => {
                    if let Err(e) = store.save(Path::new(&state.config.store_path)) {
                        let _ = send_event(
                            &mut write_half,
                            &ServerEvent::Error {
                                message: format!("failed to persist store: {e}"),
                            },
                        )
                        .await;
                    } else {
                        let _ = send_event(&mut write_half, &ServerEvent::Revoked { id }).await;
                    }
                }
                Err(e) => {
                    let _ = send_event(
                        &mut write_half,
                        &ServerEvent::Error {
                            message: e.to_string(),
                        },
                    )
                    .await;
                }
            }
        }

        ClientRequest::RunElevated { command, cwd } => {
            #[cfg(not(windows))]
            {
                let _ = (command, cwd);
                let _ = send_event(
                    &mut write_half,
                    &ServerEvent::Error {
                        message: "RunElevated is only supported on Windows".to_string(),
                    },
                )
                .await;
            }

            #[cfg(windows)]
            {
                if command.is_empty() {
                    let _ = send_event(
                        &mut write_half,
                        &ServerEvent::Error {
                            message: "command must not be empty".to_string(),
                        },
                    )
                    .await;
                    return;
                }

                let Some(target_user) = caller.verified_user else {
                    let _ = send_event(
                        &mut write_half,
                        &ServerEvent::Error {
                            message: "could not verify caller identity".to_string(),
                        },
                    )
                    .await;
                    return;
                };

                let Some(elevated_token) = caller.elevated_token else {
                    let _ = send_event(
                        &mut write_half,
                        &ServerEvent::Error {
                            message: format!(
                                "user '{target_user}' is not a member of Administrators"
                            ),
                        },
                    )
                    .await;
                    return;
                };

                let allow_credentials: Vec<String> = {
                    let store = state.store.lock().await;
                    store
                        .get_user_credentials(&target_user)
                        .iter()
                        .map(|c| c.id.clone())
                        .collect()
                };

                if allow_credentials.is_empty() {
                    eprintln!(
                        "tailauth: elevation skipped for '{target_user}': no enrolled credentials"
                    );
                    let _ = send_event(&mut write_half, &ServerEvent::NoCredentials).await;
                    return;
                }

                let token = random_b64url(24);
                let challenge = random_b64url(32);
                let timeout_secs = state.config.timeout_secs;
                let (tx, rx) = oneshot::channel();
                let service_name = command.first().cloned().unwrap_or_else(|| "sudo".to_string());

                {
                    let mut sessions = state.auth_sessions.lock().await;
                    sessions.insert(
                        token.clone(),
                        AuthSession {
                            challenge,
                            user: target_user.clone(),
                            service: service_name.clone(),
                            allow_credentials,
                            expires_at: Instant::now() + Duration::from_secs(timeout_secs),
                            responder: Some(tx),
                        },
                    );
                }

                eprintln!("tailauth: elevation auth started for '{target_user}' ({service_name})");

                let url = format!("{}/auth/{}", state.config.base_url(), token);
                if send_event(
                    &mut write_half,
                    &ServerEvent::Pending {
                        token: token.clone(),
                        url,
                        timeout_secs,
                    },
                )
                .await
                .is_err()
                {
                    state.auth_sessions.lock().await.remove(&token);
                    return;
                }

                let outcome = tokio::select! {
                    res = rx => res.unwrap_or(AuthOutcome::Timeout),
                    _ = tokio::time::sleep(Duration::from_secs(timeout_secs)) => {
                        state.auth_sessions.lock().await.remove(&token);
                        AuthOutcome::Timeout
                    }
                    _ = read_until_cancel_or_eof(&mut reader) => {
                        state.auth_sessions.lock().await.remove(&token);
                        eprintln!("tailauth: elevation cancelled by client for '{target_user}'");
                        return;
                    }
                };

                match outcome {
                    AuthOutcome::Approved {
                        label,
                        tailscale_user,
                    } => {
                        eprintln!(
                            "tailauth: elevation approved for '{target_user}' via '{label}'"
                        );
                        if send_event(
                            &mut write_half,
                            &ServerEvent::Approved {
                                label,
                                tailscale_user,
                            },
                        )
                        .await
                        .is_err()
                        {
                            return;
                        }

                        let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel();
                        let mut exec_handle = tokio::task::spawn_blocking(move || {
                            let _keep_token = elevated_token;
                            crate::win::execute_elevated_command(
                                _keep_token.0,
                                &command,
                                cwd.as_deref(),
                                out_tx,
                            )
                        });

                        while let Some((stream_name, chunk)) = out_rx.recv().await {
                            let ev = ServerEvent::Output {
                                stream: stream_name,
                                data_b64: b64url_encode(&chunk),
                            };
                            if send_event(&mut write_half, &ev).await.is_err() {
                                break;
                            }
                        }

                        match (&mut exec_handle).await {
                            Ok(Ok(code)) => {
                                let _ = send_event(&mut write_half, &ServerEvent::Exited { code })
                                    .await;
                            }
                            Ok(Err(e)) => {
                                let _ = send_event(
                                    &mut write_half,
                                    &ServerEvent::Error { message: e },
                                )
                                .await;
                            }
                            Err(e) => {
                                let _ = send_event(
                                    &mut write_half,
                                    &ServerEvent::Error {
                                        message: format!("command task panicked: {e}"),
                                    },
                                )
                                .await;
                            }
                        }
                    }
                    AuthOutcome::Denied => {
                        eprintln!("tailauth: elevation denied for '{target_user}'");
                        let _ = send_event(&mut write_half, &ServerEvent::Denied).await;
                    }
                    AuthOutcome::Timeout => {
                        eprintln!("tailauth: elevation timed out for '{target_user}'");
                        let _ = send_event(&mut write_half, &ServerEvent::Timeout).await;
                    }
                }
            }
        }

        ClientRequest::Status => {
            let store = state.store.lock().await;
            let _ = send_event(
                &mut write_half,
                &ServerEvent::StatusInfo {
                    fqdn: state.config.rp_id().to_string(),
                    https_port: state.config.https_port,
                    enrolled_users: store.enrolled_user_count(),
                    total_credentials: store.total_credentials(),
                },
            )
            .await;
        }
    }
}

#[cfg(unix)]
pub fn bind_unix_socket(socket_path: &Path) -> Result<UnixListener, String> {
    if let Some(parent) = socket_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|e| format!("failed to create socket dir {}: {e}", parent.display()))?;
        }
    }
    if socket_path.exists() {
        fs::remove_file(socket_path)
            .map_err(|e| format!("failed to remove stale socket {}: {e}", socket_path.display()))?;
    }
    let listener = UnixListener::bind(socket_path)
        .map_err(|e| format!("failed to bind unix socket {}: {e}", socket_path.display()))?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("failed to chmod socket {}: {e}", socket_path.display()))?;
    Ok(listener)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

pub async fn run_daemon(config: Config) -> Result<(), String> {
    let (_tx, rx) = oneshot::channel();
    run_daemon_with_shutdown(config, rx).await
}

pub async fn run_daemon_with_shutdown(
    config: Config,
    external_shutdown: oneshot::Receiver<()>,
) -> Result<(), String> {
    let store = CredentialStore::load(Path::new(&config.store_path))
        .map_err(|e| format!("failed to load credential store: {e}"))?;
    let socket_path_str = config.socket_path.clone();
    let listen_addr = config.listen_addr.clone();

    let state = Arc::new(AppState::new(config, store));
    let tcp_listener = TcpListener::bind(&listen_addr)
        .await
        .map_err(|e| format!("failed to bind HTTP listener on {listen_addr}: {e}"))?;

    let cleanup_state = Arc::clone(&state);
    let cleanup_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            cleanup_state.prune_expired().await;
        }
    });

    #[cfg(unix)]
    let ipc_task = {
        let unix_listener = bind_unix_socket(Path::new(&socket_path_str))?;
        let unix_state = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                match unix_listener.accept().await {
                    Ok((stream, _)) => {
                        let s = Arc::clone(&unix_state);
                        tokio::spawn(handle_unix_client(stream, s));
                    }
                    Err(e) => {
                        eprintln!("tailauth: unix accept error: {e}");
                    }
                }
            }
        })
    };

    #[cfg(windows)]
    let ipc_task = {
        let mut server = crate::win::create_secure_pipe_server(&socket_path_str, true)?;
        let pipe_name = socket_path_str.clone();
        let pipe_state = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                if let Err(e) = server.connect().await {
                    eprintln!("tailauth: named pipe connect error: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                let connected = server;
                server = match crate::win::create_secure_pipe_server(&pipe_name, false) {
                    Ok(next) => next,
                    Err(e) => {
                        eprintln!("tailauth: failed to allocate next pipe instance: {e}");
                        break;
                    }
                };
                let s = Arc::clone(&pipe_state);
                tokio::spawn(async move {
                    let caller = match crate::win::inspect_pipe_client(connected.as_raw_handle() as _) {
                        Ok(info) => CallerContext {
                            is_admin: info.is_admin,
                            verified_user: Some(info.username),
                            elevated_token: info.elevated_token,
                        },
                        Err(e) => {
                            eprintln!("tailauth: pipe client inspection failed: {e}");
                            return;
                        }
                    };
                    handle_ipc_stream(connected, s, caller).await;
                });
            }
        })
    };

    let router = build_router(Arc::clone(&state));
    eprintln!(
        "tailauth daemon listening on http://{listen_addr} (origin {}) and ipc:{socket_path_str}",
        state.config.expected_origin()
    );

    let shutdown = async move {
        tokio::select! {
            _ = shutdown_signal() => {},
            _ = external_shutdown => {},
        }
    };

    let http_res = axum::serve(tcp_listener, router)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(|e| format!("HTTP server error: {e}"));

    ipc_task.abort();
    cleanup_task.abort();
    #[cfg(unix)]
    let _ = fs::remove_file(&socket_path_str);
    http_res
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::crypto::test_helpers::{generate_p256_keypair, sign_es256};
    use crate::crypto::{b64url_encode, sha256};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    async fn http_request(
        addr: std::net::SocketAddr,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> (u16, String) {
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        let payload = body.unwrap_or("");
        let req = if body.is_some() {
            format!(
                "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                payload.len()
            )
        } else {
            format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        };
        conn.write_all(req.as_bytes()).await.unwrap();
        let mut raw = String::new();
        conn.read_to_string(&mut raw).await.unwrap();
        let (head, resp_body) = raw.split_once("\r\n\r\n").unwrap();
        let status_line = head.lines().next().unwrap();
        let code: u16 = status_line.split_whitespace().nth(1).unwrap().parse().unwrap();
        (code, resp_body.to_string())
    }

    #[tokio::test]
    async fn end_to_end_unix_socket_and_webauthn_approval_deny_and_cancel() {
        let tmp_dir = std::env::temp_dir().join(format!("tailauth_daemon_e2e_{}", std::process::id()));
        fs::create_dir_all(&tmp_dir).unwrap();
        let sock_path = tmp_dir.join("daemon.sock");
        let store_path = tmp_dir.join("credentials.json");

        let (priv_pem, pub_pem, _, _, _) = generate_p256_keypair();
        let cred_id = b64url_encode(b"e2e-cred-id");

        let cfg = Config {
            fqdn: "testbox.tailnet.ts.net".to_string(),
            https_port: 8443,
            listen_addr: "127.0.0.1:0".to_string(),
            socket_path: sock_path.display().to_string(),
            store_path: store_path.display().to_string(),
            timeout_secs: 30,
            allowed_tailscale_users: Vec::new(),
        };

        let mut store = CredentialStore::default();
        store.add_credential(
            "alice",
            CredentialRecord {
                id: cred_id.clone(),
                public_key_pem: pub_pem,
                sign_count: 1,
                label: "Test Phone".to_string(),
                tailscale_user: None,
                created_at_unix: 1700000000,
            },
        );

        let state = Arc::new(AppState::new(cfg.clone(), store));
        let unix_listener = bind_unix_socket(&sock_path).unwrap();
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = tcp_listener.local_addr().unwrap();

        let unix_state = Arc::clone(&state);
        let unix_task = tokio::spawn(async move {
            loop {
                if let Ok((stream, _)) = unix_listener.accept().await {
                    tokio::spawn(handle_unix_client(stream, Arc::clone(&unix_state)));
                }
            }
        });
        let router = build_router(Arc::clone(&state));
        let http_task = tokio::spawn(async move {
            axum::serve(tcp_listener, router).await.unwrap();
        });

        // 1) Happy-path approval
        let client = UnixStream::connect(&sock_path).await.unwrap();
        let (r, mut w) = client.into_split();
        let mut reader = BufReader::new(r);
        let req_line = serde_json::to_string(&ClientRequest::StartAuth {
            user: "alice".to_string(),
            ruser: Some("alice".to_string()),
            service: Some("sudo".to_string()),
        })
        .unwrap();
        w.write_all(format!("{req_line}\n").as_bytes()).await.unwrap();

        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let pending: ServerEvent = serde_json::from_str(line.trim()).unwrap();
        let token = match pending {
            ServerEvent::Pending { token, url, .. } => {
                assert!(url.starts_with("https://testbox.tailnet.ts.net:8443/auth/"));
                token
            }
            other => panic!("expected Pending, got {other:?}"),
        };

        let (code, body) = http_request(http_addr, "GET", &format!("/api/auth/{token}/options"), None).await;
        assert_eq!(code, 200);
        let opts: serde_json::Value = serde_json::from_str(&body).unwrap();
        let challenge = opts["challenge"].as_str().unwrap();

        let client_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://testbox.tailnet.ts.net:8443"}}"#
        );
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&sha256(b"testbox.tailnet.ts.net"));
        auth_data.push(0x05); // UP + UV
        auth_data.extend_from_slice(&2u32.to_be_bytes());
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&sha256(client_json.as_bytes()));
        let sig = sign_es256(&priv_pem, &signed);

        let verify_body = serde_json::json!({
            "id": cred_id,
            "authenticatorData": b64url_encode(&auth_data),
            "clientDataJSON": b64url_encode(client_json.as_bytes()),
            "signature": b64url_encode(&sig),
        })
        .to_string();
        let (code, _) = http_request(
            http_addr,
            "POST",
            &format!("/api/auth/{token}/verify"),
            Some(&verify_body),
        )
        .await;
        assert_eq!(code, 200);

        line.clear();
        reader.read_line(&mut line).await.unwrap();
        let approved: ServerEvent = serde_json::from_str(line.trim()).unwrap();
        assert!(matches!(approved, ServerEvent::Approved { label, .. } if label == "Test Phone"));

        // 2) Deny flow
        let client2 = UnixStream::connect(&sock_path).await.unwrap();
        let (r2, mut w2) = client2.into_split();
        let mut reader2 = BufReader::new(r2);
        w2.write_all(format!("{req_line}\n").as_bytes()).await.unwrap();
        line.clear();
        reader2.read_line(&mut line).await.unwrap();
        let token2 = match serde_json::from_str::<ServerEvent>(line.trim()).unwrap() {
            ServerEvent::Pending { token, .. } => token,
            other => panic!("expected Pending, got {other:?}"),
        };
        let (code, _) = http_request(http_addr, "POST", &format!("/api/auth/{token2}/deny"), Some("{}")).await;
        assert_eq!(code, 200);
        line.clear();
        reader2.read_line(&mut line).await.unwrap();
        assert_eq!(
            serde_json::from_str::<ServerEvent>(line.trim()).unwrap(),
            ServerEvent::Denied
        );

        // 3) Socket disconnect immediately cancels pending auth session
        let client3 = UnixStream::connect(&sock_path).await.unwrap();
        let (r3, mut w3) = client3.into_split();
        let mut reader3 = BufReader::new(r3);
        w3.write_all(format!("{req_line}\n").as_bytes()).await.unwrap();
        line.clear();
        reader3.read_line(&mut line).await.unwrap();
        let token3 = match serde_json::from_str::<ServerEvent>(line.trim()).unwrap() {
            ServerEvent::Pending { token, .. } => token,
            other => panic!("expected Pending, got {other:?}"),
        };
        drop(w3);
        drop(reader3);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (code, _) = http_request(http_addr, "GET", &format!("/api/auth/{token3}/options"), None).await;
        assert_eq!(code, 404);

        unix_task.abort();
        http_task.abort();
        let _ = fs::remove_dir_all(&tmp_dir);
    }
}
