//! WinRM session pool, password cache, failure lockout and audit.
//!
//! Port of `agent/session_manager.py`. The module knows the transport only through the
//! [`WinRmTransport`] trait, so the tests run on a fake transport that records the commands
//! it gets and do not touch the network (ADR-0003, AGENTS.md §4).
//!
//! The identity is passed explicitly to each call: the caches are keyed by user name and
//! the sessions by the pair (user, `session_id`), so a user does not see another's objects
//! (DR-3).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};
use winrm_rs::{ExposeSecret, SecretString};

use crate::executor::{
    SEPARATOR, escape_log_field, neutralize_separator, redact, sanitize_log_value, truncate,
};

pub const DEFAULT_HTTP_PORT: u16 = 5985;
pub const DEFAULT_HTTPS_PORT: u16 = 5986;

/// Forces UTF-8 in redirected PowerShell output.
///
/// `winrm-rs` sets `WINRS_CODEPAGE=65001` at the cmd shell level, but `powershell.exe`
/// uses its own `[Console]::OutputEncoding` for redirected output. On a localized Windows
/// it does not hold the system language, and PowerShell replaces unrepresentable
/// characters with `?` before it sends the bytes, so no decoding on this side can bring
/// them back. The try/catch wrapper is for a host without a console (port of
/// `UTF8_PREAMBLE` from the Python version).
pub const UTF8_PREAMBLE: &str = "try { [Console]::OutputEncoding = [Text.Encoding]::UTF8; \
     $OutputEncoding = [Text.Encoding]::UTF8 } catch { }; ";

/// Caller identity for one request (DR-2).
#[derive(Debug, Clone)]
pub struct UserIdentity {
    pub username: String,
    /// Supplied in the `X-AD-Password` header or decrypted from the profile.
    pub password: Option<SecretString>,
    /// Where the password came from: the header or the profile (ADR-0009).
    pub origin: IdentityOrigin,
}

impl UserIdentity {
    /// Identity without a password: the password comes from the cache or is requested.
    #[must_use]
    pub fn new(username: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: None,
            origin: IdentityOrigin::Headers,
        }
    }

    /// Header-origin identity that carries a password.
    #[must_use]
    pub fn with_password(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: Some(SecretString::from(password.into())),
            origin: IdentityOrigin::Headers,
        }
    }

    /// Profile-origin identity that carries a decrypted password.
    #[must_use]
    pub fn from_profile(username: impl Into<String>, password: SecretString) -> Self {
        Self {
            username: username.into(),
            password: Some(password),
            origin: IdentityOrigin::Profile,
        }
    }
}

/// Result of a remote command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Return code; `-1` if the server did not report one.
    pub exit_code: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    /// Credentials were rejected by the server.
    #[error("authentication failed: {0}")]
    AuthFailed(String),
    /// The credentials were accepted, but the host rejected the request itself (TR-SEC-10).
    #[error("request rejected: {0}")]
    Rejected(String),
    #[error("transport error: {0}")]
    Other(String),
}

impl TransportError {
    /// True if this is a credential failure (for the password cache reset).
    ///
    /// [`Self::Rejected`] is not one: there the password was already accepted, so there is
    /// nothing to reset the cache for or to move the lockout counter for (TR-SEC-10).
    #[must_use]
    pub fn is_auth_failure(&self) -> bool {
        matches!(self, Self::AuthFailed(_))
    }
}

/// Parameters of one connection to a Windows host.
#[derive(Debug, Clone)]
pub struct SessionTarget {
    pub host: String,
    pub port: u16,
    pub use_tls: bool,
    pub verify_cert: bool,
    pub username: String,
    /// Zeroized on drop (DR-4).
    pub password: SecretString,
}

/// Seam between the real transport and the fake recording one.
#[async_trait::async_trait]
pub trait WinRmTransport: Send + Sync {
    ///
    /// # Errors
    ///
    /// [`TransportError`] if the connection or the authentication fails.
    async fn run_powershell(
        &self,
        target: &SessionTarget,
        script: &str,
    ) -> Result<RemoteOutput, TransportError>;
}

/// Splits `DOMAIN\user` for NTLM, matching `spnego`.
///
/// `winrm-rs` does not split `DOMAIN\user` itself: it puts `username` into the NTLMv2 hash
/// whole (`UPPER(username) + domain`), so with an empty domain `contoso\alice` goes as
/// `CONTOSO\ALICE` and AD rejects the logon.
///
/// The split matches `spnego` (the `requests-ntlm` engine under `pywinrm`, on which the
/// Python version ran): the name is split at the first `\`; a UPN (`user@realm`) and a
/// bare name stay whole as the user name with an empty domain, and the domain case is
/// unchanged, because the server recomputes the hash from what the client sent.
#[must_use]
pub fn split_account(account: &str) -> (String, String) {
    match account.split_once('\\') {
        Some((domain, user)) => (user.to_owned(), domain.to_owned()),
        None => (account.to_owned(), String::new()),
    }
}

/// Real transport over `winrm-rs`.
#[derive(Debug, Default, Clone)]
pub struct WinrmTransportImpl;

/// `winrm-rs` credentials with `DOMAIN\user` split.
fn credentials_for(target: &SessionTarget) -> winrm_rs::WinrmCredentials {
    let (username, domain) = split_account(&target.username);
    winrm_rs::WinrmCredentials {
        username,
        password: target.password.clone(),
        domain,
    }
}

#[async_trait::async_trait]
impl WinRmTransport for WinrmTransportImpl {
    async fn run_powershell(
        &self,
        target: &SessionTarget,
        script: &str,
    ) -> Result<RemoteOutput, TransportError> {
        use winrm_rs::{WinrmClient, WinrmConfig};

        let config = WinrmConfig {
            port: target.port,
            use_tls: target.use_tls,
            accept_invalid_certs: !target.verify_cert,
            ..WinrmConfig::default()
        };
        let credentials = credentials_for(target);
        let client = WinrmClient::new(config, credentials).map_err(map_error)?;
        let output = client
            .run_powershell(&target.host, script)
            .await
            .map_err(map_error)?;
        Ok(RemoteOutput {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.exit_code,
        })
    }
}

/// The listener rejected an unencrypted message when it answers HTTP 500 with an empty body.
const UNENCRYPTED_HINT: &str = "the host returned HTTP 500 with an empty body. \
     The credentials were accepted, so this is not a password problem: WinRM answers \
     an unencrypted message this way when AllowUnencrypted is false. Connect over \
     HTTPS (port 5986), or set AllowUnencrypted on the host.";

fn map_error(error: winrm_rs::WinrmError) -> TransportError {
    match error {
        winrm_rs::WinrmError::AuthFailed(message) => classify_auth_failure(message),
        other => TransportError::Other(other.to_string()),
    }
}

/// Separates a real credential failure from a rejected request.
///
/// `winrm-rs` puts both an NTLM rejection and any failed HTTP status into `AuthFailed`
/// (`auth/ntlm.rs`, `transport.rs`). The second arrives after NTLM was accepted, so it is
/// not a password failure and must neither reset the cache nor move the lockout counter
/// (TR-SEC-10).
fn classify_auth_failure(message: String) -> TransportError {
    if !message.starts_with("HTTP ") {
        return TransportError::AuthFailed(message);
    }
    if is_empty_internal_error(&message) {
        return TransportError::Rejected(UNENCRYPTED_HINT.to_owned());
    }
    TransportError::Rejected(message)
}

/// True for `HTTP 500 ...:` with an empty body — the signature of a refusal of an
/// unencrypted message. A WS-Man error would arrive as a SOAP fault with a body.
fn is_empty_internal_error(message: &str) -> bool {
    message.starts_with("HTTP 500")
        && message
            .split_once(':')
            .is_some_and(|(_, body)| body.trim().is_empty())
}

/// Registry settings collected from `AppConfig`.
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// Idle lifetime of the password; `0` means no expiry.
    pub password_idle_ttl: Duration,
    /// Number of AD failures before the lockout.
    pub lockout_max_attempts: u32,
    pub lockout_window: Duration,
    /// Redaction threshold in the reply to the agent.
    pub secret_redact_min_length: usize,
    /// Output cap in the audit, in characters.
    pub audit_max_output_chars: usize,
    /// Whether to write the command and output body into the audit.
    pub audit_log_body: bool,
    pub default_port: u16,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            password_idle_ttl: Duration::from_secs(3600),
            lockout_max_attempts: 3,
            lockout_window: Duration::from_secs(1800),
            secret_redact_min_length: 4,
            audit_max_output_chars: 2000,
            audit_log_body: true,
            default_port: DEFAULT_HTTP_PORT,
        }
    }
}

/// Password with the time it was last used.
#[derive(Debug, Clone)]
struct CachedPassword {
    value: SecretString,
    last_used: Instant,
}

/// Counters of AD failures for the current password.
#[derive(Debug, Clone)]
struct FailureState {
    /// SHA-256 of the rejected password; the password itself is not stored (DR-4).
    password_hash: [u8; 32],
    count: u32,
    first_failure: Instant,
}

impl FailureState {
    /// Seconds until the window expires, counted from the first failure.
    fn window_remaining(&self, window: Duration, now: Instant) -> i64 {
        let elapsed = now.saturating_duration_since(self.first_failure);
        window.as_secs() as i64 - elapsed.as_secs() as i64
    }
}

/// Where the password came from: it decides whether the two-lockout rule applies to it
/// (ADR-0009, AC-PRF-56).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityOrigin {
    /// The password was presented in a header; the client can change it by hand.
    Headers,
    /// The password was decrypted from the profile; changing it needs `setup`.
    Profile,
}

/// State kept for one open connection.
#[derive(Debug, Clone)]
struct Session {
    target: SessionTarget,
    connected_at: SystemTime,
    last_used: SystemTime,
    command_count: u64,
}

/// Per-user isolation of the caches and the registry (DR-3).
pub struct SessionRegistry {
    transport: Arc<dyn WinRmTransport>,
    config: RegistryConfig,
    passwords: Mutex<HashMap<String, CachedPassword>>,
    failures: Mutex<HashMap<String, FailureState>>,
    /// Number of times the failure threshold was reached since the last successful `connect`.
    lockout_streak: Mutex<HashMap<String, u32>>,
    /// Users whose profile was rejected twice and stay blocked until a restart.
    profile_refused: Mutex<std::collections::HashSet<String>>,
    sessions: Mutex<HashMap<(String, String), Session>>,
}

impl SessionRegistry {
    #[must_use]
    pub fn new(transport: Arc<dyn WinRmTransport>, config: RegistryConfig) -> Self {
        Self {
            transport,
            config,
            passwords: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
            lockout_streak: Mutex::new(HashMap::new()),
            profile_refused: Mutex::new(std::collections::HashSet::new()),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Stores the password for the user and drops the user's sessions when it changes.
    pub fn cache_password(&self, username: &str, password: &str) {
        let now = Instant::now();
        let changed = {
            let mut passwords = lock(&self.passwords);
            let changed = passwords
                .get(username)
                .is_some_and(|cached| cached.value.expose_secret() != password);
            passwords.insert(
                username.to_owned(),
                CachedPassword {
                    value: SecretString::from(password.to_owned()),
                    last_used: now,
                },
            );
            changed
        };
        if changed {
            self.drop_sessions(username);
        }
    }

    /// Whether the user has an unexpired password; refreshes the lifetime.
    #[must_use]
    pub fn has_cached_password(&self, username: &str) -> bool {
        let now = Instant::now();
        let mut expired = false;
        let present = {
            let mut passwords = lock(&self.passwords);
            match passwords.get_mut(username) {
                None => false,
                Some(cached) if self.is_expired(cached.last_used, now) => {
                    passwords.remove(username);
                    expired = true;
                    false
                }
                Some(cached) => {
                    cached.last_used = now;
                    true
                }
            }
        };
        if expired {
            self.drop_sessions(username);
        }
        present
    }

    /// Removes the user's password and sessions, so the next `connect` asks again.
    pub fn invalidate_password(&self, username: &str) {
        lock(&self.passwords).remove(username);
        self.drop_sessions(username);
    }

    /// True if the user's profile was rejected twice and is not presented until a restart
    /// (AC-PRF-56). In stdio this is the signal to end the process.
    #[must_use]
    pub fn is_profile_refused(&self, username: &str) -> bool {
        lock(&self.profile_refused).contains(username)
    }

    fn is_expired(&self, last_used: Instant, now: Instant) -> bool {
        let ttl = self.config.password_idle_ttl;
        ttl > Duration::ZERO && now.saturating_duration_since(last_used) > ttl
    }

    fn drop_sessions(&self, username: &str) {
        lock(&self.sessions).retain(|(user, _), _| user != username);
    }

    /// Opens a session: checks the lockout, then runs a probe command.
    ///
    /// Returns the tool reply: host details on success, an `error` field on refusal.
    pub async fn connect(
        &self,
        identity: &UserIdentity,
        host: &str,
        port: Option<u16>,
        use_ssl: Option<bool>,
        verify_cert: bool,
    ) -> Value {
        let username = identity.username.clone();
        self.sync_header_password(identity);

        // AC-PRF-56: a profile rejected twice is not presented again until the process restarts.
        if identity.origin == IdentityOrigin::Profile
            && lock(&self.profile_refused).contains(&username)
        {
            return json!({
                "error": "The profile password was rejected twice; the profile is refused until \
                          the process restarts. Run 'winrig setup' to update it.",
                "auth_failed": true,
            });
        }

        // TR-SEC-13: the password arrives in the same request. A cache keyed by name alone does
        // not open a session: any holder of the shared secret can claim another's `X-AD-User`
        // (ADR-0015 §3). The profile always carries the password, so its branch is unchanged.
        let Some(password) = identity.password.clone() else {
            self.audit_refusal(
                &username,
                "connect",
                "PASSWORD_REQUIRED",
                "X-AD-Password is missing from the request",
            );
            return json!({
                "error": "connect requires the AD password in the X-AD-Password header of the same \
                          request; a cached password is not used to open a session."
            });
        };

        if let Some(locked) = self.check_lockout(&username) {
            return locked;
        }

        let use_tls =
            use_ssl.unwrap_or((port.unwrap_or(self.config.default_port)) == DEFAULT_HTTPS_PORT);
        let port = port.unwrap_or(if use_tls {
            DEFAULT_HTTPS_PORT
        } else {
            self.config.default_port
        });
        let session_id = if port == self.config.default_port {
            host.to_owned()
        } else {
            format!("{host}:{port}")
        };

        if lock(&self.sessions).contains_key(&(username.clone(), session_id.clone())) {
            tracing::info!(session = %sanitize_log_value(&session_id), "already connected");
            return json!({
                "session_id": session_id,
                "status": "already_connected",
                "host": host,
                "port": port,
            });
        }

        let target = SessionTarget {
            host: host.to_owned(),
            port,
            use_tls,
            verify_cert,
            username: username.clone(),
            password: password.clone(),
        };

        let probe = "$os = Get-CimInstance Win32_OperatingSystem; \
             \"$env:COMPUTERNAME|$($os.Caption)|$($os.Version)|\
             $($os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss'))\"";
        match self
            .transport
            .run_powershell(&target, &format!("{UTF8_PREAMBLE}{probe}"))
            .await
        {
            Ok(output) if output.exit_code == 0 => {
                let raw = String::from_utf8_lossy(&output.stdout).trim().to_owned();
                let parts: Vec<&str> = raw.split('|').collect();
                let secret = [password.expose_secret().to_owned()];
                // DR-4: fields from the host can contain the secret too, so they are redacted
                // before the audit and the reply.
                let audit_field = |value: &str| redact(value, &secret, 1);
                let reply_field =
                    |value: &str| redact(value, &secret, self.config.secret_redact_min_length);
                let computer_name = audit_field(parts.first().copied().unwrap_or(raw.as_str()));
                let reply_computer = reply_field(parts.first().copied().unwrap_or(raw.as_str()));

                lock(&self.sessions).insert(
                    (username.clone(), session_id.clone()),
                    Session {
                        target,
                        connected_at: SystemTime::now(),
                        last_used: SystemTime::now(),
                        command_count: 0,
                    },
                );
                self.clear_failures(&username);
                self.clear_lockout_streak(&username);

                let mut info = Map::new();
                info.insert("session_id".to_owned(), json!(session_id));
                info.insert("status".to_owned(), json!("connected"));
                info.insert("host".to_owned(), json!(host));
                info.insert("port".to_owned(), json!(port));
                info.insert(
                    "transport".to_owned(),
                    json!(if use_tls { "https" } else { "http" }),
                );
                info.insert(
                    "cert_validation".to_owned(),
                    json!(if verify_cert { "validate" } else { "ignore" }),
                );
                info.insert("computer_name".to_owned(), json!(reply_computer));
                if parts.len() >= 4 {
                    info.insert("os".to_owned(), json!(reply_field(parts[1])));
                    info.insert("os_version".to_owned(), json!(reply_field(parts[2])));
                    info.insert("last_boot".to_owned(), json!(reply_field(parts[3])));
                }
                self.audit(
                    "CONNECT",
                    &[
                        ("user", username.clone()),
                        ("identity", origin_label(identity.origin).to_owned()),
                        ("session", session_id.clone()),
                        ("host", host.to_owned()),
                        ("port", port.to_string()),
                        (
                            "transport",
                            if use_tls { "https" } else { "http" }.to_owned(),
                        ),
                        (
                            "cert_check",
                            if verify_cert { "validate" } else { "ignore" }.to_owned(),
                        ),
                        ("computer", computer_name),
                    ],
                    "",
                );
                Value::Object(info)
            }
            Ok(output) => {
                let stderr = strip_clixml(&String::from_utf8_lossy(&output.stderr));
                // DR-4: the host error text can contain the password. The audit is redacted
                // unconditionally, the reply to the agent by the threshold.
                let secret = [password.expose_secret().to_owned()];
                let audit_stderr = redact(&stderr, &secret, 1);
                let reply_stderr = redact(&stderr, &secret, self.config.secret_redact_min_length);
                self.audit(
                    "CONNECT FAILED",
                    &[
                        ("user", username.clone()),
                        ("host", host.to_owned()),
                        ("port", port.to_string()),
                        (
                            "transport",
                            if use_tls { "https" } else { "http" }.to_owned(),
                        ),
                    ],
                    &format!(
                        "  error: {}",
                        escape_log_field(&audit_stderr.chars().take(200).collect::<String>())
                    ),
                );
                json!({ "error": format!("Connection test failed: {reply_stderr}") })
            }
            Err(error) => {
                if error.is_auth_failure() {
                    self.record_auth_failure(&username, &password);
                    self.invalidate_password(&username);
                    // AC-PRF-56: a second run of the failure threshold for a profile turns it
                    // into a refusal until the process restarts.
                    if identity.origin == IdentityOrigin::Profile
                        && self.bump_lockout_streak(&username)
                    {
                        lock(&self.profile_refused).insert(username.clone());
                        self.audit(
                            "PROFILE REFUSED",
                            &[
                                ("user", username.clone()),
                                ("reason", "password rejected twice".to_owned()),
                            ],
                            "",
                        );
                    }
                }
                let secret = password.expose_secret().to_owned();
                let audit_error = sanitize_log_value(&redact(
                    &error.to_string(),
                    std::slice::from_ref(&secret),
                    1,
                ));
                tracing::warn!(
                    host = %sanitize_log_value(host),
                    error = %audit_error,
                    "connect failed"
                );
                self.audit(
                    "CONNECT ERROR",
                    &[
                        ("user", username.clone()),
                        ("host", host.to_owned()),
                        ("port", port.to_string()),
                        (
                            "transport",
                            if use_tls { "https" } else { "http" }.to_owned(),
                        ),
                        ("error", audit_error.chars().take(300).collect::<String>()),
                    ],
                    "",
                );
                let reply_error = redact(
                    &error.to_string(),
                    std::slice::from_ref(&secret),
                    self.config.secret_redact_min_length,
                );
                let mut reply = Map::new();
                reply.insert("error".to_owned(), json!(reply_error));
                reply.insert("host".to_owned(), json!(host));
                reply.insert("port".to_owned(), json!(port));
                if error.is_auth_failure() {
                    reply.insert("auth_failed".to_owned(), json!(true));
                }
                Value::Object(reply)
            }
        }
    }

    #[must_use]
    pub fn disconnect(&self, username: &str, session_id: &str) -> Value {
        let removed = lock(&self.sessions).remove(&(username.to_owned(), session_id.to_owned()));
        match removed {
            Some(session) => {
                self.audit(
                    "DISCONNECT",
                    &[
                        ("user", username.to_owned()),
                        ("session", session_id.to_owned()),
                        ("commands_run", session.command_count.to_string()),
                    ],
                    "",
                );
                json!({ "session_id": session_id, "status": "disconnected" })
            }
            None => json!({ "error": format!("Session not found: {session_id}") }),
        }
    }

    #[must_use]
    pub fn list_sessions(&self, username: &str) -> Value {
        let sessions = lock(&self.sessions);
        let mut items = Vec::new();
        for ((user, sid), session) in sessions.iter() {
            if user != username {
                continue;
            }
            items.push(json!({
                "session_id": sid,
                "host": session.target.host,
                "port": session.target.port,
                "connected_at": format_time(session.connected_at),
                "last_used": format_time(session.last_used),
                "command_count": session.command_count,
            }));
        }
        json!({ "sessions": items, "count": items.len() })
    }

    /// Runs a PowerShell command in an open session with redaction and audit.
    pub async fn run_ps(
        &self,
        username: &str,
        session_id: &str,
        command: &str,
        tool_name: &str,
        redactions: &[String],
    ) -> Value {
        let (target, command_number) = {
            let mut sessions = lock(&self.sessions);
            let Some(session) = sessions.get_mut(&(username.to_owned(), session_id.to_owned()))
            else {
                return json!({
                    "error": format!("Session not found: {session_id}. Use connect first.")
                });
            };
            session.last_used = SystemTime::now();
            session.command_count += 1;
            (session.target.clone(), session.command_count)
        };

        // DR-4: the session password is always redacted, even if the tool did not pass it
        // separately. Otherwise `set_registry` with a secret in a value would reach the audit
        // in clear text.
        let mut effective_secrets: Vec<String> = redactions.to_vec();
        let session_password = target.password.expose_secret().to_owned();
        if !effective_secrets
            .iter()
            .any(|secret| secret == &session_password)
        {
            effective_secrets.push(session_password.clone());
        }
        let redactions: &[String] = &effective_secrets;

        let audit = |text: &str| redact(text, redactions, 1);
        let reply_redact =
            |text: &str| redact(text, redactions, self.config.secret_redact_min_length);
        let label = if tool_name.is_empty() {
            String::new()
        } else {
            format!(" [{tool_name}]")
        };

        // The preamble is added to the execution only; the audit keeps the command the tool
        // requested.
        match self
            .transport
            .run_powershell(&target, &format!("{UTF8_PREAMBLE}{command}"))
            .await
        {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
                let stderr = strip_clixml(&String::from_utf8_lossy(&output.stderr));
                let truncated_stdout = truncate(&stdout, crate::executor::MAX_OUTPUT_CHARS);
                let body = command_audit_body(
                    command,
                    &stdout,
                    &stderr,
                    redactions,
                    self.config.audit_max_output_chars,
                );

                let fields: Vec<(&str, String)> = vec![
                    ("user", username.to_owned()),
                    ("session", session_id.to_owned()),
                    (
                        "tool",
                        if tool_name.is_empty() {
                            "(direct)".to_owned()
                        } else {
                            tool_name.to_owned()
                        },
                    ),
                    ("status_code", output.exit_code.to_string()),
                    ("stdout_bytes", stdout.len().to_string()),
                    ("stderr_bytes", stderr.len().to_string()),
                ];
                self.audit(&format!("COMMAND #{command_number}{label}"), &fields, &body);

                let mut reply = Map::new();
                reply.insert("status_code".to_owned(), json!(output.exit_code));
                reply.insert("stdout".to_owned(), json!(reply_redact(&truncated_stdout)));
                reply.insert("stderr".to_owned(), json!(reply_redact(&stderr)));
                if output.exit_code != 0 && stdout.trim().is_empty() && stderr.is_empty() {
                    reply.insert(
                        "error".to_owned(),
                        json!(format!(
                            "Command failed with exit code {} and produced no output. A cmdlet most likely reported an error that the command suppressed — often because nothing matched the requested filter.",
                            output.exit_code
                        )),
                    );
                }
                Value::Object(reply)
            }
            Err(error) => {
                let message = reply_redact(&error.to_string());
                tracing::error!(session = %sanitize_log_value(session_id), error = %message, "run_ps failed");
                self.audit(
                    &format!("COMMAND ERROR{label}"),
                    &[
                        ("user", username.to_owned()),
                        ("session", session_id.to_owned()),
                        (
                            "tool",
                            if tool_name.is_empty() {
                                "(direct)".to_owned()
                            } else {
                                tool_name.to_owned()
                            },
                        ),
                    ],
                    &format!("  PS> {}", audit(command)),
                );
                json!({ "error": message, "session_id": session_id })
            }
        }
    }

    fn cached_password(&self, username: &str) -> Option<SecretString> {
        let now = Instant::now();
        let mut expired = false;
        let value = {
            let mut passwords = lock(&self.passwords);
            match passwords.get_mut(username) {
                None => None,
                Some(cached) if self.is_expired(cached.last_used, now) => {
                    passwords.remove(username);
                    expired = true;
                    None
                }
                Some(cached) => {
                    cached.last_used = now;
                    Some(cached.value.clone())
                }
            }
        };
        if expired {
            self.drop_sessions(username);
        }
        value
    }

    fn sync_header_password(&self, identity: &UserIdentity) {
        if let Some(password) = &identity.password {
            self.cache_password(&identity.username, password.expose_secret());
        }
    }

    fn check_lockout(&self, username: &str) -> Option<Value> {
        let now = Instant::now();
        let state = {
            let failures = lock(&self.failures);
            failures.get(username).cloned()
        };
        let state = state?;
        if state.count < self.config.lockout_max_attempts {
            return None;
        }
        let remaining = state.window_remaining(self.config.lockout_window, now);
        if remaining <= 0 {
            self.clear_failures(username);
            return None;
        }
        let password = self.cached_password(username)?;
        if password_hash(password.expose_secret()) != state.password_hash {
            return None;
        }
        tracing::warn!(user = %username, attempts = state.count, "AD password lockout active");
        self.audit(
            "AUTH LOCKOUT",
            &[
                ("user", username.to_owned()),
                ("attempts", state.count.to_string()),
                ("window_remaining_s", remaining.to_string()),
            ],
            "",
        );
        Some(json!({
            "error": format!("Too many failed AD sign-ins. Retry after {remaining}s or use a different password."),
            "locked_out": true,
        }))
    }

    fn record_auth_failure(&self, username: &str, password: &SecretString) {
        let now = Instant::now();
        let digest = password_hash(password.expose_secret());
        let mut failures = lock(&self.failures);
        match failures.get_mut(username) {
            Some(state) if state.password_hash == digest => {
                state.count += 1;
                if state.count >= self.config.lockout_max_attempts {
                    state.first_failure = now;
                }
            }
            _ => {
                failures.insert(
                    username.to_owned(),
                    FailureState {
                        password_hash: digest,
                        count: 1,
                        first_failure: now,
                    },
                );
            }
        }
    }

    fn clear_failures(&self, username: &str) {
        lock(&self.failures).remove(username);
    }

    /// Accounts for the failure threshold being reached; `true` if this is already the second
    /// time in a row (AC-PRF-56). A successful `connect` clears the count (AC-PRF-57).
    fn bump_lockout_streak(&self, username: &str) -> bool {
        let reached = {
            let failures = lock(&self.failures);
            failures
                .get(username)
                .is_some_and(|state| state.count >= self.config.lockout_max_attempts)
        };
        if !reached {
            return false;
        }
        let mut streak = lock(&self.lockout_streak);
        let entry = streak.entry(username.to_owned()).or_insert(0);
        *entry += 1;
        *entry >= 2
    }

    fn clear_lockout_streak(&self, username: &str) {
        lock(&self.lockout_streak).remove(username);
    }

    /// Moves the lockout window into the past — only for window-expiry tests.
    #[cfg(test)]
    fn force_lockout_window_elapsed(&self, username: &str) {
        let backdate = self.config.lockout_window + Duration::from_secs(1);
        let mut failures = lock(&self.failures);
        if let Some(state) = failures.get_mut(username) {
            state.first_failure = Instant::now()
                .checked_sub(backdate)
                .expect("monotonic clock is older than the window");
        }
    }

    /// Writes a policy refusal that happened before the host call into the audit (TR-OBS-03,
    /// ADR-0015 §14).
    ///
    /// The reason names the host or the path, never a secret: passwords and tokens do not
    /// reach policy refusals. Fields are escaped like in the other records.
    pub fn audit_refusal(&self, username: &str, tool: &str, code: &str, reason: &str) {
        self.audit(
            "POLICY REFUSED",
            &[
                ("user", username.to_owned()),
                ("tool", tool.to_owned()),
                ("code", code.to_owned()),
                ("reason", reason.to_owned()),
            ],
            "",
        );
    }

    fn audit(&self, header: &str, fields: &[(&str, String)], body: &str) {
        let body = if self.config.audit_log_body { body } else { "" };
        let mut lines = vec![
            format!("\n{SEPARATOR}"),
            format!("{}  {}", timestamp(), escape_log_field(header)),
        ];
        lines.push("─".repeat(80));
        for (key, value) in fields {
            lines.push(format!("  {key:<14}: {}", escape_log_field(value)));
        }
        if !body.is_empty() {
            lines.push(String::new());
            lines.push(neutralize_separator(body));
        }
        lines.push(SEPARATOR.to_owned());
        tracing::info!(target: "winrig::audit", "{}", lines.join("\n"));
    }
}

/// Pure, so it can be tested without the global tracing subsystem (TR-SEC-09, DR-4).
///
/// Redacts the command and the output unconditionally (`min_length=1`), truncates and
/// formats them.
fn command_audit_body(
    command: &str,
    stdout: &str,
    stderr: &str,
    secrets: &[String],
    max_output_chars: usize,
) -> String {
    let audit = |text: &str| redact(text, secrets, 1);
    let audit_stdout = truncate(
        &audit(&truncate(stdout, crate::executor::MAX_OUTPUT_CHARS)),
        max_output_chars,
    );
    let audit_stderr = truncate(&audit(stderr), max_output_chars);

    let mut body = format!("  PS> {}\n", audit(command));
    body.push_str("\n  ── stdout ──\n");
    body.push_str(&indent(&audit_stdout));
    if !audit_stderr.is_empty() {
        body.push_str("\n\n  ── stderr ──\n");
        body.push_str(&indent(&audit_stderr));
    }
    body
}

/// Label of the password source for the audit (ADR-0009).
fn origin_label(origin: IdentityOrigin) -> &'static str {
    match origin {
        IdentityOrigin::Headers => "headers",
        IdentityOrigin::Profile => "profile",
    }
}

fn password_hash(password: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.finalize().into()
}

/// Takes the mutex, recovering after poisoning.
///
/// A panic in a thread that holds the mutex must not turn later requests into panics: the
/// registry state is caches and counters, not an invariant that cannot be restored. The
/// audit and the logging must keep working.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn strip_clixml(stderr: &str) -> String {
    // PowerShell packs progress into CLIXML; cut out the `<Objs>...</Objs>` block.
    let trimmed = stderr.trim();
    if let Some(start) = trimmed.find("#< CLIXML")
        && let Some(end) = trimmed[start..].find("</Objs>")
    {
        let mut cleaned = String::from(&trimmed[..start]);
        cleaned.push_str(&trimmed[start + end + "</Objs>".len()..]);
        return cleaned.trim().to_owned();
    }
    trimmed.to_owned()
}

fn indent(text: &str) -> String {
    if text.trim().is_empty() {
        return "  (empty)".to_owned();
    }
    text.lines()
        .map(|line| format!("  {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format_time(UNIX_EPOCH + now)
}

fn format_time(time: SystemTime) -> String {
    // No external date crate: emit epoch seconds, which is stable and enough for session
    // metadata.
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => format!("{}", duration.as_secs()),
        Err(_) => "0".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// Buffer the test `tracing` subscriber writes the log and the audit into.
    #[derive(Clone, Default)]
    struct Captured(Arc<StdMutex<Vec<u8>>>);

    thread_local! {
        /// Capture buffer of the current thread; `None` drops the events.
        static SINK: std::cell::RefCell<Option<Captured>> = const { std::cell::RefCell::new(None) };
    }

    /// Writer of the global subscriber: stores the event in the thread buffer.
    struct ThreadSink;

    impl std::io::Write for ThreadSink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            SINK.with(|sink| {
                if let Some(captured) = sink.borrow().as_ref() {
                    captured.0.lock().expect("lock").extend_from_slice(bytes);
                }
            });
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Intercepts `tracing` events of the current thread, the audit included.
    ///
    /// One subscriber serves the whole test binary and is installed globally: per-thread
    /// temporary subscribers race with parallel tests over the shared callsite-interest
    /// cache and lose events. A global subscriber is always interested in everything, and
    /// the thread buffer splits the events by test. `tokio::test` runs the test on the same
    /// thread, so asynchronous tests are visible too.
    ///
    /// The callsite-interest cache is process-wide and `tracing` never revisits it by itself.
    /// `capture` rebuilds it, so a callsite first seen while the subscriber was being
    /// installed (cached as `never`) is interested again.
    struct Capture {
        captured: Captured,
    }

    impl Capture {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.captured.0.lock().expect("lock")).into_owned()
        }
    }

    impl Drop for Capture {
        fn drop(&mut self) {
            SINK.with(|sink| sink.borrow_mut().take());
        }
    }

    fn capture() -> Capture {
        static INSTALL: std::sync::Once = std::sync::Once::new();
        INSTALL.call_once(|| {
            let subscriber = tracing_subscriber::fmt()
                .with_writer(|| ThreadSink)
                .with_ansi(false)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("no other global subscriber in unit tests");
        });
        // The install registers the dispatcher before it becomes the default, so a callsite
        // first hit in that window is cached as `never` and stays dead. Rebuild the cache now
        // that the subscriber is the default; `tracing` does not revisit it on its own.
        tracing::callsite::rebuild_interest_cache();
        let captured = Captured::default();
        SINK.with(|sink| *sink.borrow_mut() = Some(captured.clone()));
        Capture { captured }
    }

    // A stand-in callsite whose interest can be forced to the `never` state the install window
    // produces. It is not a macro callsite, so a test can reach it.
    static PROBE_META: tracing::Metadata<'static> = tracing::Metadata::new(
        "probe",
        "winrig::probe",
        tracing::Level::INFO,
        None,
        None,
        None,
        tracing::field::FieldSet::new(&["message"], tracing::callsite::Identifier(&PROBE_CALLSITE)),
        tracing::metadata::Kind::EVENT,
    );

    static PROBE_CALLSITE: tracing::callsite::DefaultCallsite =
        tracing::callsite::DefaultCallsite::new(&PROBE_META);

    // Emits the probe the way the `tracing` macro does: a `never` interest skips the event.
    fn emit_probe() {
        if PROBE_CALLSITE.interest().is_never() {
            return;
        }
        let values = [Some(&"PROBE" as &dyn tracing::field::Value)];
        let set = PROBE_META.fields().value_set_all(&values);
        tracing::Event::dispatch(&PROBE_META, &set);
    }

    /// Records the commands it gets and returns preset answers.
    struct FakeTransport {
        calls: StdMutex<Vec<(String, String)>>,
        credentials: StdMutex<Vec<(String, String)>>,
        result: StdMutex<Result<RemoteOutput, TransportError>>,
    }

    impl FakeTransport {
        fn returning(output: RemoteOutput) -> Self {
            Self {
                calls: StdMutex::new(Vec::new()),
                credentials: StdMutex::new(Vec::new()),
                result: StdMutex::new(Ok(output)),
            }
        }

        fn failing(error: TransportError) -> Self {
            Self {
                calls: StdMutex::new(Vec::new()),
                credentials: StdMutex::new(Vec::new()),
                result: StdMutex::new(Err(error)),
            }
        }

        fn set_result(&self, result: Result<RemoteOutput, TransportError>) {
            *self.result.lock().expect("result lock") = result;
        }

        fn calls(&self) -> Vec<(String, String)> {
            self.calls.lock().expect("calls lock").clone()
        }

        fn credentials(&self) -> Vec<(String, String)> {
            self.credentials.lock().expect("credentials lock").clone()
        }
    }

    #[async_trait::async_trait]
    impl WinRmTransport for FakeTransport {
        async fn run_powershell(
            &self,
            target: &SessionTarget,
            script: &str,
        ) -> Result<RemoteOutput, TransportError> {
            self.calls
                .lock()
                .expect("calls lock")
                .push((target.host.clone(), script.to_owned()));
            self.credentials.lock().expect("credentials lock").push((
                target.username.clone(),
                target.password.expose_secret().to_owned(),
            ));
            self.result.lock().expect("result lock").clone()
        }
    }

    fn output(stdout: &str, stderr: &str, code: i32) -> RemoteOutput {
        RemoteOutput {
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
            exit_code: code,
        }
    }

    fn registry(transport: Arc<FakeTransport>) -> SessionRegistry {
        SessionRegistry::new(transport, RegistryConfig::default())
    }

    /// `DOMAIN\user` splits into domain and name: without this NTLM puts the string with the
    /// backslash into the hash and AD rejects the logon. The split matches `spnego`: a UPN
    /// and a bare name are not split, the case is unchanged.
    #[test]
    fn split_account_handles_all_forms() {
        assert_eq!(
            split_account("contoso\\alice"),
            ("alice".to_owned(), "contoso".to_owned())
        );
        assert_eq!(
            split_account("CONTOSO\\Alice"),
            ("Alice".to_owned(), "CONTOSO".to_owned())
        );
        // UPN: spnego does not split it, so the domain stays empty.
        assert_eq!(
            split_account("alice@contoso.local"),
            ("alice@contoso.local".to_owned(), String::new())
        );
        assert_eq!(split_account("alice"), ("alice".to_owned(), String::new()));
        // Split at the first backslash; the rest stays the name.
        assert_eq!(
            split_account("dom\\nested\\user"),
            ("nested\\user".to_owned(), "dom".to_owned())
        );
    }

    /// `credentials_for` passes a clean name without a domain to `winrm-rs`.
    #[test]
    fn credentials_for_splits_domain() {
        let target = SessionTarget {
            host: "host1".to_owned(),
            port: DEFAULT_HTTP_PORT,
            use_tls: false,
            verify_cert: true,
            username: "contoso\\alice".to_owned(),
            password: SecretString::from("secret"),
        };
        let credentials = credentials_for(&target);
        assert_eq!(credentials.username, "alice");
        assert_eq!(credentials.domain, "contoso");
        assert_eq!(credentials.password.expose_secret(), "secret");
    }

    #[tokio::test]
    async fn connect_stores_session_and_reports_host() {
        let transport = Arc::new(FakeTransport::returning(output(
            "HOST1|Windows Server 2022|10.0|2026-01-01 10:00:00",
            "",
            0,
        )));
        let registry = registry(transport.clone());
        let identity = UserIdentity::with_password("alice", "s3cret");
        let reply = registry.connect(&identity, "host1", None, None, true).await;
        assert_eq!(reply["status"], "connected");
        assert_eq!(reply["computer_name"], "HOST1");
        assert_eq!(reply["os"], "Windows Server 2022");
        assert_eq!(registry.list_sessions("alice")["count"], 1);
        assert_eq!(transport.calls().len(), 1);
    }

    #[tokio::test]
    async fn connect_without_password_is_refused() {
        let transport = Arc::new(FakeTransport::returning(output("", "", 0)));
        let registry = registry(transport);
        let reply = registry
            .connect(&UserIdentity::new("bob"), "host1", None, None, true)
            .await;
        assert!(
            reply["error"]
                .as_str()
                .is_some_and(|error| error.contains("X-AD-Password"))
        );
    }

    /// AC-SEC13-1: on the header path a password cached under one name does not open a
    /// session. Otherwise a holder of the shared secret, naming another's `X-AD-User`,
    /// would connect with that password (TR-SEC-13).
    #[tokio::test]
    async fn header_connect_without_password_ignores_the_cached_one() {
        let transport = Arc::new(FakeTransport::returning(output("HOST1||||", "", 0)));
        let registry = registry(Arc::clone(&transport));
        let alice = UserIdentity::with_password("alice", "a-secret");
        let _ = registry.connect(&alice, "host1", None, None, true).await;
        assert!(registry.has_cached_password("alice"));
        let calls_before = transport.calls().len();

        let impostor = UserIdentity::new("alice");
        let reply = registry.connect(&impostor, "host2", None, None, true).await;

        let error = reply["error"].as_str().expect("refused");
        assert!(error.contains("X-AD-Password"), "{error}");
        assert_eq!(
            transport.calls().len(),
            calls_before,
            "the refused connect reached the transport"
        );
        assert_eq!(registry.list_sessions("alice")["count"], 1);
        // There was no password, so there was no credential failure either.
        assert!(registry.check_lockout("alice").is_none());
        assert!(!lock(&registry.failures).contains_key("alice"));
    }

    #[tokio::test]
    async fn auth_failure_is_reported_and_cached_password_dropped() {
        let transport = Arc::new(FakeTransport::failing(TransportError::AuthFailed(
            "credentials were rejected".to_owned(),
        )));
        let registry = registry(transport);
        let identity = UserIdentity::with_password("alice", "wrong");
        let reply = registry.connect(&identity, "host1", None, None, true).await;
        assert_eq!(reply["auth_failed"], true);
        assert!(!registry.has_cached_password("alice"));
    }

    /// TR-SEC-10: `winrm-rs` puts any failed HTTP status into `AuthFailed`, not only a
    /// credential failure. An empty 500 arrives after NTLM was accepted, so it is not a
    /// password failure.
    #[test]
    fn empty_500_is_not_an_auth_failure() {
        let rejected = map_error(winrm_rs::WinrmError::AuthFailed(
            "HTTP 500 Internal Server Error: ".to_owned(),
        ));
        assert!(!rejected.is_auth_failure());
        let text = rejected.to_string();
        assert!(
            text.contains("5986"),
            "a hint about HTTPS is required: {text}"
        );
        assert!(
            text.contains("AllowUnencrypted"),
            "a hint about AllowUnencrypted is required: {text}"
        );
        assert!(
            !text.contains("authentication failed"),
            "this is not a credential failure: {text}"
        );
    }

    /// TR-SEC-10: other HTTP statuses are not a password failure either, but the encryption
    /// hint is not attached to them.
    #[test]
    fn other_http_status_is_rejected_without_the_hint() {
        let rejected = map_error(winrm_rs::WinrmError::AuthFailed(
            "HTTP 503 Service Unavailable: busy".to_owned(),
        ));
        assert!(!rejected.is_auth_failure());
        let text = rejected.to_string();
        assert!(text.contains("503"), "the status must be kept: {text}");
        assert!(
            !text.contains("AllowUnencrypted"),
            "no extra hint expected: {text}"
        );
    }

    /// TR-SEC-10: a real credential failure is still recognized.
    #[test]
    fn ntlm_rejection_stays_an_auth_failure() {
        let error = map_error(winrm_rs::WinrmError::AuthFailed(
            "NTLM authentication rejected (bad credentials or CBT mismatch)".to_owned(),
        ));
        assert!(error.is_auth_failure());
    }

    /// TR-SEC-10: a rejected request does not touch the password cache — otherwise a
    /// misconfigured listener forces the password to be entered again.
    #[tokio::test]
    async fn rejected_request_keeps_cached_password() {
        let transport = Arc::new(FakeTransport::failing(TransportError::Rejected(
            "the host returned HTTP 500 with an empty body".to_owned(),
        )));
        let registry = registry(transport);
        let identity = UserIdentity::with_password("alice", "s3cret");
        let reply = registry.connect(&identity, "host1", None, None, true).await;
        assert!(
            reply.get("auth_failed").is_none(),
            "not a credential failure: {reply}"
        );
        assert!(registry.has_cached_password("alice"));
    }

    /// TR-SEC-10: however many times the listener rejects the request, the profile is not
    /// refused and the lockout does not engage (compare AC-PRF-56).
    #[tokio::test]
    async fn rejected_request_never_refuses_profile() {
        let transport = Arc::new(FakeTransport::failing(TransportError::Rejected(
            "the host returned HTTP 500 with an empty body".to_owned(),
        )));
        let registry = SessionRegistry::new(
            transport.clone(),
            RegistryConfig {
                lockout_max_attempts: 3,
                lockout_window: Duration::from_secs(1800),
                ..RegistryConfig::default()
            },
        );
        for _ in 0..3 {
            let identity = UserIdentity::from_profile("alice", SecretString::from("right"));
            let _ = registry.connect(&identity, "host1", None, None, true).await;
        }
        registry.force_lockout_window_elapsed("alice");
        for _ in 0..3 {
            let identity = UserIdentity::from_profile("alice", SecretString::from("right"));
            let _ = registry.connect(&identity, "host1", None, None, true).await;
        }
        assert!(
            !registry.is_profile_refused("alice"),
            "the profile must not be refused"
        );
        // The transport was called all six times: the lockout never stepped in.
        assert_eq!(transport.calls().len(), 6);
    }

    #[tokio::test]
    async fn lockout_blocks_fourth_attempt_without_transport() {
        let transport = Arc::new(FakeTransport::failing(TransportError::AuthFailed(
            "nope".to_owned(),
        )));
        let registry = SessionRegistry::new(
            transport.clone(),
            RegistryConfig {
                lockout_max_attempts: 3,
                lockout_window: Duration::from_secs(1800),
                ..RegistryConfig::default()
            },
        );
        for _ in 0..3 {
            let identity = UserIdentity::with_password("alice", "wrong");
            let reply = registry.connect(&identity, "host1", None, None, true).await;
            assert_eq!(reply["auth_failed"], true);
        }
        let calls_before = transport.calls().len();

        let identity = UserIdentity::with_password("alice", "wrong");
        let reply = registry.connect(&identity, "host1", None, None, true).await;
        assert_eq!(reply["locked_out"], true);
        assert_eq!(transport.calls().len(), calls_before);
    }

    /// AC-SEC13-2: `connect` without a password answers "password required" before it
    /// reveals another user's lockout (ADR-0015).
    #[tokio::test]
    async fn connect_without_password_does_not_reveal_lockout() {
        let transport = Arc::new(FakeTransport::failing(TransportError::AuthFailed(
            "nope".to_owned(),
        )));
        let registry = registry(transport);
        for _ in 0..4 {
            let identity = UserIdentity::with_password("alice", "wrong");
            let _ = registry.connect(&identity, "host1", None, None, true).await;
        }
        let reply = registry
            .connect(&UserIdentity::new("alice"), "host1", None, None, true)
            .await;
        assert!(reply.get("locked_out").is_none(), "{reply}");
        assert!(
            reply["error"]
                .as_str()
                .is_some_and(|error| error.contains("X-AD-Password")),
            "{reply}"
        );
    }

    #[tokio::test]
    async fn different_password_bypasses_lockout() {
        let transport = Arc::new(FakeTransport::failing(TransportError::AuthFailed(
            "nope".to_owned(),
        )));
        let registry = SessionRegistry::new(
            transport.clone(),
            RegistryConfig {
                lockout_max_attempts: 3,
                ..RegistryConfig::default()
            },
        );
        for _ in 0..3 {
            let identity = UserIdentity::with_password("alice", "wrong");
            let _ = registry.connect(&identity, "host1", None, None, true).await;
        }
        let calls_before = transport.calls().len();
        let identity = UserIdentity::with_password("alice", "other");
        let reply = registry.connect(&identity, "host1", None, None, true).await;
        assert!(reply.get("locked_out").is_none());
        assert_eq!(transport.calls().len(), calls_before + 1);
    }

    #[tokio::test]
    async fn run_ps_redacts_secret_from_reply_and_audit() {
        let transport = Arc::new(FakeTransport::returning(output(
            "value=supersecret done",
            "",
            0,
        )));
        let registry = registry(transport);
        let identity = UserIdentity::with_password("alice", "s3cret");
        let _ = registry.connect(&identity, "host1", None, None, true).await;
        let reply = registry
            .run_ps(
                "alice",
                "host1",
                "echo supersecret",
                "read_file",
                &["supersecret".to_owned()],
            )
            .await;
        assert!(!reply["stdout"].as_str().unwrap().contains("supersecret"));
        assert!(reply["stdout"].as_str().unwrap().contains("***"));
    }

    #[tokio::test]
    async fn run_ps_redacts_session_password_without_explicit_redactions() {
        // Production path: the server passes an empty list, but the session password must
        // still be redacted from the reply and the audit (DR-4).
        let transport = Arc::new(FakeTransport::returning(output(
            "HOST1|Windows|10.0|2026-01-01 00:00:00",
            "",
            0,
        )));
        let registry = registry(transport.clone());
        let identity = UserIdentity::with_password("alice", "supersecret");
        let _ = registry.connect(&identity, "host1", None, None, true).await;
        transport.set_result(Ok(output("registry value=supersecret", "", 0)));
        let reply = registry
            .run_ps("alice", "host1", "Get-Thing", "get_services", &[])
            .await;
        assert!(
            !reply["stdout"].as_str().unwrap().contains("supersecret"),
            "session password leaked into reply: {reply}"
        );
        assert!(reply["stdout"].as_str().unwrap().contains("***"));
    }

    /// AC-PRF-14: a profile password is redacted on the production `run_ps` path just like
    /// a header password.
    #[tokio::test]
    async fn run_ps_redacts_profile_password() {
        let transport = Arc::new(FakeTransport::returning(output(
            "HOST1|Windows|10.0|2026-01-01 00:00:00",
            "",
            0,
        )));
        let registry = registry(transport.clone());
        let identity =
            UserIdentity::from_profile("alice", SecretString::from("profilesupersecret"));
        let _ = registry.connect(&identity, "host1", None, None, true).await;
        transport.set_result(Ok(output("value=profilesupersecret", "", 0)));
        let reply = registry
            .run_ps("alice", "host1", "Get-Thing", "get_services", &[])
            .await;
        assert!(
            !reply["stdout"]
                .as_str()
                .unwrap()
                .contains("profilesupersecret"),
            "profile password leaked into reply: {reply}"
        );
        assert!(reply["stdout"].as_str().unwrap().contains("***"));
    }

    #[test]
    fn command_audit_body_redacts_below_reply_threshold() {
        // DR-4: the audit is redacted unconditionally (min_length=1), even if the secret is
        // shorter than WINRIG_SECRET_REDACT_MIN_LENGTH (that threshold is only for the reply
        // to the agent, ADR-0005 §2). The pure function is checked deterministically.
        let secrets = ["abc".to_owned()];
        let body = command_audit_body("echo abc", "value=abc done", "err abc here", &secrets, 2000);
        assert!(!body.contains("abc"), "secret leaked into audit: {body}");
        assert!(body.contains("***"));
    }

    #[test]
    fn command_audit_body_respects_output_cap() {
        let body = command_audit_body("cmd", &"x".repeat(100), "", &[], 10);
        assert!(body.contains("truncated"));
    }

    #[tokio::test]
    async fn run_ps_on_unknown_session_reports_error() {
        let transport = Arc::new(FakeTransport::returning(output("", "", 0)));
        let registry = registry(transport);
        let reply = registry.run_ps("alice", "nope", "Get-Date", "", &[]).await;
        assert!(reply["error"].as_str().is_some());
    }

    #[tokio::test]
    async fn sessions_are_isolated_per_user() {
        let transport = Arc::new(FakeTransport::returning(output("HOST1||||", "", 0)));
        let registry = registry(transport);
        let alice = UserIdentity::with_password("alice", "a");
        let bob = UserIdentity::with_password("bob", "b");
        // Alice connects over HTTPS (session_id "host1:5986"), Bob over HTTP
        // (session_id "host1"). The identifiers differ, and Bob must not reach Alice's
        // session.
        let _ = registry
            .connect(&alice, "host1", Some(5986), Some(true), true)
            .await;
        let _ = registry.connect(&bob, "host1", None, None, true).await;

        assert_eq!(registry.list_sessions("alice")["count"], 1);
        assert_eq!(registry.list_sessions("bob")["count"], 1);
        assert_eq!(
            registry.list_sessions("alice")["sessions"][0]["session_id"],
            "host1:5986"
        );
        assert_eq!(
            registry.list_sessions("bob")["sessions"][0]["session_id"],
            "host1"
        );

        let reply = registry
            .run_ps("bob", "host1:5986", "Get-Date", "", &[])
            .await;
        assert_eq!(
            reply["error"],
            "Session not found: host1:5986. Use connect first."
        );
    }

    #[tokio::test]
    async fn connect_failure_stderr_is_redacted() {
        // DR-4: a password that lands in the host error text must not leak into the reply.
        let transport = Arc::new(FakeTransport::returning(output(
            "",
            "Access denied for password supersecret",
            1,
        )));
        let registry = registry(transport);
        let identity = UserIdentity::with_password("alice", "supersecret");
        let reply = registry.connect(&identity, "host1", None, None, true).await;
        let error = reply["error"].as_str().expect("error field");
        assert!(!error.contains("supersecret"), "leaked: {error}");
        assert!(error.contains("***"));
    }

    #[tokio::test]
    async fn lockout_window_expiry_allows_same_password_again() {
        // AC-SEC01-4: after the window expires the same password reaches the transport again.
        let transport = Arc::new(FakeTransport::failing(TransportError::AuthFailed(
            "nope".to_owned(),
        )));
        let registry = SessionRegistry::new(
            transport.clone(),
            RegistryConfig {
                lockout_max_attempts: 3,
                lockout_window: Duration::from_secs(1),
                ..RegistryConfig::default()
            },
        );
        for _ in 0..3 {
            let identity = UserIdentity::with_password("alice", "wrong");
            let _ = registry.connect(&identity, "host1", None, None, true).await;
        }
        // The fourth attempt is blocked without the transport.
        let before = transport.calls().len();
        let identity = UserIdentity::with_password("alice", "wrong");
        let locked = registry.connect(&identity, "host1", None, None, true).await;
        assert_eq!(locked["locked_out"], true);
        assert_eq!(transport.calls().len(), before);

        // The window expired: the same attempt reaches the transport again.
        registry.force_lockout_window_elapsed("alice");
        let identity = UserIdentity::with_password("alice", "wrong");
        let after = registry.connect(&identity, "host1", None, None, true).await;
        assert!(after.get("locked_out").is_none());
        assert_eq!(transport.calls().len(), before + 1);
    }
    #[test]
    fn empty_command_failure_mentions_suppressed_error() {
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        runtime.block_on(async {
            let transport = Arc::new(FakeTransport::returning(output("HOST1||||", "", 0)));
            let registry = registry(transport.clone());
            let identity = UserIdentity::with_password("alice", "s3cret");
            let _ = registry.connect(&identity, "host1", None, None, true).await;
            // The probe command of connect passed; now the tool command exits with a
            // non-zero code and no output.
            transport.set_result(Ok(output("", "", 1)));
            let reply = registry
                .run_ps("alice", "host1", "Get-Service nope", "", &[])
                .await;
            assert!(reply["error"].as_str().unwrap().contains("suppressed"));
        });
    }

    /// AC-PRF-05/13: a profile password reaches the transport under the same user as a
    /// header password.
    #[tokio::test]
    async fn profile_identity_reaches_transport() {
        let transport = Arc::new(FakeTransport::returning(output(
            "HOST1|OS|1.0|2026-01-01 00:00:00",
            "",
            0,
        )));
        let registry = registry(transport.clone());
        let identity = UserIdentity::from_profile("domain\\alice", SecretString::from("s3cret"));
        let reply = registry.connect(&identity, "host1", None, None, true).await;
        assert_eq!(reply["status"], "connected");
        assert_eq!(
            transport.credentials(),
            [("domain\\alice".to_owned(), "s3cret".to_owned())]
        );
    }

    /// AC-PRF-05: the identity source in the audit distinguishes the profile and the header.
    #[test]
    fn origin_label_distinguishes_sources() {
        assert_eq!(origin_label(IdentityOrigin::Profile), "profile");
        assert_eq!(origin_label(IdentityOrigin::Headers), "headers");
    }

    /// AC-PRF-13: the lockout also covers a password that came from the profile.
    #[tokio::test]
    async fn lockout_applies_to_profile_password() {
        let transport = Arc::new(FakeTransport::failing(TransportError::AuthFailed(
            "nope".to_owned(),
        )));
        let registry = SessionRegistry::new(
            transport.clone(),
            RegistryConfig {
                lockout_max_attempts: 3,
                lockout_window: Duration::from_secs(1800),
                ..RegistryConfig::default()
            },
        );
        for _ in 0..3 {
            let identity = UserIdentity::from_profile("alice", SecretString::from("wrong"));
            let _ = registry.connect(&identity, "host1", None, None, true).await;
        }
        let before = transport.calls().len();
        let identity = UserIdentity::from_profile("alice", SecretString::from("wrong"));
        let locked = registry.connect(&identity, "host1", None, None, true).await;
        assert_eq!(locked["locked_out"], true);
        assert_eq!(transport.calls().len(), before);
    }

    /// AC-PRF-56: a second run of the failure threshold for a profile turns it into a
    /// refusal, and the transport is no longer called.
    #[tokio::test]
    async fn profile_password_rejected_twice_is_refused() {
        let transport = Arc::new(FakeTransport::failing(TransportError::AuthFailed(
            "nope".to_owned(),
        )));
        let registry = SessionRegistry::new(
            transport.clone(),
            RegistryConfig {
                lockout_max_attempts: 3,
                lockout_window: Duration::from_secs(1800),
                ..RegistryConfig::default()
            },
        );
        for _ in 0..3 {
            let identity = UserIdentity::from_profile("alice", SecretString::from("wrong"));
            let _ = registry.connect(&identity, "host1", None, None, true).await;
        }
        // The window expired: a second round of three failures.
        registry.force_lockout_window_elapsed("alice");
        for _ in 0..3 {
            let identity = UserIdentity::from_profile("alice", SecretString::from("wrong"));
            let _ = registry.connect(&identity, "host1", None, None, true).await;
        }
        assert!(
            registry.is_profile_refused("alice"),
            "the profile must be refused"
        );
        let before = transport.calls().len();
        let identity = UserIdentity::from_profile("alice", SecretString::from("wrong"));
        let refused = registry.connect(&identity, "host1", None, None, true).await;
        assert_eq!(refused["auth_failed"], true);
        assert_eq!(transport.calls().len(), before);
        // Exactly six transport calls for two rounds of three failures.
        assert_eq!(before, 6);
    }

    /// AC-PRF-56: the profile is not refused when the password came from a header.
    #[tokio::test]
    async fn header_password_does_not_refuse_profile() {
        let transport = Arc::new(FakeTransport::failing(TransportError::AuthFailed(
            "nope".to_owned(),
        )));
        let registry = SessionRegistry::new(
            transport,
            RegistryConfig {
                lockout_max_attempts: 3,
                lockout_window: Duration::from_secs(1),
                ..RegistryConfig::default()
            },
        );
        for _ in 0..3 {
            let identity = UserIdentity::with_password("alice", "wrong");
            let _ = registry.connect(&identity, "host1", None, None, true).await;
        }
        registry.force_lockout_window_elapsed("alice");
        for _ in 0..3 {
            let identity = UserIdentity::with_password("alice", "wrong");
            let _ = registry.connect(&identity, "host1", None, None, true).await;
        }
        assert!(!registry.is_profile_refused("alice"));
    }

    /// AC-PRF-57: a successful connect clears the count of back-to-back lockouts.
    #[tokio::test]
    async fn successful_connect_resets_lockout_streak() {
        let transport = Arc::new(FakeTransport::failing(TransportError::AuthFailed(
            "nope".to_owned(),
        )));
        let registry = SessionRegistry::new(
            transport.clone(),
            RegistryConfig {
                lockout_max_attempts: 3,
                lockout_window: Duration::from_secs(1),
                ..RegistryConfig::default()
            },
        );
        for _ in 0..3 {
            let identity = UserIdentity::with_password("alice", "wrong");
            let _ = registry.connect(&identity, "host1", None, None, true).await;
        }
        registry.force_lockout_window_elapsed("alice");
        transport.set_result(Ok(output("HOST1|OS|1.0|2026-01-01 00:00:00", "", 0)));
        let identity = UserIdentity::with_password("alice", "right");
        let ok = registry.connect(&identity, "host1", None, None, true).await;
        assert_eq!(ok["status"], "connected");
        // The streak is empty: the next lockout is the first again.
        assert!(lock(&registry.lockout_streak).get("alice").is_none());
    }

    /// AC-OBS03-1: a policy refusal is written to the audit as its own record with the user,
    /// the tool, the code and the reason (TR-OBS-03).
    #[test]
    fn policy_refusal_is_audited() {
        let registry = registry(Arc::new(FakeTransport::returning(output("", "", 0))));
        let captured = capture();
        registry.audit_refusal(
            "domain\\alice",
            "connect",
            "HOST_NOT_ALLOWED",
            "host \"evil\" is not allowed\nforged: line",
        );
        let text = captured.text();
        assert!(text.contains("POLICY REFUSED"), "{text}");
        assert!(text.contains("domain\\alice"), "{text}");
        assert!(text.contains("connect"), "{text}");
        assert!(text.contains("HOST_NOT_ALLOWED"), "{text}");
        // TR-SEC-09: the reason does not forge the record structure.
        assert!(!text.contains("\nforged: line"), "{text}");
    }

    /// AC-OBS03-1: a `connect` without a password lands in the audit as a policy refusal,
    /// not as a credential failure.
    #[tokio::test]
    async fn connect_without_password_is_audited() {
        let registry = registry(Arc::new(FakeTransport::returning(output("", "", 0))));
        let captured = capture();
        let _ = registry
            .connect(&UserIdentity::new("bob"), "host1", None, None, true)
            .await;
        let text = captured.text();
        assert!(text.contains("POLICY REFUSED"), "{text}");
        assert!(text.contains("PASSWORD_REQUIRED"), "{text}");
        assert!(!text.contains("AUTH LOCKOUT"), "{text}");
    }

    /// The audit callsite is one static location whose interest `tracing` caches for the whole
    /// process. A callsite first seen while the subscriber was being installed is cached as
    /// `never` and stays dead. `capture` rebuilds the cache, so the entry does not outlive it.
    #[test]
    fn capture_revives_a_callsite_cached_as_never() {
        use tracing::callsite::Callsite as _;
        let _installed = capture();
        tracing::callsite::register(&PROBE_CALLSITE);
        PROBE_CALLSITE.set_interest(tracing::subscriber::Interest::never());
        // A parallel test can also call `capture`; every call rebuilds the cache, so the
        // forced `never` cannot outlive the next one.
        let captured = capture();
        assert!(
            !PROBE_CALLSITE.interest().is_never(),
            "capture must rebuild the interest cache"
        );
        emit_probe();
        assert!(captured.text().contains("PROBE"), "{}", captured.text());
    }
}
