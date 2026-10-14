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

/// Prefix of every command sent to the host.
///
/// `winrm-rs` sets `WINRS_CODEPAGE=65001` at the cmd shell level, but `powershell.exe`
/// uses its own `[Console]::OutputEncoding` for redirected output. On a localized Windows
/// it does not hold the system language, and PowerShell replaces unrepresentable
/// characters with `?` before it sends the bytes, so no decoding on this side can bring
/// them back. The try/catch wrapper is for a host without a console (port of
/// `UTF8_PREAMBLE` from the Python version). `$ProgressPreference` stops the progress
/// stream, which otherwise writes a localized CLIXML record to stderr on the first use
/// of a module (TR-REL-10).
pub const PREAMBLE: &str = "try { [Console]::OutputEncoding = [Text.Encoding]::UTF8; \
     $OutputEncoding = [Text.Encoding]::UTF8 } catch { }; \
     $ProgressPreference = 'SilentlyContinue'; ";

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

/// One confirmed `run_script` operation: the staging chunks, the command that
/// verifies and runs the script, the command that removes the staging file, the
/// script text for the audit and the confirmed SHA-256 (ADR-0017 §29–33).
pub struct ScriptRun<'a> {
    /// The write commands that create and append the staging `.ps1`.
    pub chunks: &'a [String],
    /// The command that verifies and executes the staging script as a script block.
    pub run: &'a str,
    /// The command that removes the staging file once the run has finished.
    pub cleanup: &'a str,
    /// The script text, shown redacted and indented in the audit (DR-4).
    pub display: &'a str,
    /// The confirmed SHA-256 of the script bytes, recorded in the audit.
    pub hash: &'a str,
}

/// The fields of one file-transfer audit record (ADR-0017 §38).
///
/// The record holds the resolved paths, the size, both SHA-256 values when they are
/// known and the confirmation state; it never holds content (DR-4).
pub struct AuditTransfer<'a> {
    pub username: &'a str,
    pub tool: &'a str,
    /// WinRM target of the session, for the audit record.
    pub host: &'a str,
    /// The file on the Windows host, as the host resolved it.
    pub remote_path: &'a str,
    /// The file on this computer, as the server resolved it.
    pub local_path: &'a str,
    pub size: i64,
    /// Digest the host computed; empty until it returns.
    pub host_hash: &'a str,
    /// The SHA-256 the server computed while it transferred; empty until then.
    pub local_hash: &'a str,
    /// `confirmed`, `unsupported` or `cancelled`.
    pub confirmation: &'a str,
    /// `downloaded`, `uploaded`, `failed` or `cancelled`.
    pub status: &'a str,
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

    /// Runs the script with `stdin` as its standard input (TR-XFER-04, ADR-0017 §26).
    ///
    /// The bytes do not count against the WinRS command line, so one call carries a
    /// whole upload window.
    ///
    /// # Errors
    ///
    /// [`TransportError`] if the connection or the authentication fails, or if the
    /// transport cannot send standard input.
    async fn run_powershell_stdin(
        &self,
        _target: &SessionTarget,
        _script: &str,
        _stdin: &[u8],
    ) -> Result<RemoteOutput, TransportError> {
        Err(TransportError::Other(
            "this transport cannot send standard input".to_owned(),
        ))
    }
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
        let client = winrm_client(target)?;
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

    async fn run_powershell_stdin(
        &self,
        target: &SessionTarget,
        script: &str,
        stdin: &[u8],
    ) -> Result<RemoteOutput, TransportError> {
        let client = Arc::new(winrm_client(target)?);
        let shell = client.open_shell(&target.host).await.map_err(map_error)?;
        // A dropped future (a client disconnect) leaves the host command blocked on
        // its standard input. The guard terminates the command and closes the shell
        // from a task (TR-XFER-04).
        let mut guard = CallGuard {
            cleanup: Arc::new(ClientCleanup {
                client: Arc::clone(&client),
                host: target.host.clone(),
                shell_id: shell.shell_id().to_owned(),
            }),
            command_id: None,
            armed: true,
        };
        let result = tokio::time::timeout(
            STDIN_CALL_TIMEOUT,
            drive_stdin_call(
                &ShellCall(&shell),
                script,
                stdin,
                &mut guard,
                SEND_ERROR_DRAIN,
            ),
        )
        .await;
        match result {
            Ok(Ok(output)) => {
                guard.armed = false;
                shell.close().await.ok();
                Ok(output)
            }
            Ok(Err(error)) => {
                guard.run_cleanup().await;
                Err(map_error(error))
            }
            Err(_) => {
                guard.run_cleanup().await;
                Err(TransportError::Other(format!(
                    "the host call with standard input did not finish in {} seconds",
                    STDIN_CALL_TIMEOUT.as_secs()
                )))
            }
        }
    }
}

/// Bytes of standard input in one WS-Man `Send` message, before base64.
///
/// The base64 form of this size stays well under the 153 600-byte envelope that
/// `winrm-rs` declares (TR-XFER-04).
const STDIN_SEND_BYTES: usize = 64 * 1024;

/// Time limit of one call with standard input, for the whole window.
const STDIN_CALL_TIMEOUT: Duration = Duration::from_secs(600);

/// Output cap of one call with standard input; the upload scripts print one line.
const STDIN_OUTPUT_CAP: usize = 1024 * 1024;

fn winrm_client(target: &SessionTarget) -> Result<winrm_rs::WinrmClient, TransportError> {
    let config = winrm_rs::WinrmConfig {
        port: target.port,
        use_tls: target.use_tls,
        accept_invalid_certs: !target.verify_cert,
        ..winrm_rs::WinrmConfig::default()
    };
    winrm_rs::WinrmClient::new(config, credentials_for(target)).map_err(map_error)
}

/// How long the output is drained after a failed `Send`, to read the exit code and
/// the error text of a command that already ended (TR-XFER-04).
const SEND_ERROR_DRAIN: Duration = Duration::from_secs(10);

/// Answer of one receive request for a running host command.
struct Poll {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_code: Option<i32>,
    done: bool,
}

/// The steps of a host command with standard input, as the transport needs them.
#[async_trait::async_trait]
trait StdinCall: Send + Sync {
    async fn start(&self, script: &str) -> Result<String, winrm_rs::WinrmError>;
    async fn send(
        &self,
        command_id: &str,
        data: &[u8],
        end_of_stream: bool,
    ) -> Result<(), winrm_rs::WinrmError>;
    async fn receive(&self, command_id: &str) -> Result<Poll, winrm_rs::WinrmError>;
}

struct ShellCall<'a>(&'a winrm_rs::Shell<'a>);

#[async_trait::async_trait]
impl StdinCall for ShellCall<'_> {
    async fn start(&self, script: &str) -> Result<String, winrm_rs::WinrmError> {
        let encoded = winrm_rs::encode_powershell_command(script);
        self.0
            .start_command("powershell.exe", &["-EncodedCommand", &encoded])
            .await
    }

    async fn send(
        &self,
        command_id: &str,
        data: &[u8],
        end_of_stream: bool,
    ) -> Result<(), winrm_rs::WinrmError> {
        self.0.send_input(command_id, data, end_of_stream).await
    }

    async fn receive(&self, command_id: &str) -> Result<Poll, winrm_rs::WinrmError> {
        let output = self.0.receive_next(command_id).await?;
        Ok(Poll {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.exit_code,
            done: output.done,
        })
    }
}

/// Best-effort release of a host command and its shell.
#[async_trait::async_trait]
trait ShellCleanup: Send + Sync {
    async fn terminate(&self, command_id: &str);
    async fn delete(&self);
}

struct ClientCleanup {
    client: Arc<winrm_rs::WinrmClient>,
    host: String,
    shell_id: String,
}

#[async_trait::async_trait]
impl ShellCleanup for ClientCleanup {
    async fn terminate(&self, command_id: &str) {
        let _ = self
            .client
            .signal_terminate(&self.host, &self.shell_id, command_id)
            .await;
    }

    async fn delete(&self) {
        let _ = self.client.delete_shell(&self.host, &self.shell_id).await;
    }
}

/// Terminates the command and deletes the shell when the call future is dropped
/// before it ends (TR-XFER-04).
///
/// The host command blocks on its standard input and holds the temp file open until
/// then. `drop` cannot wait, so a task sends the signal first and then deletes the
/// shell.
struct CallGuard {
    cleanup: Arc<dyn ShellCleanup>,
    command_id: Option<String>,
    armed: bool,
}

impl CallGuard {
    async fn run_cleanup(&mut self) {
        self.armed = false;
        if let Some(command_id) = &self.command_id {
            self.cleanup.terminate(command_id).await;
        }
        self.cleanup.delete().await;
    }
}

impl Drop for CallGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let cleanup = Arc::clone(&self.cleanup);
        let command_id = self.command_id.clone();
        runtime.spawn(async move {
            if let Some(command_id) = command_id {
                cleanup.terminate(&command_id).await;
            }
            cleanup.delete().await;
        });
    }
}

/// Starts the script, feeds `stdin` in `Send` messages, closes the stream and
/// collects the output (TR-XFER-04).
///
/// A failed `Send` does not end the call at once: a command that already ended
/// still has an exit code and an error text, which tell more than the broken pipe.
/// The output is drained for `drain`, and the send error stands only when the
/// command has not finished by then.
async fn drive_stdin_call(
    call: &dyn StdinCall,
    script: &str,
    stdin: &[u8],
    guard: &mut CallGuard,
    drain: Duration,
) -> Result<RemoteOutput, winrm_rs::WinrmError> {
    let command_id = call.start(script).await?;
    guard.command_id = Some(command_id.clone());
    let mut send_error = None;
    let mut parts = stdin.chunks(STDIN_SEND_BYTES).peekable();
    if parts.peek().is_none() {
        send_error = call.send(&command_id, &[], true).await.err();
    }
    while send_error.is_none()
        && let Some(part) = parts.next()
    {
        send_error = call
            .send(&command_id, part, parts.peek().is_none())
            .await
            .err();
    }
    let Some(send_error) = send_error else {
        return collect_output(call, &command_id).await;
    };
    match tokio::time::timeout(drain, collect_output(call, &command_id)).await {
        Ok(Ok(output)) if output.exit_code != -1 => Ok(output),
        _ => Err(send_error),
    }
}

/// Polls until the command is done and returns its output and exit code.
async fn collect_output(
    call: &dyn StdinCall,
    command_id: &str,
) -> Result<RemoteOutput, winrm_rs::WinrmError> {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_code = None;
    loop {
        let poll = call.receive(command_id).await?;
        stdout.extend_from_slice(&poll.stdout);
        stderr.extend_from_slice(&poll.stderr);
        if stdout.len() + stderr.len() > STDIN_OUTPUT_CAP {
            return Err(winrm_rs::WinrmError::Transfer(format!(
                "command output exceeded {STDIN_OUTPUT_CAP} bytes"
            )));
        }
        exit_code = poll.exit_code.or(exit_code);
        if poll.done {
            break;
        }
    }
    Ok(RemoteOutput {
        stdout,
        stderr,
        exit_code: exit_code.unwrap_or(-1),
    })
}

/// The listener rejected an unencrypted message when it answers HTTP 500 with an empty body.
const UNENCRYPTED_HINT: &str = "the host returned HTTP 500 with an empty body. \
     The host accepted the credentials, so this is not a password problem: WinRM answers \
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
                "error": "The host rejected the profile password twice. The server refuses the \
                          profile until the process restarts. Run 'winrig setup' to update it.",
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
                          request. The server does not use a cached password to open a session."
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
            .run_powershell(&target, &format!("{PREAMBLE}{probe}"))
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
                let stderr = strip_clixml(&String::from_utf8_lossy(&output.stderr), true);
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
                json!({ "error": format!("The connect test failed: {reply_stderr}") })
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

    /// The target of an open connection, for the text of the prompt (TR-SEC-16).
    ///
    /// `None` when no such connection is open; the caller shows an honest placeholder
    /// rather than an empty value.
    #[must_use]
    pub fn session_host(&self, username: &str, session_id: &str) -> Option<String> {
        lock(&self.sessions)
            .get(&(username.to_owned(), session_id.to_owned()))
            .map(|session| session.target.host.clone())
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
        self.run_ps_displayed(
            username,
            session_id,
            command,
            command,
            tool_name,
            redactions,
            &[],
        )
        .await
    }

    /// Runs a command and audits a separate display text (ADR-0013 §4).
    ///
    /// The executed script can be an encoded wrapper; the audit shows `display`, so
    /// the log holds the command the operator confirmed, not its encoding. Both go
    /// through `redact`, and the body obeys `WINRIG_AUDIT_LOG_BODY`. `extra_fields`
    /// adds records such as a hash to the audit entry.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_ps_displayed(
        &self,
        username: &str,
        session_id: &str,
        command: &str,
        display: &str,
        tool_name: &str,
        redactions: &[String],
        extra_fields: &[(&'static str, String)],
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

        // The preamble (TR-REL-10) counts against the WinRS command line, so a
        // command that no longer fits is refused here, before the transport.
        let command_chars = crate::ps::command_line_chars(command);
        if command_chars > crate::ps::WINRS_COMMAND_LINE_LIMIT {
            self.audit(
                "COMMAND REFUSED",
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
                    ("chars", command_chars.to_string()),
                    ("limit", crate::ps::WINRS_COMMAND_LINE_LIMIT.to_string()),
                ],
                "",
            );
            return json!({
                "error": format!(
                    "command is {command_chars} characters; the WinRS command line holds \
                     {} characters",
                    crate::ps::WINRS_COMMAND_LINE_LIMIT
                )
            });
        }

        // The preamble is added to the execution only; the audit keeps the command the tool
        // requested.
        match self
            .transport
            .run_powershell(&target, &format!("{PREAMBLE}{command}"))
            .await
        {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
                let stderr = strip_clixml(
                    &String::from_utf8_lossy(&output.stderr),
                    !redactions.is_empty(),
                );
                let truncated_stdout = truncate(&stdout, crate::executor::MAX_OUTPUT_CHARS);
                let body = command_audit_body(
                    display,
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
                let mut fields = fields;
                for (key, value) in extra_fields {
                    fields.push((key, value.clone()));
                }
                self.audit(&format!("COMMAND #{command_number}{label}"), &fields, &body);

                let mut reply = Map::new();
                reply.insert("status_code".to_owned(), json!(output.exit_code));
                reply.insert("stdout".to_owned(), json!(reply_redact(&truncated_stdout)));
                reply.insert("stderr".to_owned(), json!(reply_redact(&stderr)));
                if output.exit_code != 0 && stdout.trim().is_empty() && stderr.is_empty() {
                    reply.insert(
                        "error".to_owned(),
                        json!(format!(
                            "The command failed with exit code {} and produced no output. A cmdlet most likely reported an error that the command suppressed, often because nothing matched the requested filter.",
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
                    &format!("  PS> {}", indent(&audit(display))),
                );
                json!({ "error": message, "session_id": session_id })
            }
        }
    }

    /// Runs one host command of a file transfer and returns its output without an
    /// audit record (DR-4).
    ///
    /// A download reply carries the raw base64 of a chunk, and an upload sends the
    /// window as `stdin`. The audit records nothing here because the payload may be
    /// personal data; the caller writes one summary record with the paths, the size
    /// and the hash (ADR-0017 §38). `tool` names the caller in a refusal record.
    pub async fn run_transfer_command(
        &self,
        username: &str,
        session_id: &str,
        tool: &str,
        command: &str,
        stdin: Option<&[u8]>,
    ) -> Value {
        let target = {
            let mut sessions = lock(&self.sessions);
            let Some(session) = sessions.get_mut(&(username.to_owned(), session_id.to_owned()))
            else {
                return json!({
                    "error": format!("Session not found: {session_id}. Use connect first.")
                });
            };
            session.last_used = SystemTime::now();
            session.command_count += 1;
            session.target.clone()
        };

        let command_chars = crate::ps::command_line_chars(command);
        if command_chars > crate::ps::WINRS_COMMAND_LINE_LIMIT {
            self.audit(
                "COMMAND REFUSED",
                &[
                    ("user", username.to_owned()),
                    ("session", session_id.to_owned()),
                    ("tool", tool.to_owned()),
                    ("chars", command_chars.to_string()),
                    ("limit", crate::ps::WINRS_COMMAND_LINE_LIMIT.to_string()),
                ],
                "",
            );
            return json!({
                "error": format!(
                    "command is {command_chars} characters; the WinRS command line holds \
                     {} characters",
                    crate::ps::WINRS_COMMAND_LINE_LIMIT
                )
            });
        }

        let session_password = target.password.expose_secret().to_owned();
        let script = format!("{PREAMBLE}{command}");
        let result = match stdin {
            Some(bytes) => {
                self.transport
                    .run_powershell_stdin(&target, &script, bytes)
                    .await
            }
            None => self.transport.run_powershell(&target, &script).await,
        };
        match result {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
                let stderr = strip_clixml(&String::from_utf8_lossy(&output.stderr), false);
                json!({
                    "status_code": output.exit_code,
                    "stdout": stdout,
                    "stderr": stderr,
                })
            }
            Err(error) => {
                let message = redact(
                    &error.to_string(),
                    &[session_password],
                    self.config.secret_redact_min_length,
                );
                tracing::error!(session = %sanitize_log_value(session_id), error = %message, "run_transfer_command failed");
                json!({ "error": message, "session_id": session_id })
            }
        }
    }

    /// Records one file transfer: the resolved paths, the size, both hashes when
    /// known and the confirmation state, never the content (TR-XFER-02, ADR-0017
    /// §38, DR-4).
    #[allow(clippy::too_many_arguments)]
    pub fn audit_transfer(&self, transfer: AuditTransfer<'_>) {
        self.audit(
            "FILE TRANSFER",
            &[
                ("user", transfer.username.to_owned()),
                ("tool", transfer.tool.to_owned()),
                ("host", transfer.host.to_owned()),
                ("remote", transfer.remote_path.to_owned()),
                ("local", transfer.local_path.to_owned()),
                ("size", transfer.size.to_string()),
                ("sha256_host", transfer.host_hash.to_owned()),
                ("sha256_local", transfer.local_hash.to_owned()),
                ("confirmation", transfer.confirmation.to_owned()),
                ("status", transfer.status.to_owned()),
            ],
            "",
        );
    }

    /// Uploads the staging file, verifies and runs it as a script block and
    /// removes it in one confirmed operation (TR-EXE-06, ADR-0017 §29–33).
    ///
    /// A failed chunk tries to remove the partial staging file before the tool
    /// returns; the error text names the cleanup outcome. A failed run or a
    /// timeout still tries to remove the file, and a failed removal adds a
    /// `warning`. The script text goes to the audit, not the encoded wrapper
    /// (DR-4).
    pub async fn run_script(
        &self,
        username: &str,
        session_id: &str,
        op: ScriptRun<'_>,
        tool_name: &str,
    ) -> Value {
        for (index, chunk) in op.chunks.iter().enumerate() {
            // DR-4: the content travels in the command as base64 and may be a
            // secret, so exactly what the command carries is redacted.
            let secrets = crate::ps::base64_payloads(chunk);
            let reply = self
                .run_ps(username, session_id, chunk, tool_name, &secrets)
                .await;
            if reply.get("error").is_some()
                || reply.get("status_code").and_then(Value::as_i64) != Some(0)
            {
                let temp_file = self
                    .remove_staging(username, session_id, op.cleanup, tool_name)
                    .await;
                let (message, warning) =
                    staging_failure_message(index, op.chunks.len(), &temp_file);
                let mut out = json!({
                    "error": message,
                    "step": reply,
                    "temp_file": temp_file,
                });
                if let Some(warning) = warning {
                    out["warning"] = json!(warning);
                }
                return out;
            }
        }
        let run_secrets = crate::ps::base64_payloads(op.run);
        let mut reply = self
            .run_ps_displayed(
                username,
                session_id,
                op.run,
                op.display,
                tool_name,
                &run_secrets,
                &[("sha256", op.hash.to_owned())],
            )
            .await;
        // A 97 exit with the mismatch marker means the file changed between the
        // upload and the run. The reply gets a plain error, because the run itself
        // produced a message on stderr and no `error` field (TR-EXE-06).
        let mismatch = reply.get("status_code").and_then(Value::as_i64)
            == Some(i64::from(crate::ps::SCRIPT_HASH_MISMATCH_EXIT))
            && reply
                .get("stderr")
                .and_then(Value::as_str)
                .is_some_and(|stderr| stderr.contains(crate::ps::SCRIPT_HASH_MISMATCH_MARKER));
        let temp_file = self
            .remove_staging(username, session_id, op.cleanup, tool_name)
            .await;
        if let Some(object) = reply.as_object_mut() {
            if mismatch {
                object.insert(
                    "error".to_owned(),
                    json!("The staging file changed after the upload. The tool did not run the script."),
                );
            }
            if let Some(warning) = staging_warning(&temp_file) {
                object.insert("warning".to_owned(), json!(warning));
            }
            object.insert("temp_file".to_owned(), json!(temp_file));
        }
        reply
    }

    /// Deletes the staging file and reports the outcome: `removed`, `absent` or a
    /// failure text (TR-EXE-06).
    async fn remove_staging(
        &self,
        username: &str,
        session_id: &str,
        cleanup_command: &str,
        tool_name: &str,
    ) -> String {
        let reply = self
            .run_ps(username, session_id, cleanup_command, tool_name, &[])
            .await;
        if reply.get("error").is_some() {
            return "cleanup failed".to_owned();
        }
        let stdout = reply
            .get("stdout")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_owned();
        let code = reply.get("status_code").and_then(Value::as_i64);
        if code == Some(0) && (stdout == "removed" || stdout == "absent") {
            stdout
        } else {
            format!("cleanup failed: {stdout}")
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

    /// Records that the operator write allowlist permitted a write into a protected
    /// location, and names the entry that permitted it (TR-FS-07, ADR-0017 §39).
    ///
    /// The record makes the log show why a protected path was permitted. The path
    /// and the entry are not secrets.
    pub fn audit_write_allow(&self, username: &str, tool: &str, path: &str, entry: &str) {
        self.audit(
            "WRITE ALLOWED BY ALLOWLIST",
            &[
                ("user", username.to_owned()),
                ("tool", tool.to_owned()),
                ("path", path.to_owned()),
                ("entry", entry.to_owned()),
            ],
            "",
        );
    }

    /// Records that a modifying operation ran through the permanent operator
    /// agreement instead of an answer (TR-SEC-11, ADR-0013 §22).
    ///
    /// The entry exists so the log shows that no person answered at the moment.
    pub fn audit_confirmation_unsupported(
        &self,
        username: &str,
        tool: &str,
        session: &str,
        host: &str,
    ) {
        self.audit(
            "CONFIRMATION UNSUPPORTED",
            &[
                ("user", username.to_owned()),
                ("session", session.to_owned()),
                ("host", host.to_owned()),
                ("tool", tool.to_owned()),
                ("confirmation", "unsupported".to_owned()),
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

    let mut body = format!("  PS> {}\n", indent(&audit(command)));
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

/// Removes the CLIXML envelope that PowerShell writes to stderr (TR-REL-10).
///
/// The stream records inside the envelope carry the reason a command failed or
/// misbehaved, so their text stays. The progress records, the envelope and the
/// position lines are noise. PowerShell escapes a stream record as
/// `<S S="Error">text</S>`, not as an object. `unwrap` joins the lines of a
/// record, so a secret that a host buffer split across lines stays whole for the
/// redaction (DR-4).
fn strip_clixml(stderr: &str, unwrap: bool) -> String {
    strip_clixml_envelopes(&remove_progress_objects(stderr), unwrap)
}

/// Drops every `<Obj S="progress" …>…</Obj>` object.
fn remove_progress_objects(stderr: &str) -> String {
    const PROGRESS_OBJ: &str = "<Obj S=\"progress\"";
    let mut cleaned = String::with_capacity(stderr.len());
    let mut rest = stderr;
    while let Some(start) = rest.find(PROGRESS_OBJ) {
        cleaned.push_str(&rest[..start]);
        // A progress object nests elements but no other `<Obj>`, so the next
        // `</Obj>` closes it.
        match rest[start..].find("</Obj>") {
            Some(end) => rest = &rest[start + end + "</Obj>".len()..],
            None => {
                // Unclosed: the end is unknown, so keep the tail as it is.
                cleaned.push_str(&rest[start..]);
                rest = "";
                break;
            }
        }
    }
    cleaned.push_str(rest);
    cleaned
}

/// Replaces every `#< CLIXML … </Objs>` envelope with its stream text.
fn strip_clixml_envelopes(input: &str, unwrap: bool) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    loop {
        let Some(marker) = rest.find("#< CLIXML") else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..marker]);
        let Some(close) = rest[marker..].find("</Objs>") else {
            // No closing tag: the text stays as it is.
            out.push_str(&rest[marker..]);
            break;
        };
        let body_end = marker + close + "</Objs>".len();
        let text = clixml_stream_text(&rest[marker..body_end], unwrap);
        if !out.is_empty() && !out.ends_with('\n') && !text.is_empty() {
            out.push('\n');
        }
        out.push_str(&text);
        rest = &rest[body_end..];
    }
    out.trim().to_owned()
}

/// The plain text of the `<S S="...">` stream records inside a CLIXML envelope.
///
/// The newline that ends each record stays, so records concatenate without a
/// blank line. A position line goes, because a window of our one-line script can
/// hold a fragment of a secret (DR-4). With `unwrap` a record's lines join, so a
/// secret split by a wrapped line is still one string.
fn clixml_stream_text(body: &str, unwrap: bool) -> String {
    let mut out = String::new();
    let mut rest = body;
    while let Some(start) = rest.find("<S S=\"") {
        let Some(open) = rest[start..].find('>') else {
            break;
        };
        if rest[start..start + open + 1].ends_with("/>") {
            // A self-closing record carries no text; do not eat the next one.
            rest = &rest[start + open + 1..];
            continue;
        }
        let text_start = start + open + 1;
        let Some(close) = rest[text_start..].find("</S>") else {
            break;
        };
        let raw = decode_clixml_text(&rest[text_start..text_start + close]);
        let text = drop_position_lines(&raw.replace("\r\n", "\n"), unwrap);
        if unwrap && !out.is_empty() && !text.is_empty() {
            out.push('\n');
        }
        out.push_str(&text);
        rest = &rest[text_start + close + "</S>".len()..];
    }
    out.trim_end_matches('\n').to_owned()
}

/// Removes the `At …` header, the `+ …` script window and the `+ ~~~` underline.
///
/// Those lines carry a window of our one-line script, which can hold a fragment
/// of a secret (DR-4). The `+ CategoryInfo` and `+ FullyQualifiedErrorId` lines
/// carry no script text and stay. With `unwrap` the kept lines join without a
/// separator, so a secret that a host buffer split across lines is matched.
fn drop_position_lines(text: &str, unwrap: bool) -> String {
    let kept: Vec<&str> = text
        .lines()
        .filter(|line| !is_position_line(line))
        .collect();
    if unwrap {
        return kept.join("");
    }
    let mut out = kept.join("\n");
    // `str::lines` drops the trailing newline; restore it so the next record
    // abuts the way PowerShell wrote it.
    if text.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// True for a line that carries a window of the script rather than the message.
fn is_position_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with("At line:") || trimmed.starts_with("At char:") {
        return true;
    }
    if trimmed.starts_with("At ") && trimmed.contains(" char:") {
        return true;
    }
    match trimmed.strip_prefix("+ ") {
        Some(rest) => {
            let rest = rest.trim_start();
            !(rest.starts_with("CategoryInfo") || rest.starts_with("FullyQualifiedErrorId"))
        }
        None => false,
    }
}

/// Decodes the text of a CLIXML stream record.
///
/// PowerShell writes a control character as `_xHHHH_` and an XML metacharacter as
/// an entity, so the plain text needs both undone to be readable.
fn decode_clixml_text(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '_'
            && i + 6 < chars.len()
            && chars[i + 1] == 'x'
            && chars[i + 6] == '_'
            && chars[i + 2..i + 6].iter().all(char::is_ascii_hexdigit)
        {
            let hex: String = chars[i + 2..i + 6].iter().collect();
            if let Some(c) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                out.push(c);
                i += 7;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
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

/// The text for the `warning` field when the removal reported no definite outcome.
fn staging_warning(temp_file: &str) -> Option<String> {
    match temp_file {
        "removed" | "absent" => None,
        other => Some(format!(
            "The temporary file may remain on the host: {other}"
        )),
    }
}

/// The error text of a failed chunk upload, tied to the cleanup outcome, and the
/// matching `warning` text.
fn staging_failure_message(step: usize, total: usize, temp_file: &str) -> (String, Option<String>) {
    let warning = staging_warning(temp_file);
    let message = if warning.is_some() {
        format!(
            "The upload of the script failed at step {} of {}. The staging file may remain on the \
             host.",
            step + 1,
            total
        )
    } else {
        format!(
            "The upload of the script failed at step {} of {}. The tool removed the staging file.",
            step + 1,
            total
        )
    };
    (message, warning)
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

    /// AC-REL10-1: PowerShell writes a CLIXML progress record to stderr on the first
    /// use of a module, in the host language. Every command must carry the preamble
    /// that silences the stream, so the result holds no `S="progress"` record
    /// (TR-REL-10).
    #[tokio::test]
    async fn every_command_carries_the_progress_silencing_preamble() {
        let transport = Arc::new(FakeTransport::returning(output(
            "HOST1|Windows|10.0|2026-01-01 00:00:00",
            "",
            0,
        )));
        let registry = registry(transport.clone());
        let identity = UserIdentity::with_password("alice", "s3cret");
        let _ = registry.connect(&identity, "host1", None, None, true).await;
        for command in [
            crate::ps::get_system_info(),
            crate::ps::list_processes("", "cpu", 5),
            crate::ps::get_services("", "", false),
        ] {
            let _ = registry
                .run_ps("alice", "host1", &command, "read", &[])
                .await;
        }
        let calls = transport.calls();
        assert!(calls.len() >= 4, "expected the probe and three commands");
        for (_, script) in calls {
            assert!(
                script.starts_with(PREAMBLE),
                "command lacks the progress-silencing preamble: {script}"
            );
        }
    }

    /// TR-REL-10: PowerShell serializes stderr as CLIXML. The test uses the real
    /// shape: a `<Obj S="progress">` record and a `<S S="Error">` stream record in
    /// one `<Objs>` envelope. The progress record goes; the error text stays, with
    /// the `_xHHHH_` escapes decoded.
    #[test]
    fn strip_clixml_keeps_stream_records_and_drops_progress() {
        let stderr = "#< CLIXML\r\n<Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\">\
<Obj S=\"progress\" RefId=\"0\"><TN RefId=\"0\"><T>System.Management.Automation.PSCustomObject</T><T>System.Object</T></TN><MS><I64 N=\"SourceId\">1</I64><PR N=\"Record\"><AV>Preparing modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj>\
<S S=\"Error\">Get-Item : Cannot find path 'C:\\nope' because it does not exist._x000D__x000A_</S></Objs>";
        let cleaned = strip_clixml(stderr, false);
        assert!(
            cleaned.contains("Cannot find path 'C:\\nope' because it does not exist."),
            "{cleaned}"
        );
        assert!(!cleaned.contains("S=\"progress\""), "{cleaned}");
        assert!(!cleaned.contains("<Objs"), "{cleaned}");
        assert!(
            !cleaned.contains("_x000D_"),
            "escapes must be decoded: {cleaned}"
        );
    }

    /// TR-REL-10: the `_xHHHH_` escapes and the XML entities of a stream record are
    /// decoded, so the text is what a person reads.
    #[test]
    fn strip_clixml_decodes_escapes_and_entities() {
        let stderr = "#< CLIXML\n<Objs Version=\"1.1.0.1\">\
<S S=\"Error\">a&lt;b&gt; &amp; c_x000D__x000A_</S></Objs>";
        assert_eq!(strip_clixml(stderr, false), "a<b> & c");
    }

    /// TR-REL-10: every progress record goes, not only the first. A run of a
    /// module can emit several before the command output.
    #[test]
    fn strip_clixml_removes_every_progress_record() {
        let stderr = "#< CLIXML\n<Objs Version=\"1.1.0.1\">\
                      <Obj S=\"progress\">one</Obj>\
                      <Obj S=\"progress\">two</Obj></Objs>";
        let cleaned = strip_clixml(stderr, false);
        assert!(!cleaned.contains("progress"), "{cleaned}");
        assert!(cleaned.is_empty(), "{cleaned}");
    }

    /// Plain stderr without CLIXML passes through unchanged.
    #[test]
    fn strip_clixml_keeps_stderr_without_clixml() {
        assert_eq!(strip_clixml("access denied\n", false), "access denied");
    }

    /// An unclosed `<Obj S="progress"` has no known end, so the tail stays as it
    /// is rather than losing unknown content.
    #[test]
    fn strip_clixml_keeps_an_unclosed_progress_record() {
        let stderr = "#< CLIXML\n<Objs Version=\"1.1.0.1\"><Obj S=\"progress\" RefId=\"0\"><TN>";
        let cleaned = strip_clixml(stderr, false);
        assert!(cleaned.contains("<Obj S=\"progress\""), "{cleaned}");
        assert!(cleaned.contains("<TN>"), "{cleaned}");
    }

    /// The envelope goes only when it closes; without `</Objs>` the text stays as
    /// it is and nothing panics.
    #[test]
    fn strip_clixml_keeps_an_unclosed_envelope() {
        let stderr = "#< CLIXML\n<Objs Version=\"1.1.0.1\"><S S=\"Error\">boom";
        let cleaned = strip_clixml(stderr, false);
        assert!(cleaned.contains("boom"), "{cleaned}");
    }

    /// DR-4: the position lines carry a window of our one-line script, which can
    /// hold a fragment of a secret. The exception message and the two
    /// `+ CategoryInfo` / `+ FullyQualifiedErrorId` lines stay.
    #[test]
    fn strip_clixml_drops_position_lines() {
        let stderr = "#< CLIXML\r\n<Objs Version=\"1.1.0.1\"><S S=\"Error\">\
Get-Item : Cannot find path 'C:\\nope' because it does not exist._x000D__x000A_\
At line:1 char:2940_x000D__x000A_\
+ ... supersecretvalu ..._x000D__x000A_\
+ ~~~~~~~~~~~~~~~~~~~~~~~~_x000D__x000A_\
+ CategoryInfo : ObjectNotFound: (C:\\nope:String) [Get-Item], ItemNotFoundException_x000D__x000A_\
+ FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.GetItemCommand_x000D__x000A_\
</S></Objs>";
        let cleaned = strip_clixml(stderr, false);
        assert!(
            cleaned.contains("Cannot find path 'C:\\nope' because it does not exist."),
            "{cleaned}"
        );
        assert!(cleaned.contains("+ CategoryInfo"), "{cleaned}");
        assert!(cleaned.contains("+ FullyQualifiedErrorId"), "{cleaned}");
        assert!(!cleaned.contains("supersecretvalu"), "{cleaned}");
        assert!(!cleaned.contains("At line:"), "{cleaned}");
        assert!(!cleaned.contains("~~~"), "{cleaned}");
    }

    /// Two records abut: each ends with a newline, so they join into exactly two
    /// lines, without a blank line between them.
    #[test]
    fn strip_clixml_joins_records_without_a_blank_line() {
        let stderr = "#< CLIXML\n<Objs Version=\"1.1.0.1\">\
<S S=\"Error\">line one_x000D__x000A_</S>\
<S S=\"Error\">line two_x000D__x000A_</S></Objs>";
        assert_eq!(strip_clixml(stderr, false), "line one\nline two");
    }

    /// A second `#< CLIXML … </Objs>` envelope is cleaned too.
    #[test]
    fn strip_clixml_cleans_a_second_envelope() {
        let stderr = "#< CLIXML\n<Objs Version=\"1.1.0.1\"><S S=\"Error\">one_x000D__x000A_</S></Objs>\
#< CLIXML\n<Objs Version=\"1.1.0.1\"><S S=\"Error\">two_x000D__x000A_</S></Objs>";
        let cleaned = strip_clixml(stderr, false);
        assert!(cleaned.contains("one"), "{cleaned}");
        assert!(cleaned.contains("two"), "{cleaned}");
        assert!(!cleaned.contains("<Objs"), "{cleaned}");
        assert!(!cleaned.contains("#< CLIXML"), "{cleaned}");
    }

    /// A self-closing `<S …/>` carries no text; skipping it must not swallow the
    /// record that follows.
    #[test]
    fn strip_clixml_skips_a_self_closing_record() {
        let stderr = "#< CLIXML\n<Objs Version=\"1.1.0.1\">\
<S S=\"Error\" />\
<S S=\"Error\">boom_x000D__x000A_</S></Objs>";
        let cleaned = strip_clixml(stderr, false);
        assert!(cleaned.contains("boom"), "{cleaned}");
        assert!(!cleaned.contains("<S "), "{cleaned}");
    }

    /// A host buffer can split a record across lines; with `unwrap` the halves
    /// join so the redaction matches the whole secret (DR-4).
    #[test]
    fn strip_clixml_unwraps_a_split_record() {
        let stderr = "#< CLIXML\n<Objs Version=\"1.1.0.1\">\
<S S=\"Error\">super_x000D__x000A_secretvalue123_x000D__x000A_</S></Objs>";
        assert_eq!(strip_clixml(stderr, false), "super\nsecretvalue123");
        assert_eq!(strip_clixml(stderr, true), "supersecretvalue123");
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

    /// TR-SEC-09: a multi-line command indents every line, so a continuation line
    /// cannot look like an audit field line.
    #[test]
    fn command_audit_body_indents_a_multi_line_command() {
        let body = command_audit_body("Get-Service\nRemove-Item C:\\x", "", "", &[], 2000);
        let lines: Vec<&str> = body.lines().collect();
        assert!(lines[0].contains("Get-Service"), "{body}");
        assert_eq!(lines[1], "  Remove-Item C:\\x", "{body}");
    }

    #[tokio::test]
    async fn run_ps_on_unknown_session_reports_error() {
        let transport = Arc::new(FakeTransport::returning(output("", "", 0)));
        let registry = registry(transport);
        let reply = registry.run_ps("alice", "nope", "Get-Date", "", &[]).await;
        assert!(reply["error"].as_str().is_some());
    }

    /// DR-4: a position window in the host stderr holds a fragment of our one-line
    /// script; it must not reach the reply or the audit. The exception message
    /// stays.
    #[tokio::test]
    async fn run_ps_drops_the_position_window_from_stderr() {
        let transport = Arc::new(FakeTransport::returning(output(
            "HOST1|Windows|10.0|2026-01-01 00:00:00",
            "",
            0,
        )));
        let registry = registry(transport.clone());
        let identity = UserIdentity::with_password("alice", "s3cret");
        let _ = registry.connect(&identity, "host1", None, None, true).await;
        let stderr = "#< CLIXML\r\n<Objs Version=\"1.1.0.1\"><S S=\"Error\">\
Get-Item : Cannot find path 'C:\\nope' because it does not exist._x000D__x000A_\
At line:1 char:2940_x000D__x000A_\
+ ... supersecretvalu ..._x000D__x000A_\
+ ~~~~~~~~~~~~~~~~~~~~~~~~_x000D__x000A_\
+ CategoryInfo : ObjectNotFound_x000D__x000A_\
+ FullyQualifiedErrorId : PathNotFound_x000D__x000A_\
</S></Objs>";
        transport.set_result(Ok(output("", stderr, 1)));
        let captured = capture();
        let reply = registry
            .run_ps(
                "alice",
                "host1",
                "Get-Item 'C:\\nope'",
                "read_file",
                &["supersecretvalue123".to_owned()],
            )
            .await;
        let reply_stderr = reply["stderr"].as_str().unwrap_or_default();
        assert!(
            reply_stderr.contains("Cannot find path 'C:\\nope' because it does not exist."),
            "{reply_stderr}"
        );
        assert!(!reply_stderr.contains("supersecretvalu"), "{reply_stderr}");
        let audit = captured.text();
        assert!(!audit.contains("supersecretvalu"), "{audit}");
        assert!(audit.contains("Cannot find path"), "{audit}");
    }

    /// DR-4: a host buffer split wraps a long line and cuts a secret in half, so
    /// the redaction of the whole secret would miss. The record lines join before
    /// the redaction, so no half reaches the reply or the audit.
    #[tokio::test]
    async fn run_ps_redacts_a_secret_split_across_lines() {
        let transport = Arc::new(FakeTransport::returning(output(
            "HOST1|Windows|10.0|2026-01-01 00:00:00",
            "",
            0,
        )));
        let registry = registry(transport.clone());
        let identity = UserIdentity::with_password("alice", "s3cret");
        let _ = registry.connect(&identity, "host1", None, None, true).await;
        let stderr = "#< CLIXML\r\n<Objs Version=\"1.1.0.1\"><S S=\"Error\">\
Get-Item : the path under super_x000D__x000A_secretvalue123 was not found._x000D__x000A_</S></Objs>";
        transport.set_result(Ok(output("", stderr, 1)));
        let captured = capture();
        let reply = registry
            .run_ps(
                "alice",
                "host1",
                "Get-Item 'C:\\nope'",
                "read_file",
                &["supersecretvalue123".to_owned()],
            )
            .await;
        let reply_stderr = reply["stderr"].as_str().unwrap_or_default();
        assert!(!reply_stderr.contains("secretvalue123"), "{reply_stderr}");
        assert!(!reply_stderr.contains("super"), "{reply_stderr}");
        let audit = captured.text();
        assert!(!audit.contains("secretvalue123"), "{audit}");
        assert!(!audit.contains("supersecretvalue123"), "{audit}");
    }

    /// The preamble counts against the WinRS command line, so an oversized command
    /// is refused before the transport records anything. The refusal is audited
    /// with the length and the limit, without the command body.
    #[tokio::test]
    async fn run_ps_refuses_an_oversized_command_without_transport() {
        let transport = Arc::new(FakeTransport::returning(output(
            "HOST1|Windows|10.0|2026-01-01 00:00:00",
            "",
            0,
        )));
        let registry = registry(transport.clone());
        let identity = UserIdentity::with_password("alice", "s3cret");
        let _ = registry.connect(&identity, "host1", None, None, true).await;
        let command = "x".repeat(9000);
        let before = transport.calls().len();
        let captured = capture();
        let reply = registry
            .run_ps("alice", "host1", &command, "read_file", &[])
            .await;
        let error = reply["error"].as_str().unwrap_or_default();
        let expected = crate::ps::command_line_chars(&command).to_string();
        assert!(error.contains(&expected), "{error}");
        assert!(error.contains("8191"), "{error}");
        assert_eq!(
            transport.calls().len(),
            before,
            "the transport must not be called"
        );
        let audit = captured.text();
        assert!(audit.contains("COMMAND REFUSED"), "{audit}");
        assert!(audit.contains(&expected), "{audit}");
        assert!(audit.contains("8191"), "{audit}");
        assert!(
            !audit.contains(&"x".repeat(100)),
            "the command body leaked: {audit}"
        );
    }

    /// A transport whose chunk, run and cleanup answers are set for each test.
    struct ScriptTransport {
        calls: StdMutex<Vec<String>>,
        chunk_count: StdMutex<usize>,
        /// The 0-based index of the write that fails, if any.
        fail_chunk: Option<usize>,
        fail_run: bool,
        fail_cleanup: bool,
        /// The run reports a SHA-256 that differs from the confirmed value.
        mismatch: bool,
    }

    impl ScriptTransport {
        fn new() -> Self {
            Self {
                calls: StdMutex::new(Vec::new()),
                chunk_count: StdMutex::new(0),
                fail_chunk: None,
                fail_run: false,
                fail_cleanup: false,
                mismatch: false,
            }
        }
    }

    #[async_trait::async_trait]
    impl WinRmTransport for ScriptTransport {
        async fn run_powershell(
            &self,
            _target: &SessionTarget,
            script: &str,
        ) -> Result<RemoteOutput, TransportError> {
            self.calls.lock().expect("lock").push(script.to_owned());
            if script.contains("Remove-Item") {
                return Ok(if self.fail_cleanup {
                    output("", "cleanup boom", 1)
                } else {
                    output("removed", "", 0)
                });
            }
            if script.contains("[ScriptBlock]::Create") {
                if self.mismatch {
                    return Ok(output(
                        "",
                        crate::ps::SCRIPT_HASH_MISMATCH_MARKER,
                        crate::ps::SCRIPT_HASH_MISMATCH_EXIT,
                    ));
                }
                return Ok(if self.fail_run {
                    output("", "run boom", 1)
                } else {
                    output("", "", 0)
                });
            }
            let mut count = self.chunk_count.lock().expect("lock");
            let index = *count;
            *count += 1;
            if self.fail_chunk == Some(index) {
                return Ok(output("", "chunk boom", 1));
            }
            Ok(output("", "", 0))
        }
    }

    /// Builds the chunk, run and cleanup commands of a staging write, so the tests
    /// pass exactly what the tool builds.
    fn script_steps(path: &str, chunk_count: usize) -> (Vec<String>, String, String, String) {
        let script = "Write-Output 1";
        let mut chunks = Vec::new();
        for index in 0..chunk_count {
            chunks.push(if index == 0 {
                crate::ps::script_chunk_create(path, "QUJD")
            } else {
                crate::ps::write_chunk(path, "QUJD", false)
            });
        }
        let hash = crate::ps::script_sha256(script);
        (
            chunks,
            crate::ps::run_script_file(path, &hash).expect("fits"),
            crate::ps::script_cleanup(path),
            hash,
        )
    }

    /// TR-EXE-06, AC-EXE-06: a failed run still removes the staging file, and the
    /// removal runs after the run and the chunk write.
    #[tokio::test]
    async fn run_script_deletes_the_temp_file_on_failure() {
        let transport = Arc::new(ScriptTransport {
            fail_run: true,
            ..ScriptTransport::new()
        });
        let registry = SessionRegistry::new(
            Arc::clone(&transport) as Arc<dyn WinRmTransport>,
            RegistryConfig::default(),
        );
        let identity = UserIdentity::with_password("alice", "s3cret");
        let _ = registry.connect(&identity, "host1", None, None, true).await;

        let path = "C:\\Temp\\winrig-abc.ps1";
        let (chunks, run, cleanup, hash) = script_steps(path, 1);
        let reply = registry
            .run_script(
                "alice",
                "host1",
                ScriptRun {
                    chunks: &chunks,
                    run: &run,
                    cleanup: &cleanup,
                    display: "Write-Output 1",
                    hash: &hash,
                },
                "run_script",
            )
            .await;

        assert_eq!(reply["temp_file"], "removed", "{reply}");
        assert!(reply.get("warning").is_none(), "{reply}");
        let calls = transport.calls.lock().expect("lock").clone();
        let chunk = calls.iter().position(|c| c.contains("FromBase64String"));
        let run_at = calls
            .iter()
            .position(|c| c.contains("[ScriptBlock]::Create"));
        let delete = calls.iter().position(|c| c.contains("Remove-Item"));
        assert!(
            chunk.is_some(),
            "the chunk did not reach the host: {calls:?}"
        );
        assert!(
            run_at.is_some(),
            "the run did not reach the host: {calls:?}"
        );
        assert!(
            delete.is_some(),
            "the failed run left the staging file: {calls:?}"
        );
        assert!(
            chunk < run_at && run_at < delete,
            "the order is wrong: {calls:?}"
        );
    }

    /// TR-EXE-06: a middle chunk fails and the cleanup succeeds, so the cleanup
    /// runs after the failure and the run never starts.
    #[tokio::test]
    async fn run_script_middle_chunk_failure_runs_the_cleanup() {
        let transport = Arc::new(ScriptTransport {
            fail_chunk: Some(1),
            ..ScriptTransport::new()
        });
        let registry = SessionRegistry::new(
            Arc::clone(&transport) as Arc<dyn WinRmTransport>,
            RegistryConfig::default(),
        );
        let identity = UserIdentity::with_password("alice", "s3cret");
        let _ = registry.connect(&identity, "host1", None, None, true).await;

        let path = "C:\\Temp\\winrig-abc.ps1";
        let (chunks, run, cleanup, hash) = script_steps(path, 2);
        let reply = registry
            .run_script(
                "alice",
                "host1",
                ScriptRun {
                    chunks: &chunks,
                    run: &run,
                    cleanup: &cleanup,
                    display: "Write-Output 1",
                    hash: &hash,
                },
                "run_script",
            )
            .await;

        assert_eq!(reply["temp_file"], "removed", "{reply}");
        assert!(
            reply["error"]
                .as_str()
                .is_some_and(|error| error.contains("The tool removed the staging file")),
            "{reply}"
        );
        assert!(reply.get("warning").is_none(), "{reply}");
        let calls = transport.calls.lock().expect("lock").clone();
        assert!(
            !calls.iter().any(|c| c.contains("[ScriptBlock]::Create")),
            "the run must not start after a chunk failure: {calls:?}"
        );
        let delete = calls.iter().position(|c| c.contains("Remove-Item"));
        assert!(
            delete.is_some(),
            "the cleanup did not run after the failure: {calls:?}"
        );
    }

    /// TR-EXE-06: when the first chunk and the cleanup both fail, the error text
    /// says the file may remain, and the result carries a warning.
    #[tokio::test]
    async fn run_script_failed_chunk_and_cleanup_says_it_may_remain() {
        let transport = Arc::new(ScriptTransport {
            fail_chunk: Some(0),
            fail_cleanup: true,
            ..ScriptTransport::new()
        });
        let registry = SessionRegistry::new(
            Arc::clone(&transport) as Arc<dyn WinRmTransport>,
            RegistryConfig::default(),
        );
        let identity = UserIdentity::with_password("alice", "s3cret");
        let _ = registry.connect(&identity, "host1", None, None, true).await;

        let path = "C:\\Temp\\winrig-abc.ps1";
        let (chunks, run, cleanup, hash) = script_steps(path, 1);
        let reply = registry
            .run_script(
                "alice",
                "host1",
                ScriptRun {
                    chunks: &chunks,
                    run: &run,
                    cleanup: &cleanup,
                    display: "Write-Output 1",
                    hash: &hash,
                },
                "run_script",
            )
            .await;

        assert!(
            reply["error"]
                .as_str()
                .is_some_and(|error| error.contains("may remain on the host")),
            "{reply}"
        );
        assert!(
            reply["warning"]
                .as_str()
                .is_some_and(|warning| warning.contains("may remain on the host")),
            "{reply}"
        );
    }

    /// TR-EXE-06: when the removal of the staging file fails, the tool says so
    /// instead of losing the failure in silence.
    #[tokio::test]
    async fn run_script_reports_a_failed_cleanup() {
        let transport = Arc::new(ScriptTransport {
            fail_cleanup: true,
            ..ScriptTransport::new()
        });
        let registry = SessionRegistry::new(
            Arc::clone(&transport) as Arc<dyn WinRmTransport>,
            RegistryConfig::default(),
        );
        let identity = UserIdentity::with_password("alice", "s3cret");
        let _ = registry.connect(&identity, "host1", None, None, true).await;

        let path = "C:\\Temp\\winrig-abc.ps1";
        let (chunks, run, cleanup, hash) = script_steps(path, 1);
        let reply = registry
            .run_script(
                "alice",
                "host1",
                ScriptRun {
                    chunks: &chunks,
                    run: &run,
                    cleanup: &cleanup,
                    display: "Write-Output 1",
                    hash: &hash,
                },
                "run_script",
            )
            .await;

        assert!(
            reply["temp_file"]
                .as_str()
                .is_some_and(|value| value.contains("cleanup failed")),
            "{reply}"
        );
        assert!(
            reply["warning"]
                .as_str()
                .is_some_and(|warning| warning.contains("may remain on the host")),
            "{reply}"
        );
    }

    /// TR-EXE-06, AC-EXE-06: an exit code 97 with the mismatch marker means the
    /// staging file changed after the upload, so the reply names it.
    #[tokio::test]
    async fn run_script_reports_a_hash_mismatch() {
        let transport = Arc::new(ScriptTransport {
            mismatch: true,
            ..ScriptTransport::new()
        });
        let registry = SessionRegistry::new(
            Arc::clone(&transport) as Arc<dyn WinRmTransport>,
            RegistryConfig::default(),
        );
        let identity = UserIdentity::with_password("alice", "s3cret");
        let _ = registry.connect(&identity, "host1", None, None, true).await;

        let path = "C:\\Temp\\winrig-abc.ps1";
        let (chunks, run, cleanup, hash) = script_steps(path, 1);
        let reply = registry
            .run_script(
                "alice",
                "host1",
                ScriptRun {
                    chunks: &chunks,
                    run: &run,
                    cleanup: &cleanup,
                    display: "Write-Output 1",
                    hash: &hash,
                },
                "run_script",
            )
            .await;

        assert_eq!(
            reply["status_code"],
            crate::ps::SCRIPT_HASH_MISMATCH_EXIT,
            "{reply}"
        );
        assert!(
            reply["error"]
                .as_str()
                .is_some_and(|error| error.contains("changed after the upload")),
            "{reply}"
        );
        assert_eq!(reply["temp_file"], "removed", "{reply}");
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

    /// A host command with a scripted behaviour for the standard input tests.
    struct FakeCall {
        send_fails: bool,
        /// Source of the scripted answer; a function keeps the fake `Sync`.
        poll: fn() -> Poll,
    }

    #[async_trait::async_trait]
    impl StdinCall for FakeCall {
        async fn start(&self, _script: &str) -> Result<String, winrm_rs::WinrmError> {
            Ok("cmd-1".to_owned())
        }

        async fn send(
            &self,
            _command_id: &str,
            _data: &[u8],
            _end_of_stream: bool,
        ) -> Result<(), winrm_rs::WinrmError> {
            if self.send_fails {
                Err(winrm_rs::WinrmError::Transfer("broken pipe".to_owned()))
            } else {
                Ok(())
            }
        }

        async fn receive(&self, _command_id: &str) -> Result<Poll, winrm_rs::WinrmError> {
            tokio::task::yield_now().await;
            Ok((self.poll)())
        }
    }

    /// Records the cleanup calls. The delete of the shell is refused while the command
    /// still runs, as on the host: the open handle stays until the terminate signal.
    struct FakeCleanup {
        events: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl ShellCleanup for FakeCleanup {
        async fn terminate(&self, command_id: &str) {
            self.events
                .lock()
                .expect("lock")
                .push(format!("terminate:{command_id}"));
        }

        async fn delete(&self) {
            let mut events = self.events.lock().expect("lock");
            let terminated = events.iter().any(|event| event.starts_with("terminate:"));
            events.push(
                if terminated {
                    "delete"
                } else {
                    "delete-blocked"
                }
                .to_owned(),
            );
        }
    }

    fn finished_with_error() -> Poll {
        Poll {
            stdout: Vec::new(),
            stderr: b"boom".to_vec(),
            exit_code: Some(1),
            done: true,
        }
    }

    fn still_running() -> Poll {
        Poll {
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_code: None,
            done: false,
        }
    }

    fn idle_guard() -> (Arc<FakeCleanup>, CallGuard) {
        let cleanup = Arc::new(FakeCleanup {
            events: Mutex::new(Vec::new()),
        });
        let guard = CallGuard {
            cleanup: Arc::clone(&cleanup) as Arc<dyn ShellCleanup>,
            command_id: None,
            armed: true,
        };
        (cleanup, guard)
    }

    /// TR-XFER-04: a failed `Send` after the command ended still returns the exit code
    /// and the error text of the command, not the broken pipe.
    #[tokio::test]
    async fn send_error_still_collects_the_exit_code_and_stderr() {
        let (_, mut guard) = idle_guard();
        let call = FakeCall {
            send_fails: true,
            poll: finished_with_error,
        };
        let output = drive_stdin_call(
            &call,
            "script",
            b"bytes",
            &mut guard,
            Duration::from_millis(200),
        )
        .await
        .expect("the output of the ended command");
        assert_eq!(output.exit_code, 1);
        assert_eq!(output.stderr, b"boom");
        guard.armed = false;
    }

    /// TR-XFER-04: a failed `Send` while the command still runs stays an error.
    #[tokio::test]
    async fn send_error_with_a_running_command_is_the_error() {
        let (_, mut guard) = idle_guard();
        let call = FakeCall {
            send_fails: true,
            poll: still_running,
        };
        let error = drive_stdin_call(
            &call,
            "script",
            b"bytes",
            &mut guard,
            Duration::from_millis(50),
        )
        .await
        .expect_err("the send error");
        assert!(error.to_string().contains("broken pipe"), "{error}");
        assert_eq!(guard.command_id.as_deref(), Some("cmd-1"));
        guard.armed = false;
    }

    /// TR-XFER-04: a dropped call terminates the command first and deletes the shell
    /// after it, so the delete is not blocked by the open handle on the host.
    #[tokio::test]
    async fn dropped_call_terminates_the_command_before_it_deletes_the_shell() {
        let (cleanup, mut guard) = idle_guard();
        guard.command_id = Some("cmd-1".to_owned());
        drop(guard);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            *cleanup.events.lock().expect("lock"),
            vec!["terminate:cmd-1".to_owned(), "delete".to_owned()]
        );
    }

    /// TR-XFER-04: a finished call leaves nothing to clean up, and a call that never
    /// started a command only deletes the shell.
    #[tokio::test]
    async fn disarmed_guard_does_nothing_and_an_unstarted_call_only_deletes() {
        let (cleanup, mut guard) = idle_guard();
        guard.armed = false;
        drop(guard);
        let (second, guard) = idle_guard();
        drop(guard);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(cleanup.events.lock().expect("lock").is_empty());
        assert_eq!(
            *second.events.lock().expect("lock"),
            vec!["delete-blocked".to_owned()]
        );
    }
}
