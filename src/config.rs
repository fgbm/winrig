//! The single point that reads and validates the configuration (DR-8, ADR-0004).
//!
//! Any invalid environment variable stops the start: [`load_config`] returns
//! [`ConfigError`] with the variable name and the expected format. Secrets are
//! not revealed in the messages. Values come through an `Fn(&str) ->
//! Option<String>` closure, not directly from `std::env`, so the configuration
//! can be tested without changing the process environment.

use std::fmt;

/// Smallest allowed TCP port number.
pub const MIN_PORT: u16 = 1;
/// Largest allowed TCP port number.
pub const MAX_PORT: u16 = 65535;

const TRUE_VALUES: [&str; 4] = ["1", "true", "yes", "on"];
const FALSE_VALUES: [&str; 4] = ["0", "false", "no", "off"];

/// Source of environment variable values.
pub type Env = dyn Fn(&str) -> Option<String>;

/// Invalid configuration: the message names the variable and the format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(String);

impl ConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

/// Severity used by the server journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// `DEBUG`.
    Debug,
    /// `INFO`.
    Info,
    /// `WARNING`.
    Warning,
    /// `ERROR`.
    Error,
    /// `CRITICAL`.
    Critical,
}

impl LogLevel {
    /// Canonical spelling for the logging subsystem.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warning => "WARNING",
            Self::Error => "ERROR",
            Self::Critical => "CRITICAL",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw.to_ascii_uppercase().as_str() {
            "DEBUG" => Some(Self::Debug),
            "INFO" => Some(Self::Info),
            "WARNING" => Some(Self::Warning),
            "ERROR" => Some(Self::Error),
            "CRITICAL" => Some(Self::Critical),
            _ => None,
        }
    }

    /// Directive for `tracing_subscriber::EnvFilter`.
    ///
    /// `EnvFilter` knows the levels `trace/debug/info/warn/error`; `WARNING` and
    /// `CRITICAL` are not a level for it but a target name, so `as_str()` cannot
    /// be passed directly: the filter takes the string as a target and silences
    /// the rest of the journal. Here the levels are mapped explicitly.
    #[must_use]
    pub fn filter_directive(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warning => "warn",
            Self::Error | Self::Critical => "error",
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the server does when the client declared no elicitation channel (TR-SEC-11).
///
/// The relaxation attaches to the absent channel only. A user refusal, a cancel,
/// a timeout and a transport error are never bypassed (ADR-0013 §20).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmFallback {
    /// Fail-closed: the operation does not run (default).
    Refuse,
    /// The operation runs, and the audit marks the absent confirmation.
    Proceed,
}

impl ConfirmFallback {
    fn parse(raw: &str) -> Option<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "refuse" => Some(Self::Refuse),
            "proceed" => Some(Self::Proceed),
            _ => None,
        }
    }

    /// Canonical spelling for the environment check (TR-PRF-18).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Refuse => "refuse",
            Self::Proceed => "proceed",
        }
    }
}

impl fmt::Display for ConfirmFallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Validated environment parameters.
///
/// `Debug` is implemented by hand: the secrets (`mcp_auth_token`,
/// `profile_token`) must not reach an accidental `{:?}` output (DR-4).
#[derive(Clone)]
pub struct AppConfig {
    /// Shared secret for the header path (`X-AD-User`); optional when a profile
    /// is used (DR-1, ADR-0009).
    pub mcp_auth_token: Option<String>,
    /// Address the HTTP server listens on.
    pub mcp_bind_host: String,
    /// TCP port of the HTTP server.
    pub mcpo_port: u16,
    /// Selected profile; `None` picks the only available one (ADR-0009).
    pub profile_name: Option<String>,
    /// Secret that opens the profile; required in stdio mode (ADR-0009).
    pub profile_token: Option<String>,
    /// Idle lifetime of the cached AD password, in seconds (0 means no expiry).
    pub ad_password_idle_ttl_seconds: u64,
    /// Directory for logs and audit; `None` means the profile state directory.
    pub log_dir: Option<String>,
    pub log_level: LogLevel,
    /// Journal size before rotation, in bytes.
    pub log_max_bytes: u64,
    /// How many rotated files to keep.
    pub log_backup_count: u32,
    /// AD failure threshold after which the password is not presented for a
    /// while (TR-SEC-01).
    pub ad_lockout_max_attempts: u32,
    /// Lockout window after failures, in seconds.
    pub ad_lockout_window_seconds: u64,
    /// Smallest secret length that is redacted in the reply to the agent.
    pub secret_redact_min_length: usize,
    /// Empty means loopback only; `*` means any host (TR-SEC-14).
    pub allowed_hosts: Vec<String>,
    /// Whether the TLS check downgrade is allowed (TR-SEC-06).
    pub allow_insecure_tls: bool,
    /// How many output characters of each call to keep in the audit.
    pub audit_max_output_chars: usize,
    /// Whether to write the command and output body to the audit or only metadata.
    pub audit_log_body: bool,
    /// How many seconds to wait for the answer to a modification confirmation.
    pub confirm_timeout_seconds: u64,
    /// Idle lifetime of the cached SFTP credentials, in seconds.
    pub sftp_cred_idle_ttl_seconds: u64,
    /// Whether writing files to the host is allowed (TR-FS-01, ADR-0013).
    pub allow_file_write: bool,
    /// Size limit of the written content, in bytes (TR-FS-04).
    pub max_write_bytes: usize,
    /// Whether running arbitrary commands is allowed (TR-EXE-01, ADR-0013).
    pub allow_command_exec: bool,
    /// Command prefixes the server admits; empty means any command (TR-EXE-02).
    pub allowed_commands: Vec<String>,
    /// What happens when the client declared no confirmation channel (TR-SEC-11).
    pub confirm_fallback: ConfirmFallback,
}

impl fmt::Debug for AppConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppConfig")
            .field(
                "mcp_auth_token",
                &self.mcp_auth_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("mcp_bind_host", &self.mcp_bind_host)
            .field("mcpo_port", &self.mcpo_port)
            .field("profile_name", &self.profile_name)
            .field(
                "profile_token",
                &self.profile_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "ad_password_idle_ttl_seconds",
                &self.ad_password_idle_ttl_seconds,
            )
            .field("log_dir", &self.log_dir)
            .field("log_level", &self.log_level)
            .field("log_max_bytes", &self.log_max_bytes)
            .field("log_backup_count", &self.log_backup_count)
            .field("ad_lockout_max_attempts", &self.ad_lockout_max_attempts)
            .field("ad_lockout_window_seconds", &self.ad_lockout_window_seconds)
            .field("secret_redact_min_length", &self.secret_redact_min_length)
            .field("allowed_hosts", &self.allowed_hosts)
            .field("allow_insecure_tls", &self.allow_insecure_tls)
            .field("audit_max_output_chars", &self.audit_max_output_chars)
            .field("audit_log_body", &self.audit_log_body)
            .field("confirm_timeout_seconds", &self.confirm_timeout_seconds)
            .field("allow_file_write", &self.allow_file_write)
            .field("max_write_bytes", &self.max_write_bytes)
            .field("allow_command_exec", &self.allow_command_exec)
            .field("allowed_commands", &self.allowed_commands)
            .field("confirm_fallback", &self.confirm_fallback)
            .field(
                "sftp_cred_idle_ttl_seconds",
                &self.sftp_cred_idle_ttl_seconds,
            )
            .finish()
    }
}

/// The value is trimmed of spaces; an empty string means absent.
fn read(env: &Env, name: &str) -> Option<String> {
    env(name)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn read_int(
    env: &Env,
    name: &str,
    default: i64,
    minimum: Option<i64>,
    maximum: Option<i64>,
) -> Result<i64, ConfigError> {
    let Some(raw) = read(env, name) else {
        return Ok(default);
    };
    let value = raw.parse::<i64>().map_err(|_| {
        let expected = match (minimum, maximum) {
            (Some(lo), Some(hi)) => format!("an integer between {lo} and {hi}"),
            (Some(lo), None) => format!("an integer of at least {lo}"),
            _ => "an integer".to_owned(),
        };
        ConfigError::new(format!(
            "{name}={raw:?} is not an integer; expected {expected}"
        ))
    })?;
    if let Some(lo) = minimum
        && value < lo
    {
        return Err(ConfigError::new(format!(
            "{name}={value} is below the minimum of {lo}"
        )));
    }
    if let Some(hi) = maximum
        && value > hi
    {
        return Err(ConfigError::new(format!(
            "{name}={value} is above the maximum of {hi}"
        )));
    }
    Ok(value)
}

fn read_bool(env: &Env, name: &str, default: bool) -> Result<bool, ConfigError> {
    let Some(raw) = read(env, name) else {
        return Ok(default);
    };
    let lowered = raw.to_ascii_lowercase();
    if TRUE_VALUES.contains(&lowered.as_str()) {
        return Ok(true);
    }
    if FALSE_VALUES.contains(&lowered.as_str()) {
        return Ok(false);
    }
    Err(ConfigError::new(format!(
        "{name}={raw:?} is not a boolean; expected one of true/false, 1/0, yes/no, on/off"
    )))
}

fn read_log_level(env: &Env, name: &str, default: LogLevel) -> Result<LogLevel, ConfigError> {
    let Some(raw) = read(env, name) else {
        return Ok(default);
    };
    LogLevel::parse(&raw).ok_or_else(|| {
        ConfigError::new(format!(
            "{name}={raw:?} is not a log level; expected one of DEBUG, ERROR, INFO, WARNING, CRITICAL"
        ))
    })
}

/// The host allowlist by the grammar of `policy::parse_allowed_hosts`.
///
/// A bad element refuses the start (DR-8): otherwise `*.corp.example` would
/// silently allow nothing, and the operator would not see why.
fn read_allowed_hosts(env: &Env) -> Result<Vec<String>, ConfigError> {
    let Some(raw) = read(env, "WINRIG_ALLOWED_HOSTS") else {
        return Ok(Vec::new());
    };
    crate::policy::parse_allowed_hosts(&raw).map_err(|entry| {
        ConfigError::new(format!(
            "WINRIG_ALLOWED_HOSTS entry {entry:?} is not valid; expected {}",
            crate::policy::ALLOWED_HOSTS_FORM
        ))
    })
}

/// The command allowlist by the grammar of `policy::parse_allowed_commands`.
///
/// A bad element refuses the start (DR-8): a prefix with a control character can
/// never match, so the operator must see why.
fn read_allowed_commands(env: &Env) -> Result<Vec<String>, ConfigError> {
    let Some(raw) = read(env, "WINRIG_ALLOWED_COMMANDS") else {
        return Ok(Vec::new());
    };
    crate::policy::parse_allowed_commands(&raw).map_err(|entry| {
        ConfigError::new(format!(
            "WINRIG_ALLOWED_COMMANDS entry {entry:?} is not valid; expected {}",
            crate::policy::ALLOWED_COMMANDS_FORM
        ))
    })
}

/// The fallback for a client without a confirmation channel (TR-SEC-11).
fn read_confirm_fallback(env: &Env) -> Result<ConfirmFallback, ConfigError> {
    let Some(raw) = read(env, "WINRIG_CONFIRM_FALLBACK") else {
        return Ok(ConfirmFallback::Refuse);
    };
    ConfirmFallback::parse(&raw).ok_or_else(|| {
        ConfigError::new(format!(
            "WINRIG_CONFIRM_FALLBACK={raw:?} is not valid; expected one of refuse, proceed"
        ))
    })
}

fn load_auth_token(env: &Env) -> Option<String> {
    read(env, "WINRIG_AUTH_TOKEN")
}

/// Name of the selected profile; an empty string means absent.
fn read_profile_name(env: &Env) -> Option<String> {
    read(env, "WINRIG_PROFILE")
}

/// Profile access token; required in stdio mode.
fn read_profile_token(env: &Env) -> Option<String> {
    read(env, "WINRIG_TOKEN")
}

/// Reads an integer and converts it to the target type without panicking.
///
/// The type upper bound is checked through `TryFrom`, so an oversized value
/// gives [`ConfigError`] with the variable name, not a panic (DR-8).
fn read_uint<T>(
    env: &Env,
    name: &str,
    default: i64,
    minimum: Option<i64>,
    maximum: Option<i64>,
) -> Result<T, ConfigError>
where
    T: TryFrom<i64>,
{
    let value = read_int(env, name, default, minimum, maximum)?;
    T::try_from(value).map_err(|_| {
        ConfigError::new(format!(
            "{name}={value} is out of range for the target type"
        ))
    })
}

/// Old variable names replaced by the `WINRIG_*` notation (ADR-0010).
///
/// A clean break: when an old name is set, the start refuses and names the new
/// one, so the operator does not think the value took effect.
pub const RENAMED_VARIABLES: &[(&str, &str)] = &[
    ("MCP_AUTH_TOKEN", "WINRIG_AUTH_TOKEN"),
    ("MCP_BIND_HOST", "WINRIG_BIND_HOST"),
    ("MCPO_PORT", "WINRIG_PORT"),
    (
        "AD_PASSWORD_IDLE_TTL_SECONDS",
        "WINRIG_PASSWORD_TTL_SECONDS",
    ),
    ("LOG_DIR", "WINRIG_LOG_DIR"),
    ("LOG_LEVEL", "WINRIG_LOG_LEVEL"),
    ("LOG_MAX_BYTES", "WINRIG_LOG_MAX_BYTES"),
    ("LOG_BACKUP_COUNT", "WINRIG_LOG_BACKUP_COUNT"),
    ("AUDIT_MAX_OUTPUT_CHARS", "WINRIG_AUDIT_MAX_OUTPUT_CHARS"),
    ("AUDIT_LOG_BODY", "WINRIG_AUDIT_LOG_BODY"),
    ("CONFIRM_TIMEOUT_SECONDS", "WINRIG_CONFIRM_TIMEOUT_SECONDS"),
    ("AD_LOCKOUT_MAX_ATTEMPTS", "WINRIG_LOCKOUT_ATTEMPTS"),
    ("AD_LOCKOUT_WINDOW_SECONDS", "WINRIG_LOCKOUT_WINDOW_SECONDS"),
    (
        "SECRET_REDACT_MIN_LENGTH",
        "WINRIG_SECRET_REDACT_MIN_LENGTH",
    ),
    ("ALLOWED_HOSTS", "WINRIG_ALLOWED_HOSTS"),
    ("ALLOW_INSECURE_TLS", "WINRIG_ALLOW_INSECURE_TLS"),
    ("SFTP_CRED_IDLE_TTL_SECONDS", "WINRIG_SFTP_CRED_TTL_SECONDS"),
];

/// Refuses when any of the old variable names is set.
///
/// All old names are checked at once, so the message lists the full set of the
/// ones found, not the first.
fn reject_renamed_variables(env: &Env) -> Result<(), ConfigError> {
    let found: Vec<String> = RENAMED_VARIABLES
        .iter()
        .filter(|(old, _)| read(env, old).is_some())
        .map(|(old, new)| format!("{old} -> {new}"))
        .collect();
    if found.is_empty() {
        return Ok(());
    }
    Err(ConfigError::new(format!(
        "the environment variable names use the WINRIG_* notation; rename: {}",
        found.join(", ")
    )))
}

/// Reads and validates the variables from the given source.
///
/// # Errors
///
/// Returns [`ConfigError`] for the first old variable name or the first invalid
/// variable, and names it.
pub fn load_config_from(env: &Env) -> Result<AppConfig, ConfigError> {
    reject_renamed_variables(env)?;
    let mcp_auth_token = load_auth_token(env);
    let profile_name = read_profile_name(env);
    let profile_token = read_profile_token(env);
    let log_dir = read(env, "WINRIG_LOG_DIR");
    Ok(AppConfig {
        mcp_auth_token,
        profile_name,
        profile_token,
        log_dir,
        mcp_bind_host: read(env, "WINRIG_BIND_HOST").unwrap_or_else(|| "127.0.0.1".to_owned()),
        mcpo_port: read_uint(
            env,
            "WINRIG_PORT",
            8005,
            Some(i64::from(MIN_PORT)),
            Some(i64::from(MAX_PORT)),
        )?,
        ad_password_idle_ttl_seconds: read_uint(
            env,
            "WINRIG_PASSWORD_TTL_SECONDS",
            3600,
            Some(0),
            None,
        )?,
        log_level: read_log_level(env, "WINRIG_LOG_LEVEL", LogLevel::Info)?,
        log_max_bytes: read_uint(env, "WINRIG_LOG_MAX_BYTES", 10 * 1024 * 1024, Some(1), None)?,
        log_backup_count: read_uint(
            env,
            "WINRIG_LOG_BACKUP_COUNT",
            5,
            Some(0),
            Some(i64::from(u32::MAX)),
        )?,
        ad_lockout_max_attempts: read_uint(
            env,
            "WINRIG_LOCKOUT_ATTEMPTS",
            3,
            Some(1),
            Some(i64::from(u32::MAX)),
        )?,
        ad_lockout_window_seconds: read_uint(
            env,
            "WINRIG_LOCKOUT_WINDOW_SECONDS",
            1800,
            Some(0),
            None,
        )?,
        secret_redact_min_length: read_uint(
            env,
            "WINRIG_SECRET_REDACT_MIN_LENGTH",
            4,
            Some(1),
            None,
        )?,
        allowed_hosts: read_allowed_hosts(env)?,
        allow_insecure_tls: read_bool(env, "WINRIG_ALLOW_INSECURE_TLS", false)?,
        audit_max_output_chars: read_uint(
            env,
            "WINRIG_AUDIT_MAX_OUTPUT_CHARS",
            2000,
            Some(0),
            None,
        )?,
        audit_log_body: read_bool(env, "WINRIG_AUDIT_LOG_BODY", true)?,
        confirm_timeout_seconds: read_uint(
            env,
            "WINRIG_CONFIRM_TIMEOUT_SECONDS",
            300,
            Some(1),
            None,
        )?,
        sftp_cred_idle_ttl_seconds: read_uint(
            env,
            "WINRIG_SFTP_CRED_TTL_SECONDS",
            3600,
            Some(0),
            None,
        )?,
        allow_file_write: read_bool(env, "WINRIG_ALLOW_FILE_WRITE", false)?,
        // The lower bound is one chunk: a smaller limit would mean a tool that
        // always refuses (ADR-0013 §8, §11).
        max_write_bytes: read_uint(
            env,
            "WINRIG_MAX_WRITE_BYTES",
            64 * 1024,
            Some(crate::ps::WRITE_CHUNK_BYTES as i64),
            None,
        )?,
        allow_command_exec: read_bool(env, "WINRIG_ALLOW_COMMAND_EXEC", false)?,
        allowed_commands: read_allowed_commands(env)?,
        confirm_fallback: read_confirm_fallback(env)?,
    })
}

/// Reads and validates the process environment variables.
///
/// # Errors
///
/// Returns [`ConfigError`] for the first invalid variable, and names it.
pub fn load_config() -> Result<AppConfig, ConfigError> {
    load_config_from(&|name| std::env::var(name).ok())
}

/// Canonical `(variable, value)` pairs of the known non-secret settings, for the
/// environment check (TR-PRF-18). A `None` value means the setting has no fixed
/// default. The order is the order the check prints them.
#[must_use]
pub fn setting_pairs(config: &AppConfig) -> Vec<(&'static str, Option<String>)> {
    vec![
        ("WINRIG_BIND_HOST", Some(config.mcp_bind_host.clone())),
        ("WINRIG_PORT", Some(config.mcpo_port.to_string())),
        (
            "WINRIG_PASSWORD_TTL_SECONDS",
            Some(config.ad_password_idle_ttl_seconds.to_string()),
        ),
        ("WINRIG_LOG_DIR", config.log_dir.clone()),
        (
            "WINRIG_LOG_LEVEL",
            Some(config.log_level.as_str().to_owned()),
        ),
        (
            "WINRIG_LOG_MAX_BYTES",
            Some(config.log_max_bytes.to_string()),
        ),
        (
            "WINRIG_LOG_BACKUP_COUNT",
            Some(config.log_backup_count.to_string()),
        ),
        (
            "WINRIG_LOCKOUT_ATTEMPTS",
            Some(config.ad_lockout_max_attempts.to_string()),
        ),
        (
            "WINRIG_LOCKOUT_WINDOW_SECONDS",
            Some(config.ad_lockout_window_seconds.to_string()),
        ),
        (
            "WINRIG_SECRET_REDACT_MIN_LENGTH",
            Some(config.secret_redact_min_length.to_string()),
        ),
        (
            "WINRIG_ALLOWED_HOSTS",
            Some(canonical_host_list(&config.allowed_hosts)),
        ),
        (
            "WINRIG_ALLOW_INSECURE_TLS",
            Some(config.allow_insecure_tls.to_string()),
        ),
        (
            "WINRIG_AUDIT_MAX_OUTPUT_CHARS",
            Some(config.audit_max_output_chars.to_string()),
        ),
        (
            "WINRIG_AUDIT_LOG_BODY",
            Some(config.audit_log_body.to_string()),
        ),
        (
            "WINRIG_CONFIRM_TIMEOUT_SECONDS",
            Some(config.confirm_timeout_seconds.to_string()),
        ),
        (
            "WINRIG_SFTP_CRED_TTL_SECONDS",
            Some(config.sftp_cred_idle_ttl_seconds.to_string()),
        ),
        (
            "WINRIG_ALLOW_FILE_WRITE",
            Some(config.allow_file_write.to_string()),
        ),
        (
            "WINRIG_MAX_WRITE_BYTES",
            Some(config.max_write_bytes.to_string()),
        ),
        (
            "WINRIG_ALLOW_COMMAND_EXEC",
            Some(config.allow_command_exec.to_string()),
        ),
        (
            "WINRIG_ALLOWED_COMMANDS",
            Some(canonical_command_list(&config.allowed_commands)),
        ),
        (
            "WINRIG_CONFIRM_FALLBACK",
            Some(config.confirm_fallback.as_str().to_owned()),
        ),
    ]
}

/// The list is a set, so the canonical form is sorted.
fn canonical_command_list(commands: &[String]) -> String {
    let mut sorted = commands.to_vec();
    sorted.sort();
    sorted.join(",")
}

/// Order does not matter for a membership list, so the canonical form is sorted.
fn canonical_host_list(hosts: &[String]) -> String {
    let mut sorted = hosts.to_vec();
    sorted.sort();
    sorted.join(",")
}

/// Text of one known variable in canonical form, or `None` when the parser
/// refuses it (TR-PRF-18). One variable is normalized alone, so a bad value does
/// not hide the others.
#[must_use]
pub fn canonical_setting(name: &str, raw: &str) -> Option<String> {
    let target = name.to_owned();
    let value = raw.to_owned();
    let env = move |key: &str| (key == target.as_str()).then(|| value.clone());
    let config = load_config_from(&env).ok()?;
    setting_pairs(&config)
        .into_iter()
        .find(|(key, _)| *key == name)
        .and_then(|(_, value)| value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Missing keys give `None`.
    ///
    /// `+ use<>` is required: in Rust 2024 `impl Trait` otherwise captures the
    /// lifetime of the argument, and the temporary slice outlives the call.
    fn source(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name: &str| map.get(name).cloned()
    }

    fn base() -> Vec<(&'static str, &'static str)> {
        vec![("WINRIG_AUTH_TOKEN", "test-token")]
    }

    fn with(extra: &[(&'static str, &'static str)]) -> Vec<(&'static str, &'static str)> {
        let mut all = base();
        all.extend_from_slice(extra);
        all
    }

    #[test]
    fn defaults_preserved() {
        let env = source(&base());
        let config = load_config_from(&env).expect("valid");
        assert_eq!(config.log_dir, None);
        assert_eq!(config.log_level, LogLevel::Info);
        assert_eq!(config.log_max_bytes, 10_485_760);
        assert_eq!(config.log_backup_count, 5);
        assert_eq!(config.ad_password_idle_ttl_seconds, 3600);
        assert_eq!(config.mcpo_port, 8005);
        assert_eq!(config.mcp_bind_host, "127.0.0.1");
        assert_eq!(config.mcp_auth_token.as_deref(), Some("test-token"));
        assert_eq!(config.ad_lockout_max_attempts, 3);
        assert_eq!(config.ad_lockout_window_seconds, 1800);
        assert_eq!(config.secret_redact_min_length, 4);
        assert!(config.allowed_hosts.is_empty());
        // AC-SEC06-1: the TLS check downgrade is forbidden until the operator
        // allows it explicitly (TR-SEC-06, ADR-0015).
        assert!(!config.allow_insecure_tls);
        assert_eq!(config.audit_max_output_chars, 2000);
        assert!(config.audit_log_body);
        assert_eq!(config.sftp_cred_idle_ttl_seconds, 3600);
        assert_eq!(config.confirm_timeout_seconds, 300);
        // TR-FS-01: file write is off until the operator turns it on.
        assert!(!config.allow_file_write);
        // TR-FS-04: a patience limit, not a protocol limit (ADR-0013 §11).
        assert_eq!(config.max_write_bytes, 64 * 1024);
        // TR-EXE-01: arbitrary execution is off until the operator turns it on.
        assert!(!config.allow_command_exec);
        // TR-EXE-02: an empty command list admits any command.
        assert!(config.allowed_commands.is_empty());
        // TR-SEC-11: a missing confirmation channel is a refusal by default.
        assert_eq!(config.confirm_fallback, ConfirmFallback::Refuse);
    }

    /// TR-EXE-01: the setting is switched by the usual boolean values.
    #[test]
    fn command_exec_is_switched_by_the_operator() {
        let env = source(&with(&[("WINRIG_ALLOW_COMMAND_EXEC", "true")]));
        assert!(load_config_from(&env).expect("valid").allow_command_exec);
        let env = source(&with(&[("WINRIG_ALLOW_COMMAND_EXEC", "0")]));
        assert!(!load_config_from(&env).expect("valid").allow_command_exec);
    }

    /// TR-EXE-02: the command list is read and trimmed.
    #[test]
    fn allowed_commands_are_read() {
        let env = source(&with(&[(
            "WINRIG_ALLOWED_COMMANDS",
            " Get-Service ,, ipconfig ",
        )]));
        assert_eq!(
            load_config_from(&env).expect("valid").allowed_commands,
            ["Get-Service", "ipconfig"]
        );
    }

    /// DR-8: a bad command entry refuses the start with the variable name.
    #[test]
    fn invalid_allowed_commands_entry_refuses_startup() {
        let env = source(&with(&[("WINRIG_ALLOWED_COMMANDS", "ok,bad\nentry")]));
        let error = load_config_from(&env).expect_err("must fail").to_string();
        assert!(error.contains("WINRIG_ALLOWED_COMMANDS"), "{error}");
        assert!(error.contains("prefixes"), "{error}");
    }

    /// TR-SEC-11: the fallback reads `proceed`, defaults to `refuse`, and refuses
    /// an unknown value with the variable name (DR-8).
    #[test]
    fn confirm_fallback_reads_and_refuses_a_bad_value() {
        let env = source(&with(&[("WINRIG_CONFIRM_FALLBACK", "proceed")]));
        assert_eq!(
            load_config_from(&env).expect("valid").confirm_fallback,
            ConfirmFallback::Proceed
        );
        let env = source(&with(&[("WINRIG_CONFIRM_FALLBACK", "maybe")]));
        let error = load_config_from(&env).expect_err("must fail").to_string();
        assert!(error.contains("WINRIG_CONFIRM_FALLBACK"), "{error}");
        assert!(error.contains("proceed"), "{error}");
    }

    /// TR-FS-01: the setting is switched by the usual boolean values.
    #[test]
    fn file_write_is_switched_by_the_operator() {
        let env = source(&with(&[("WINRIG_ALLOW_FILE_WRITE", "true")]));
        assert!(load_config_from(&env).expect("valid").allow_file_write);
        let env = source(&with(&[("WINRIG_ALLOW_FILE_WRITE", "0")]));
        assert!(!load_config_from(&env).expect("valid").allow_file_write);
    }

    /// TR-FS-04: the limit cannot be below one chunk; otherwise the tool would
    /// always refuse, and the cause would read as a size error.
    #[test]
    fn max_write_bytes_must_hold_at_least_one_chunk() {
        let env = source(&with(&[("WINRIG_MAX_WRITE_BYTES", "100")]));
        let error = load_config_from(&env).expect_err("below one chunk");
        assert!(
            error.to_string().contains("WINRIG_MAX_WRITE_BYTES"),
            "{error}"
        );
        let env = source(&with(&[("WINRIG_MAX_WRITE_BYTES", "2000")]));
        assert_eq!(load_config_from(&env).expect("valid").max_write_bytes, 2000);
    }

    /// AC-PRF-47: without a profile and without a token the config still reads,
    /// and the entry point makes the "at least one secret" decision.
    #[test]
    fn no_secret_is_accepted_by_parser() {
        let env = source(&[]);
        let config = load_config_from(&env).expect("valid");
        assert_eq!(config.mcp_auth_token, None);
        assert_eq!(config.profile_name, None);
        assert_eq!(config.profile_token, None);
    }

    /// AC-PRF-21: tokens are not printed through Debug.
    #[test]
    fn debug_redacts_tokens() {
        let env = source(&with(&[
            ("WINRIG_AUTH_TOKEN", "shared-secret-value"),
            ("WINRIG_TOKEN", "profile-token-value"),
        ]));
        let rendered = format!("{:?}", load_config_from(&env).expect("valid"));
        assert!(!rendered.contains("shared-secret-value"), "{rendered}");
        assert!(!rendered.contains("profile-token-value"), "{rendered}");
        assert!(rendered.contains("[REDACTED]"));
    }

    /// AC-PRF-04/42: the profile name and the token are read from the environment.
    #[test]
    fn profile_variables_are_read() {
        let env = source(&with(&[
            ("WINRIG_PROFILE", "corp"),
            ("WINRIG_TOKEN", "secret-token"),
        ]));
        let config = load_config_from(&env).expect("valid");
        assert_eq!(config.profile_name.as_deref(), Some("corp"));
        assert_eq!(config.profile_token.as_deref(), Some("secret-token"));
    }

    /// AC-PRF-09: LOG_DIR stays an explicit override.
    #[test]
    fn log_dir_override_is_read() {
        let env = source(&with(&[("WINRIG_LOG_DIR", "/tmp/winrig-logs")]));
        assert_eq!(
            load_config_from(&env).expect("valid").log_dir.as_deref(),
            Some("/tmp/winrig-logs")
        );
    }

    /// Clean break: an old variable name refuses the start and names the new one.
    #[test]
    fn renamed_variables_are_rejected_with_the_new_name() {
        for (old, new) in [
            ("MCP_AUTH_TOKEN", "WINRIG_AUTH_TOKEN"),
            ("MCPO_PORT", "WINRIG_PORT"),
            ("LOG_DIR", "WINRIG_LOG_DIR"),
            ("ALLOWED_HOSTS", "WINRIG_ALLOWED_HOSTS"),
            ("AD_LOCKOUT_MAX_ATTEMPTS", "WINRIG_LOCKOUT_ATTEMPTS"),
        ] {
            let env = source(&with(&[(old, "value")]));
            let error = load_config_from(&env).expect_err("must refuse");
            let message = error.to_string();
            assert!(message.contains(old), "{message}");
            assert!(message.contains(new), "{message}");
        }
    }

    /// Several old names are listed in one message.
    #[test]
    fn several_renamed_variables_are_listed_together() {
        let env = source(&with(&[("MCPO_PORT", "1"), ("LOG_LEVEL", "INFO")]));
        let message = load_config_from(&env).expect_err("must refuse").to_string();
        assert!(message.contains("MCPO_PORT -> WINRIG_PORT"), "{message}");
        assert!(
            message.contains("LOG_LEVEL -> WINRIG_LOG_LEVEL"),
            "{message}"
        );
    }

    /// The new names are read, the old ones are not.
    #[test]
    fn only_new_names_are_effective() {
        let env = source(&with(&[("WINRIG_PORT", "9000")]));
        assert_eq!(load_config_from(&env).expect("valid").mcpo_port, 9000);
    }

    #[test]
    fn invalid_log_level_names_variable() {
        let env = source(&with(&[("WINRIG_LOG_LEVEL", "BOGUS")]));
        let err = load_config_from(&env).expect_err("must fail");
        assert!(err.to_string().contains("WINRIG_LOG_LEVEL"));
    }

    #[test]
    fn invalid_integer_names_variable() {
        let env = source(&with(&[("WINRIG_LOG_MAX_BYTES", "abc")]));
        let err = load_config_from(&env).expect_err("must fail");
        assert!(err.to_string().contains("WINRIG_LOG_MAX_BYTES"));
    }

    #[test]
    fn new_variables_are_read() {
        let env = source(&with(&[
            ("WINRIG_LOCKOUT_ATTEMPTS", "7"),
            ("WINRIG_LOCKOUT_WINDOW_SECONDS", "60"),
            ("WINRIG_SECRET_REDACT_MIN_LENGTH", "8"),
            ("WINRIG_ALLOW_INSECURE_TLS", "true"),
        ]));
        let config = load_config_from(&env).expect("valid");
        assert_eq!(config.ad_lockout_max_attempts, 7);
        assert_eq!(config.ad_lockout_window_seconds, 60);
        assert_eq!(config.secret_redact_min_length, 8);
        assert!(config.allow_insecure_tls);
    }

    #[test]
    fn allowed_hosts_parsed_and_case_folded() {
        let env = source(&with(&[(
            "WINRIG_ALLOWED_HOSTS",
            " HOST1 , .Example.com ,host2,, ",
        )]));
        let config = load_config_from(&env).expect("valid");
        assert_eq!(config.allowed_hosts, ["host1", ".example.com", "host2"]);
    }

    /// AC-SEC05-6: a bad allowlist element refuses the start with the variable
    /// name and the expected form (DR-8).
    #[test]
    fn invalid_allowed_hosts_entry_refuses_startup() {
        let env = source(&with(&[("WINRIG_ALLOWED_HOSTS", "host1,*.example.com")]));
        let error = load_config_from(&env).expect_err("must fail").to_string();
        assert!(error.contains("WINRIG_ALLOWED_HOSTS"), "{error}");
        assert!(error.contains("*.example.com"), "{error}");
        assert!(error.contains("'.suffix'"), "{error}");
    }

    #[test]
    fn allowed_hosts_leading_dot_suffix_preserved() {
        let env = source(&with(&[("WINRIG_ALLOWED_HOSTS", ".example.com, Host1")]));
        let config = load_config_from(&env).expect("valid");
        assert_eq!(config.allowed_hosts, [".example.com", "host1"]);
    }

    #[test]
    fn boolean_forms() {
        for raw in ["1", "true", "TRUE", "Yes", "on"] {
            let env = source(&with(&[("WINRIG_ALLOW_INSECURE_TLS", raw)]));
            assert!(load_config_from(&env).expect("valid").allow_insecure_tls);
        }
        for raw in ["0", "false", "No", "OFF"] {
            let env = source(&with(&[("WINRIG_ALLOW_INSECURE_TLS", raw)]));
            assert!(!load_config_from(&env).expect("valid").allow_insecure_tls);
        }
    }

    #[test]
    fn invalid_boolean_names_variable() {
        let env = source(&with(&[("WINRIG_ALLOW_INSECURE_TLS", "maybe")]));
        let err = load_config_from(&env).expect_err("must fail");
        assert!(err.to_string().contains("WINRIG_ALLOW_INSECURE_TLS"));
    }

    #[test]
    fn lockout_attempts_below_one_rejected() {
        for raw in ["0", "-1"] {
            let env = source(&with(&[("WINRIG_LOCKOUT_ATTEMPTS", raw)]));
            let err = load_config_from(&env).expect_err("must fail");
            assert!(err.to_string().contains("WINRIG_LOCKOUT_ATTEMPTS"));
        }
    }

    #[test]
    fn lockout_window_zero_allowed_and_negative_rejected() {
        let zero = source(&with(&[("WINRIG_LOCKOUT_WINDOW_SECONDS", "0")]));
        assert_eq!(
            load_config_from(&zero)
                .expect("valid")
                .ad_lockout_window_seconds,
            0
        );
        let negative = source(&with(&[("WINRIG_LOCKOUT_WINDOW_SECONDS", "-5")]));
        assert!(load_config_from(&negative).is_err());
    }

    #[test]
    fn port_out_of_range_rejected() {
        for raw in ["0", "65536", "-1"] {
            let env = source(&with(&[("WINRIG_PORT", raw)]));
            let err = load_config_from(&env).expect_err("must fail");
            assert!(err.to_string().contains("WINRIG_PORT"));
        }
    }

    #[test]
    fn audit_defaults_and_reads() {
        let default = source(&base());
        let config = load_config_from(&default).expect("valid");
        assert_eq!(config.audit_max_output_chars, 2000);
        assert!(config.audit_log_body);

        let env = source(&with(&[
            ("WINRIG_AUDIT_MAX_OUTPUT_CHARS", "500"),
            ("WINRIG_AUDIT_LOG_BODY", "off"),
            ("WINRIG_SFTP_CRED_TTL_SECONDS", "60"),
        ]));
        let config = load_config_from(&env).expect("valid");
        assert_eq!(config.audit_max_output_chars, 500);
        assert!(!config.audit_log_body);
        assert_eq!(config.sftp_cred_idle_ttl_seconds, 60);
    }

    #[test]
    fn audit_log_body_empty_is_default_true() {
        let env = source(&with(&[("WINRIG_AUDIT_LOG_BODY", "")]));
        assert!(load_config_from(&env).expect("valid").audit_log_body);
    }

    #[test]
    fn log_level_filter_directives_match_env_filter_levels() {
        // `WARNING`/`CRITICAL` do not exist for EnvFilter: it would take them as
        // a target and turn the journal off. The directive must be a valid level.
        assert_eq!(LogLevel::Debug.filter_directive(), "debug");
        assert_eq!(LogLevel::Info.filter_directive(), "info");
        assert_eq!(LogLevel::Warning.filter_directive(), "warn");
        assert_eq!(LogLevel::Error.filter_directive(), "error");
        assert_eq!(LogLevel::Critical.filter_directive(), "error");
    }

    #[test]
    fn confirm_timeout_default_and_read() {
        let default = source(&base());
        assert_eq!(
            load_config_from(&default)
                .expect("valid")
                .confirm_timeout_seconds,
            300
        );
        let env = source(&with(&[("WINRIG_CONFIRM_TIMEOUT_SECONDS", "10")]));
        assert_eq!(
            load_config_from(&env)
                .expect("valid")
                .confirm_timeout_seconds,
            10
        );
    }

    #[test]
    fn confirm_timeout_zero_rejected() {
        let env = source(&with(&[("WINRIG_CONFIRM_TIMEOUT_SECONDS", "0")]));
        let err = load_config_from(&env).expect_err("must fail");
        assert!(err.to_string().contains("WINRIG_CONFIRM_TIMEOUT_SECONDS"));
    }

    #[test]
    fn integer_below_minimum_reports_bound() {
        let env = source(&with(&[("WINRIG_LOG_MAX_BYTES", "0")]));
        let err = load_config_from(&env).expect_err("must fail");
        assert_eq!(
            err.to_string(),
            "WINRIG_LOG_MAX_BYTES=0 is below the minimum of 1"
        );
    }

    #[test]
    fn integer_above_maximum_reports_bound() {
        let env = source(&with(&[("WINRIG_PORT", "70000")]));
        let err = load_config_from(&env).expect_err("must fail");
        assert_eq!(
            err.to_string(),
            "WINRIG_PORT=70000 is above the maximum of 65535"
        );
    }

    #[test]
    fn secret_redact_min_length_below_one_rejected() {
        let env = source(&with(&[("WINRIG_SECRET_REDACT_MIN_LENGTH", "0")]));
        assert!(load_config_from(&env).is_err());
    }

    #[test]
    fn invalid_audit_log_body_names_variable() {
        let env = source(&with(&[("WINRIG_AUDIT_LOG_BODY", "maybe")]));
        let err = load_config_from(&env).expect_err("must fail");
        assert!(err.to_string().contains("WINRIG_AUDIT_LOG_BODY"));
    }

    #[test]
    fn u32_overflow_reports_variable_instead_of_panicking() {
        // DR-8: an oversized value must not panic (it used to exit 101).
        for name in ["WINRIG_LOG_BACKUP_COUNT", "WINRIG_LOCKOUT_ATTEMPTS"] {
            let env = source(&with(&[(name, "4294967296")]));
            let err = load_config_from(&env).expect_err("must fail");
            assert!(err.to_string().contains(name), "{err}");
        }
    }

    #[test]
    fn u32_maximum_is_accepted() {
        let env = source(&with(&[("WINRIG_LOG_BACKUP_COUNT", "4294967295")]));
        let config = load_config_from(&env).expect("valid");
        assert_eq!(config.log_backup_count, u32::MAX);
    }

    #[test]
    fn negative_value_for_unsigned_field_is_rejected() {
        let env = source(&with(&[("WINRIG_LOG_BACKUP_COUNT", "-1")]));
        assert!(load_config_from(&env).is_err());
    }

    /// TR-PRF-18: the environment check reads the same values as the parser, so
    /// `1` and `true` agree and a host list is normalized and sorted.
    #[test]
    fn setting_pairs_use_the_parser_forms() {
        let env = source(&with(&[
            ("WINRIG_ALLOW_INSECURE_TLS", "1"),
            ("WINRIG_ALLOWED_HOSTS", "Host1,.Corp.Example"),
            ("WINRIG_PASSWORD_TTL_SECONDS", "0300"),
        ]));
        let pairs: BTreeMap<&str, Option<String>> =
            setting_pairs(&load_config_from(&env).expect("valid"))
                .into_iter()
                .collect();
        assert_eq!(pairs["WINRIG_ALLOW_INSECURE_TLS"].as_deref(), Some("true"));
        assert_eq!(
            pairs["WINRIG_ALLOWED_HOSTS"].as_deref(),
            Some(".corp.example,host1")
        );
        assert_eq!(pairs["WINRIG_PASSWORD_TTL_SECONDS"].as_deref(), Some("300"));
        assert_eq!(pairs["WINRIG_LOG_DIR"], None);
    }

    /// TR-PRF-18: the empty environment gives a valid default configuration, and
    /// one variable normalizes alone.
    #[test]
    fn canonical_setting_normalizes_one_variable() {
        assert!(load_config_from(&|_| None).is_ok());
        assert_eq!(
            canonical_setting("WINRIG_ALLOW_INSECURE_TLS", "ON").as_deref(),
            Some("true")
        );
        assert_eq!(
            canonical_setting("WINRIG_ALLOWED_HOSTS", "B,.A").as_deref(),
            Some(".a,b")
        );
        assert_eq!(
            canonical_setting("WINRIG_PORT", "9000").as_deref(),
            Some("9000")
        );
        assert_eq!(canonical_setting("WINRIG_PORT", "abc"), None);
        assert_eq!(canonical_setting("WINRIG_PORT", "70000"), None);
    }
}
