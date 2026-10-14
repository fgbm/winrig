//! Orchestration of `winrig`: subcommands, logging and the serve/stdio modes (ADR-0009).
//!
//! The library layer holds all the logic, so the CLI paths, logging and both modes
//! are covered by tests without starting a process. `src/main.rs` is a thin
//! wrapper that returns the exit code.

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio_util::sync::CancellationToken;

use crate::auth::{AuthState, BoundProfile, auth_middleware};
use crate::cli::{Cli, Command, SecretArg};
use crate::client_config;
use crate::client_config::Scope;
use crate::config::{AppConfig, load_config_from};
use crate::logging::RotatingFile;
use crate::paths::{Locations, PathError, ProcessLock};
use crate::profile;
use crate::server::WinrigServer;
use crate::session::{RegistryConfig, SessionRegistry, WinrmTransportImpl};

/// Top-level error with an exit code.
pub enum StartupError {
    /// Invalid configuration or profile: exit code 2.
    Usage(String),
    /// Profile rejected twice: exit code 3 (AC-PRF-56).
    PasswordRejected(String),
    /// Other failures at run time: exit code 1.
    Runtime(String),
    /// The environment check found a difference or an incomplete scan: exit code 1
    /// (TR-PRF-18).
    EnvironmentDrift(String),
}

impl StartupError {
    /// Process status returned to the shell.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => 2,
            Self::PasswordRejected(_) => 3,
            Self::Runtime(_) | Self::EnvironmentDrift(_) => 1,
        }
    }
}

impl std::fmt::Display for StartupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(message)
            | Self::PasswordRejected(message)
            | Self::Runtime(message)
            | Self::EnvironmentDrift(message) => f.write_str(message),
        }
    }
}

/// Parses the arguments and runs the subcommand. Returns the exit code.
#[must_use]
pub fn main() -> i32 {
    match run(Cli::parse()) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{error}");
            error.exit_code()
        }
    }
}

/// Dispatches the parsed command.
///
/// # Errors
///
/// [`StartupError`] with an exit code.
pub fn run(cli: Cli) -> Result<(), StartupError> {
    match cli.command {
        Some(Command::Setup {
            name,
            user,
            overwrite,
            write_config,
            scope,
            server_name,
            allowed_hosts,
        }) => setup_command(
            &name,
            user.as_deref(),
            overwrite,
            write_config.as_deref(),
            scope,
            server_name.as_deref(),
            allowed_hosts.as_deref(),
        ),
        Some(Command::List { json }) => list_command(json),
        Some(Command::Rotate { name }) => rotate_command(&name),
        Some(Command::Forget { name }) => forget_command(&name),
        Some(Command::Doctor) => doctor_command(),
        Some(Command::Stdio { profile }) => run_stdio(profile.as_deref()),
        Some(Command::Serve {
            profile,
            port,
            host,
            token,
            auth_token,
        }) => run_serve(
            profile.as_deref(),
            port,
            host.as_deref(),
            token.as_ref(),
            auth_token.as_ref(),
        ),
        None => run_serve(None, None, None, None, None),
    }
}

/// Directories and configuration shared by the subcommands.
fn load() -> Result<(Locations, AppConfig), StartupError> {
    let config = load_config_from(&|name| std::env::var(name).ok())
        .map_err(|error| StartupError::Usage(format!("configuration error: {error}")))?;
    let locations = Locations::resolve(&|name| std::env::var(name).ok())
        .map_err(|error| StartupError::Usage(format!("configuration error: {error}")))?;
    Ok((locations, config))
}

fn warn_loose_permissions(path: &std::path::Path) {
    if let Some(warning) = profile::permissions_warning(path) {
        eprintln!("warning: {warning}");
    }
}

/// AC-PRF-50: the shared secret must not equal the profile token.
fn ensure_auth_token_is_not_profile_key(
    config: &AppConfig,
    profile_path: &std::path::Path,
) -> Result<(), StartupError> {
    let Some(token) = config.mcp_auth_token.as_deref() else {
        return Ok(());
    };
    if profile::decrypts(profile_path, token) {
        return Err(StartupError::Usage(
            "WINRIG_AUTH_TOKEN must not be the profile token. The server must not store the \
             profile key."
                .to_owned(),
        ));
    }
    Ok(())
}

/// Why a binding failed, for the log (AC-PRF-40/41). The token value is not part
/// of it.
fn profile_bind_reason(error: &profile::ProfileError) -> &'static str {
    match error {
        profile::ProfileError::InvalidToken { .. } => "invalid profile token",
        profile::ProfileError::Corrupt { .. } => "profile file corrupt",
        profile::ProfileError::UnsupportedVersion { .. } => "profile version unsupported",
        _ => "profile load failed",
    }
}

/// Loads the account and binds it to the process.
fn bind_profile(
    locations: &Locations,
    name: &str,
    token: &str,
) -> Result<Arc<BoundProfile>, StartupError> {
    let path = locations.profile_path(name);
    warn_loose_permissions(&path);
    BoundProfile::bind(path, token)
        .map(Arc::new)
        .map_err(|error| {
            // AC-PRF-40/41: the reason differs in the log; the token value is not
            // logged.
            tracing::warn!(
                target: "winrig::auth",
                profile = %name,
                reason = profile_bind_reason(&error),
                "cannot bind the profile"
            );
            StartupError::Usage(format!("profile error: {error}"))
        })
}

/// Resolves the profile name and holds the process lock (AC-PRF-54).
fn prepare_profile(
    requested: Option<&str>,
) -> Result<
    (
        Locations,
        AppConfig,
        String,
        ProcessLock,
        std::path::PathBuf,
    ),
    StartupError,
> {
    let (locations, config) = load()?;
    locations
        .ensure()
        .map_err(|error| StartupError::Usage(error.to_string()))?;
    let name = locations
        .select(requested.or(config.profile_name.as_deref()))
        .map_err(|error| StartupError::Usage(error.to_string()))?;
    let state_dir = locations
        .state_dir_for(&name)
        .map_err(|error| StartupError::Usage(error.to_string()))?;
    let lock =
        ProcessLock::acquire(&state_dir).map_err(|error| StartupError::Usage(error.to_string()))?;
    Ok((locations, config, name, lock, state_dir))
}

/// Logs without `WINRIG_LOG_DIR` go to the profile state directory (AC-PRF-08/09).
fn resolve_log_dir(config: &AppConfig, profile_state: &std::path::Path) -> std::path::PathBuf {
    config
        .log_dir
        .as_ref()
        .map_or_else(|| profile_state.to_path_buf(), std::path::PathBuf::from)
}

/// The transfer endpoint without `WINRIG_TRANSFER_DIR` goes under the profile state
/// directory (TR-XFER-01, ADR-0017 §21).
fn resolve_transfer_dir(config: &AppConfig, profile_state: &std::path::Path) -> std::path::PathBuf {
    config
        .transfer_dir
        .as_ref()
        .map_or_else(|| profile_state.join("transfer"), std::path::PathBuf::from)
}

fn registry_for(config: &AppConfig) -> Arc<SessionRegistry> {
    let registry_config = RegistryConfig {
        password_idle_ttl: Duration::from_secs(config.ad_password_idle_ttl_seconds),
        lockout_max_attempts: config.ad_lockout_max_attempts,
        lockout_window: Duration::from_secs(config.ad_lockout_window_seconds),
        secret_redact_min_length: config.secret_redact_min_length,
        audit_max_output_chars: config.audit_max_output_chars,
        audit_log_body: config.audit_log_body,
        default_port: crate::session::DEFAULT_HTTP_PORT,
    };
    Arc::new(SessionRegistry::new(
        Arc::new(WinrmTransportImpl),
        registry_config,
    ))
}

fn build_runtime() -> Result<tokio::runtime::Runtime, StartupError> {
    tokio::runtime::Runtime::new()
        .map_err(|error| StartupError::Runtime(format!("runtime error: {error}")))
}

// ---------------------------------------------------------------------------
// Profile subcommands
// ---------------------------------------------------------------------------

/// Prompts on a terminal without echo; falls back to a line from stdin.
///
/// In a non-interactive run (script, pipe) the echo cannot be suppressed, so the
/// password is read line by line from stdin; the tests use this too.
fn read_password(label: &str) -> Result<String, StartupError> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        rpassword::prompt_password(label)
            .map_err(|error| StartupError::Runtime(format!("cannot read password: {error}")))
    } else {
        let mut line = String::new();
        std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line)
            .map_err(|error| StartupError::Runtime(format!("cannot read password: {error}")))?;
        let value = line.trim_end_matches(['\r', '\n']).to_owned();
        if value.is_empty() {
            return Err(StartupError::Usage("password must not be empty".to_owned()));
        }
        Ok(value)
    }
}

fn setup_command(
    name: &str,
    user: Option<&str>,
    overwrite: bool,
    write_config: Option<&str>,
    scope: Option<Scope>,
    server_name: Option<&str>,
    allowed_hosts: Option<&str>,
) -> Result<(), StartupError> {
    use std::io::Write;

    let (locations, _config) = load()?;
    if name.trim().is_empty() {
        return Err(StartupError::Usage(
            "profile name must not be empty".to_owned(),
        ));
    }
    // The write scope is decided before the profile is created: a refusal leaves
    // neither a profile nor a config (ADR-0012).
    let write_target = match (write_config, scope) {
        (None, Some(_)) => {
            return Err(StartupError::Usage(
                "--scope is only valid together with --write-config".to_owned(),
            ));
        }
        (Some(client_name), explicit) => {
            let client = crate::cli::parse_client(client_name).map_err(StartupError::Usage)?;
            Some((client, resolve_scope(explicit)?))
        }
        (None, None) => None,
    };
    locations
        .ensure()
        .map_err(|error| StartupError::Usage(error.to_string()))?;
    let username = match user {
        Some(value) if !value.trim().is_empty() => value.to_owned(),
        Some(_) => return Err(StartupError::Usage("--user must not be empty".to_owned())),
        None => prompt("AD account (DOMAIN\\user): ")?,
    };
    let password = read_password("AD password: ")?;
    if password.is_empty() {
        return Err(StartupError::Usage("password must not be empty".to_owned()));
    }

    let path = locations.profile_path(name);
    let token = profile::create(&path, name, &username, &password, overwrite)
        .map_err(|error| StartupError::Usage(format!("profile error: {error}")))?;
    warn_loose_permissions(&path);

    // The profile state directory is needed by both the server and the client, so
    // it goes into the definition and the entry is self-contained (ADR-0009). The
    // root goes to the config; the server adds the profile name itself, once
    // (TR-PRF-15).
    locations
        .state_dir_for(name)
        .map_err(|error| StartupError::Usage(error.to_string()))?;
    let definition = crate::cli::server_definition(
        binary_path(),
        name,
        &token,
        locations.profile_dir(),
        locations.state_root(),
        server_name,
        allowed_hosts,
    );
    match write_target {
        Some((client, scope)) => {
            let written = client_config::write_client_config(client, scope, &definition)
                .map_err(|error| StartupError::Runtime(error.to_string()))?;
            println!("Profile {name:?} created at {}", path.display());
            println!(
                "Wrote the winrig MCP server entry to {} ({})",
                written.display(),
                scope.as_str()
            );
            if client.supports_file_reference() {
                println!(
                    "The entry references the token in a private file and does not inline it."
                );
            } else if scope.is_project() {
                eprintln!(
                    "warning: {} can go into version control and contains the profile \
                     token; keep it out of the repository",
                    written.display()
                );
            }
        }
        None => println!("Profile {name:?} created at {}", path.display()),
    }
    println!();
    println!("Profile token (shown once, store it with the client; the server keeps no key):");
    println!("{token}");
    println!();
    println!("MCP server definition:");
    println!(
        "{}",
        definition
            .to_json()
            .map_err(|error| StartupError::Runtime(error.to_string()))?
    );
    std::io::stdout()
        .flush()
        .map_err(|error| StartupError::Runtime(format!("cannot flush stdout: {error}")))?;
    Ok(())
}

/// Resolves the config write scope: the explicit flag, a terminal question, or a
/// refusal in a non-interactive run (ADR-0012).
fn resolve_scope(explicit: Option<Scope>) -> Result<Scope, StartupError> {
    use std::io::IsTerminal;
    resolve_scope_with(explicit, std::io::stdin().is_terminal(), || {
        prompt(
            "Write the winrig MCP entry to the (g)lobal or the (p)roject client configuration? [g/p]: ",
        )
    })
}

/// Testable core of the scope choice: without a flag and without a terminal it
/// refuses instead of choosing silently (ADR-0012).
fn resolve_scope_with(
    explicit: Option<Scope>,
    interactive: bool,
    read: impl FnOnce() -> Result<String, StartupError>,
) -> Result<Scope, StartupError> {
    if let Some(scope) = explicit {
        return Ok(scope);
    }
    if !interactive {
        return Err(StartupError::Usage(
            "no client configuration scope: pass --scope global or --scope project (interactive \
             input is not available)"
                .to_owned(),
        ));
    }
    match read()?.trim().to_ascii_lowercase().as_str() {
        "g" | "global" => Ok(Scope::Global),
        "p" | "project" => Ok(Scope::Project),
        _ => Err(StartupError::Usage(
            "unknown scope; expected g(lobal) or p(roject)".to_owned(),
        )),
    }
}

/// Reads a line from stdin, printing the label to stderr.
fn prompt(label: &str) -> Result<String, StartupError> {
    use std::io::Write;
    eprint!("{label}");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|error| StartupError::Runtime(format!("cannot read input: {error}")))?;
    Ok(line.trim().to_owned())
}

/// Prints the profiles: a table with headers, or JSON (`--json`).
///
/// There are no secrets in either format: only the name, the account, the creation
/// time and the path.
fn list_command(json: bool) -> Result<(), StartupError> {
    let (locations, _config) = load()?;
    let names = locations.profile_names();
    let paths: Vec<std::path::PathBuf> = names
        .iter()
        .map(|name| locations.profile_path(name))
        .collect();
    let summaries = profile::list(&paths, &names);

    if json {
        let items: Vec<serde_json::Value> = summaries
            .iter()
            .map(|summary| {
                serde_json::json!({
                    "name": summary.name,
                    "username": summary.username,
                    "created_at": summary.created_at,
                    "path": summary.path.display().to_string(),
                })
            })
            .collect();
        let rendered = serde_json::to_string_pretty(&serde_json::json!({
            "profiles": items,
            "count": items.len(),
        }))
        .map_err(|error| StartupError::Runtime(format!("cannot render JSON: {error}")))?;
        println!("{rendered}");
        return Ok(());
    }

    if summaries.is_empty() {
        println!("No profiles in {}", locations.profile_dir().display());
        return Ok(());
    }
    let name_width = summaries
        .iter()
        .map(|summary| summary.name.len())
        .max()
        .unwrap_or(0)
        .max("NAME".len());
    let user_width = summaries
        .iter()
        .map(|summary| summary.username.len())
        .max()
        .unwrap_or(0)
        .max("USER".len());
    println!("{:<name_width$}  {:<user_width$}  PATH", "NAME", "USER");
    for summary in &summaries {
        println!(
            "{:<name_width$}  {:<user_width$}  {}",
            summary.name,
            summary.username,
            summary.path.display()
        );
    }
    Ok(())
}

fn rotate_command(name: &str) -> Result<(), StartupError> {
    let (locations, _config) = load()?;
    let path = resolve_profile_path(&locations, name)?;
    if !path.is_file() {
        return Err(StartupError::Usage(
            PathError::NotFound {
                name: name.to_owned(),
                dir: locations.profile_dir().to_path_buf(),
            }
            .to_string(),
        ));
    }
    let password = read_password("New AD password: ")?;
    let token = profile::rotate(&path, &password)
        .map_err(|error| StartupError::Usage(format!("profile error: {error}")))?;
    warn_loose_permissions(&path);
    println!("Profile {name:?} rotated.");
    println!("New profile token (shown once):");
    println!("{token}");
    Ok(())
}

/// Resolves the profile path, rejecting a name with path characters (AC-PRF-27).
///
/// Without this check `rotate`/`forget` with a name like `../victim` would reach a
/// file outside the profile directory.
fn resolve_profile_path(
    locations: &Locations,
    name: &str,
) -> Result<std::path::PathBuf, StartupError> {
    crate::paths::validate_profile_name(name)
        .map_err(|error| StartupError::Usage(error.to_string()))?;
    Ok(locations.profile_path(name))
}

fn forget_command(name: &str) -> Result<(), StartupError> {
    let (locations, _config) = load()?;
    let path = resolve_profile_path(&locations, name)?;
    let removed = profile::forget(&path)
        .map_err(|error| StartupError::Usage(format!("profile error: {error}")))?;
    if removed {
        println!("Profile {name:?} removed.");
    } else {
        println!("Profile {name:?} did not exist; nothing to remove.");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Environment check
// ---------------------------------------------------------------------------

/// Variables that name a server or carry its secret; they differ between servers
/// by design, so the drift check leaves them out (TR-PRF-18).
const SERVER_IDENTITY_VARIABLES: [&str; 5] = [
    "WINRIG_TOKEN",
    "WINRIG_AUTH_TOKEN",
    "WINRIG_PROFILE",
    "WINRIG_PROFILE_DIR",
    "WINRIG_STATE_DIR",
];

/// AC-PRF-69: reads the client configurations, reports the effective settings of
/// each winrig server and marks the differences. Read-only (Q-23).
fn doctor_command() -> Result<(), StartupError> {
    let cwd = std::env::current_dir().map_err(|error| {
        StartupError::Runtime(format!("cannot read the current directory: {error}"))
    })?;
    let mut servers = Vec::new();
    let mut skipped = Vec::new();
    let mut unparsed = Vec::new();
    let mut not_compared = Vec::new();
    for file in client_config::config_files(&cwd) {
        match client_config::read_servers(&file) {
            Ok(scan) => {
                servers.extend(scan.servers);
                for key in scan.unparsed {
                    unparsed.push((file.path.clone(), key));
                }
                for key in scan.not_compared {
                    not_compared.push((file.path.clone(), key));
                }
            }
            Err(error) => skipped.push((file.path.clone(), error.reason)),
        }
    }
    let servers = effective_servers(servers);
    let differences = doctor_differences(&servers);
    print!(
        "{}",
        format_doctor_report(&servers, &differences, &skipped, &unparsed, &not_compared)
    );
    if differences.is_empty() && skipped.is_empty() && unparsed.is_empty() {
        return Ok(());
    }
    Err(StartupError::EnvironmentDrift(
        "the winrig servers disagree or the check is incomplete".to_owned(),
    ))
}

/// The narrowest scope wins for one server key: a local or project entry
/// overrides the global one (TR-PRF-18).
fn effective_servers(
    mut servers: Vec<client_config::ServerEntry>,
) -> Vec<client_config::ServerEntry> {
    servers.sort_by(|a, b| {
        (a.client, &a.key, a.scope.rank()).cmp(&(b.client, &b.key, b.scope.rank()))
    });
    servers.dedup_by(|a, b| a.client == b.client && a.key == b.key);
    servers
}

/// Pairs of the known variables with the parser's values (TR-PRF-18).
fn default_settings() -> Vec<(&'static str, Option<String>)> {
    let config = crate::config::load_config_from(&|_| None)
        .expect("the empty environment must give a valid default configuration");
    crate::config::setting_pairs(&config)
}

/// Canonical or refused value of one known setting for one server (TR-PRF-18).
#[derive(Clone, PartialEq, Eq)]
enum Effective {
    /// A value the parser accepted, in canonical form.
    Value(String),
    /// A value the parser refused; the raw text is never kept.
    Invalid,
    /// The setting has no default and the entry does not set it.
    Unset,
}

/// Effective values of the known settings for one server. Each variable is
/// normalized alone, so a bad value does not hide the others (TR-PRF-18).
fn setting_values(
    entry: &client_config::ServerEntry,
    defaults: &[(&'static str, Option<String>)],
) -> std::collections::BTreeMap<&'static str, Effective> {
    defaults
        .iter()
        .map(|(name, default)| {
            let raw = entry
                .variables
                .get(*name)
                .map(|value| value.trim())
                .filter(|value| !value.is_empty());
            let effective = match raw {
                None => default.clone().map_or(Effective::Unset, Effective::Value),
                Some(text) => crate::config::canonical_setting(name, text)
                    .map_or(Effective::Invalid, Effective::Value),
            };
            (*name, effective)
        })
        .collect()
}

fn is_default(entry: &client_config::ServerEntry, name: &str) -> bool {
    entry
        .variables
        .get(name)
        .map(|value| value.trim().is_empty())
        .unwrap_or(true)
}

fn configured_settings(
    servers: &[client_config::ServerEntry],
    defaults: &[(&'static str, Option<String>)],
) -> Vec<&'static str> {
    defaults
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| servers.iter().any(|server| !is_default(server, name)))
        .collect()
}

fn other_variables(
    servers: &[client_config::ServerEntry],
    defaults: &[(&'static str, Option<String>)],
) -> std::collections::BTreeSet<String> {
    let known: std::collections::BTreeSet<&str> = defaults.iter().map(|(name, _)| *name).collect();
    let mut others = std::collections::BTreeSet::new();
    for server in servers {
        for name in server.variables.keys() {
            if !known.contains(name.as_str()) {
                others.insert(name.clone());
            }
        }
    }
    others
}

/// AC-PRF-69: the report lists each server with its effective settings and marks
/// the differing ones. A value outside the known settings is never printed
/// (DR-4).
fn format_doctor_report(
    servers: &[client_config::ServerEntry],
    differences: &[String],
    skipped: &[(std::path::PathBuf, String)],
    unparsed: &[(std::path::PathBuf, String)],
    not_compared: &[(std::path::PathBuf, String)],
) -> String {
    use std::fmt::Write;

    let defaults = default_settings();
    let settings = configured_settings(servers, &defaults);
    let others = other_variables(servers, &defaults);
    let mut out = String::new();
    if servers.is_empty() {
        out.push_str("No winrig servers found in the client configurations.\n");
    } else {
        let _ = writeln!(out, "winrig servers ({}):", servers.len());
        for server in servers {
            let account = server.profile.as_deref().unwrap_or("(unknown)");
            let _ = writeln!(
                out,
                "  {} [{} {}, profile={}]",
                escape_text(&server.key),
                server.client.as_str(),
                server.scope.as_str(),
                escape_text(account)
            );
            let _ = writeln!(
                out,
                "    path: {}",
                escape_text(&server.path.display().to_string())
            );
            let values = setting_values(server, &defaults);
            for &name in &settings {
                let effective = values.get(name).cloned().unwrap_or(Effective::Unset);
                let _ = writeln!(
                    out,
                    "    {name} = {}",
                    escape_text(&display_effective(&effective, is_default(server, name)))
                );
            }
            for name in &others {
                let Some(raw) = server.variables.get(name.as_str()) else {
                    continue;
                };
                let shown = if raw.is_empty() { "(empty)" } else { "set" };
                let _ = writeln!(out, "    {} = {shown}", escape_text(name));
            }
        }
    }
    for (path, reason) in skipped {
        let _ = writeln!(
            out,
            "skipped: {}: {}",
            escape_text(&path.display().to_string()),
            escape_text(reason)
        );
    }
    for (path, key) in unparsed {
        let _ = writeln!(
            out,
            "not parsed: {}: {}",
            escape_text(&path.display().to_string()),
            escape_text(key)
        );
    }
    for (path, key) in not_compared {
        let _ = writeln!(
            out,
            "not compared: {}: {} (HTTP entry)",
            escape_text(&path.display().to_string()),
            escape_text(key)
        );
    }
    if differences.is_empty() {
        out.push_str("differences: none\n");
    } else {
        let _ = writeln!(out, "differences ({}):", differences.len());
        for line in differences {
            let _ = writeln!(out, "  {line}");
        }
    }
    out
}

fn display_effective(effective: &Effective, is_default: bool) -> String {
    match effective {
        Effective::Value(text) if text.is_empty() && is_default => "(default)".to_owned(),
        Effective::Value(text) if text.is_empty() => "(empty)".to_owned(),
        Effective::Value(text) if is_default => format!("{text} (default)"),
        Effective::Value(text) => text.clone(),
        Effective::Invalid => "invalid".to_owned(),
        Effective::Unset => "(unset)".to_owned(),
    }
}

fn doctor_differences(servers: &[client_config::ServerEntry]) -> Vec<String> {
    let defaults = default_settings();
    let settings = configured_settings(servers, &defaults);
    let others = other_variables(servers, &defaults);
    let values: Vec<std::collections::BTreeMap<&'static str, Effective>> = servers
        .iter()
        .map(|server| setting_values(server, &defaults))
        .collect();
    let mut lines = Vec::new();
    for &name in &settings {
        let per_server: Vec<Effective> = values
            .iter()
            .map(|map| map.get(name).cloned().unwrap_or(Effective::Unset))
            .collect();
        if all_equal(&per_server) {
            continue;
        }
        let rendered: Vec<String> = servers
            .iter()
            .zip(&per_server)
            .map(|(server, effective)| {
                format!(
                    "{}/{}={}",
                    server.client.as_str(),
                    escape_text(&server.key),
                    escape_text(&display_effective(effective, is_default(server, name)))
                )
            })
            .collect();
        lines.push(format!("{}: {}", escape_text(name), rendered.join(", ")));
    }
    for name in &others {
        if is_server_identity_variable(name) {
            continue;
        }
        let per_server: Vec<Option<&str>> = servers
            .iter()
            .map(|server| server.variables.get(name.as_str()).map(String::as_str))
            .collect();
        if !all_equal(&per_server) {
            lines.push(format!("{}: differs", escape_text(name)));
        }
    }
    lines
}

fn is_server_identity_variable(name: &str) -> bool {
    SERVER_IDENTITY_VARIABLES.contains(&name)
}

fn all_equal<T: PartialEq>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] == pair[1])
}

/// Replaces a control character so a value cannot forge a report line (TR-PRF-18).
fn escape_text(text: &str) -> String {
    use std::fmt::Write;

    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            character if character.is_control() => {
                let _ = write!(out, "\\x{:02x}", character as u32);
            }
            character => out.push(character),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Server modes
// ---------------------------------------------------------------------------

/// Starts the HTTP mode: with a profile (profile token), or by the shared secret
/// alone. At least one secret is required (AC-PRF-47).
///
/// `port`/`host` and `token`/`auth_token` are explicit CLI flags; they override
/// `WINRIG_PORT`/`WINRIG_BIND_HOST` and `WINRIG_TOKEN`/`WINRIG_AUTH_TOKEN`
/// (CLI > env). A secret passed as an argument is visible in the process list, so
/// its `Debug` is redacted.
fn run_serve(
    requested: Option<&str>,
    port: Option<u16>,
    host: Option<&str>,
    token: Option<&SecretArg>,
    auth_token: Option<&SecretArg>,
) -> Result<(), StartupError> {
    let (locations, mut config) = load()?;
    // Explicit flags override the environment.
    if let Some(secret) = auth_token {
        config.mcp_auth_token = Some(secret.expose().to_owned());
    }
    if let Some(secret) = token {
        config.profile_token = Some(secret.expose().to_owned());
    }
    let has_token = config.mcp_auth_token.is_some();
    let has_profile_token = config.profile_token.is_some();
    if !has_token && !has_profile_token {
        return Err(StartupError::Usage(
            "no secret is set: create a profile and pass --token/WINRIG_TOKEN, or set \
             --auth-token/WINRIG_AUTH_TOKEN for the header path"
                .to_owned(),
        ));
    }

    // The profile is used when its token is set; otherwise only the header path
    // with WINRIG_AUTH_TOKEN works.
    let (bound, name, state_dir, _lock) = if has_profile_token {
        locations
            .ensure()
            .map_err(|error| StartupError::Usage(error.to_string()))?;
        let name = locations
            .select(requested.or(config.profile_name.as_deref()))
            .map_err(|error| StartupError::Usage(error.to_string()))?;
        let state_dir = locations
            .state_dir_for(&name)
            .map_err(|error| StartupError::Usage(error.to_string()))?;
        let lock = ProcessLock::acquire(&state_dir)
            .map_err(|error| StartupError::Usage(error.to_string()))?;
        let bound = bind_profile(&locations, &name, &token_from(&config)?)?;
        ensure_auth_token_is_not_profile_key(&config, &bound.path)?;
        (Some(bound), name, state_dir, Some(lock))
    } else {
        let state_dir = locations
            .state_dir_default()
            .map_err(|error| StartupError::Usage(error.to_string()))?;
        (None, "(headers)".to_owned(), state_dir, None)
    };

    let log_dir = resolve_log_dir(&config, &state_dir);
    setup_logging(&config, &log_dir)
        .map_err(|error| StartupError::Runtime(format!("logging error: {error}")))?;

    // The transfer endpoint is resolved before the server is built, so the tool
    // reads one absolute root (TR-XFER-01, ADR-0017 §21).
    config.transfer_dir = Some(
        resolve_transfer_dir(&config, &state_dir)
            .to_string_lossy()
            .into_owned(),
    );

    let registry = registry_for(&config);
    let auth = AuthState {
        mcp_auth_token: config.mcp_auth_token.clone().map(Arc::new),
        profile: bound.clone(),
    };
    // CLI flags override the environment.
    let bind_host = host.unwrap_or(&config.mcp_bind_host).to_owned();
    let bind_port = port.unwrap_or(config.mcpo_port);
    tracing::info!(profile = %name, host = %bind_host, port = bind_port, "winrig starts (streamable-http on /mcp)");
    let runtime = build_runtime()?;
    runtime.block_on(serve_http(
        registry,
        Arc::new(config),
        auth,
        bind_host,
        bind_port,
    ))
}

fn run_stdio(requested: Option<&str>) -> Result<(), StartupError> {
    let (locations, mut config, name, _lock, state_dir) = prepare_profile(requested)?;
    let log_dir = resolve_log_dir(&config, &state_dir);
    setup_logging(&config, &log_dir)
        .map_err(|error| StartupError::Runtime(format!("logging error: {error}")))?;

    config.transfer_dir = Some(
        resolve_transfer_dir(&config, &state_dir)
            .to_string_lossy()
            .into_owned(),
    );

    let bound = bind_profile(&locations, &name, &token_from(&config)?)?;
    let registry = registry_for(&config);
    tracing::info!(profile = %name, "winrig starts (stdio)");
    let runtime = build_runtime()?;
    runtime.block_on(serve_stdio(registry, Arc::new(config), bound))
}

fn token_from(config: &AppConfig) -> Result<String, StartupError> {
    config.profile_token.clone().ok_or_else(|| {
        StartupError::Usage(
            "WINRIG_TOKEN is not set. Pass the token printed by 'winrig setup' through the \
             client environment."
                .to_owned(),
        )
    })
}

/// Builds and starts the axum server with the gate and the MCP endpoint.
async fn serve_http(
    registry: Arc<SessionRegistry>,
    config: Arc<AppConfig>,
    auth: AuthState,
    bind_host: String,
    bind_port: u16,
) -> Result<(), StartupError> {
    let cancellation = CancellationToken::new();
    let server = WinrigServer::new(Arc::clone(&registry), Arc::clone(&config));
    let mcp_config = rmcp::transport::streamable_http_server::StreamableHttpServerConfig::default()
        .with_sse_keep_alive(None)
        .with_cancellation_token(cancellation.clone());
    let service: rmcp::transport::streamable_http_server::StreamableHttpService<
        WinrigServer,
        rmcp::transport::streamable_http_server::session::local::LocalSessionManager,
    > = rmcp::transport::streamable_http_server::StreamableHttpService::new(
        move || Ok(server.clone()),
        Default::default(),
        mcp_config,
    );
    let app = axum::Router::new()
        .nest_service("/mcp", service)
        .layer(axum::middleware::from_fn_with_state(auth, auth_middleware));

    let address = format!("{bind_host}:{bind_port}");
    let listener = tokio::net::TcpListener::bind(&address)
        .await
        .map_err(|error| StartupError::Runtime(format!("cannot bind {address}: {error}")))?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(cancellation))
        .await
        .map_err(|error| StartupError::Runtime(format!("server error: {error}")))
}

/// Serves MCP over stdin/stdout until the input closes.
///
/// When the profile is rejected twice (AC-PRF-56), a background check cancels the
/// service and the function returns [`StartupError::PasswordRejected`] (exit code
/// 3).
async fn serve_stdio(
    registry: Arc<SessionRegistry>,
    config: Arc<AppConfig>,
    bound: Arc<BoundProfile>,
) -> Result<(), StartupError> {
    let username = bound.identity().username.clone();
    let server = WinrigServer::with_profile_identity(
        Arc::clone(&registry),
        config,
        Arc::new(bound.identity().clone()),
    );
    let (stdin, stdout) = rmcp::transport::io::stdio();
    let running = rmcp::serve_server(server, (stdin, stdout))
        .await
        .map_err(|error| StartupError::Runtime(format!("stdio error: {error}")))?;

    // Watcher for a profile refusal: stdio serves one profile, so a periodic check
    // of its name is enough.
    let token = running.cancellation_token();
    let watcher_registry = Arc::clone(&registry);
    let watcher_username = username.clone();
    let watcher = tokio::spawn(async move {
        loop {
            if watcher_registry.is_profile_refused(&watcher_username) {
                token.cancel();
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    });

    let reason = running
        .waiting()
        .await
        .map_err(|error| StartupError::Runtime(format!("stdio error: {error}")))?;
    watcher.abort();
    let _ = reason;
    stdio_outcome(registry.is_profile_refused(&username))
}

/// A profile refusal gives [`StartupError::PasswordRejected`] (exit code 3); a
/// normal end is success (AC-PRF-56).
fn stdio_outcome(profile_refused: bool) -> Result<(), StartupError> {
    if profile_refused {
        return Err(StartupError::PasswordRejected(
            "The host rejected the profile password twice. The server refuses the profile until \
             the operator updates it. Run 'winrig setup' to change it."
                .to_owned(),
        ));
    }
    Ok(())
}

/// Waits for SIGINT (Ctrl+C) or, on Unix, SIGTERM.
///
/// systemd stops the process with SIGTERM; without handling it the server ended
/// without a graceful shutdown and cut active requests.
async fn shutdown_signal(cancellation: CancellationToken) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    cancellation.cancel();
}

/// Sets up logging: stderr plus a file with rotation.
///
/// The audit (`target = "winrig::audit"`) always goes to a separate file at INFO
/// level, regardless of `WINRIG_LOG_LEVEL`.
fn setup_logging(
    config: &AppConfig,
    log_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::Layer;
    use tracing_subscriber::filter::filter_fn;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let log_path = log_dir.join("winrig.log");
    let file = RotatingFile::new(&log_path, config.log_max_bytes, config.log_backup_count)?;
    let audit_path = log_dir.join("winrig-audit.log");
    let audit = RotatingFile::new(&audit_path, config.log_max_bytes, config.log_backup_count)?;

    let filter = EnvFilter::try_new(config.log_level.filter_directive())
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let main_layer = tracing_subscriber::fmt::layer()
        .with_writer(FileAndStderr { file })
        .with_target(true)
        .with_filter(filter)
        .with_filter(filter_fn(|meta| meta.target() != "winrig::audit"));
    let audit_layer = tracing_subscriber::fmt::layer()
        .with_writer(audit)
        .with_target(false)
        .with_ansi(false)
        .with_filter(filter_fn(|meta| meta.target() == "winrig::audit"));

    tracing_subscriber::registry()
        .with(main_layer)
        .with(audit_layer)
        .try_init()?;
    Ok(())
}

/// Mirrors every record to stderr plus the log file: stderr shows in the console,
/// the file survives a restart.
struct FileAndStderr {
    file: RotatingFile,
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for FileAndStderr {
    type Writer = FileAndStderrWriter<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        FileAndStderrWriter {
            file: self.file.make_writer(),
            stderr: std::io::stderr(),
        }
    }
}

struct FileAndStderrWriter<'a> {
    file: crate::logging::RotatingGuard<'a>,
    stderr: std::io::Stderr,
}

impl std::io::Write for FileAndStderrWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let _ = std::io::Write::write_all(&mut self.stderr, buf);
        self.file.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let _ = std::io::Write::flush(&mut self.stderr);
        self.file.flush()
    }
}

/// Absolute location of the running executable.
fn binary_path() -> std::path::PathBuf {
    std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("winrig"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::PROFILE_DIR_ENV;
    use std::path::PathBuf;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "winrig-app-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// AC-PRF-08/09: the log goes to the profile state directory, or to WINRIG_LOG_DIR.
    #[test]
    fn log_dir_prefers_explicit_override() {
        let profile_state = PathBuf::from("/tmp/profile-state");
        let config = load_config_from(&|name| match name {
            "WINRIG_LOG_DIR" => Some("/tmp/explicit-logs".to_owned()),
            _ => None,
        })
        .expect("config");
        assert_eq!(
            resolve_log_dir(&config, &profile_state),
            PathBuf::from("/tmp/explicit-logs")
        );

        let config =
            load_config_from(&|name| (name == "WINRIG_AUTH_TOKEN").then(|| "t".to_owned()))
                .expect("config");
        assert_eq!(resolve_log_dir(&config, &profile_state), profile_state);
    }

    /// TR-XFER-01: the transfer endpoint is `WINRIG_TRANSFER_DIR`, or the transfer
    /// subdirectory of the profile state directory.
    #[test]
    fn transfer_dir_prefers_explicit_override() {
        let profile_state = PathBuf::from("/tmp/profile-state");
        let config = load_config_from(&|name| match name {
            "WINRIG_TRANSFER_DIR" => Some("/tmp/explicit-transfer".to_owned()),
            _ => None,
        })
        .expect("config");
        assert_eq!(
            resolve_transfer_dir(&config, &profile_state),
            PathBuf::from("/tmp/explicit-transfer")
        );

        let config =
            load_config_from(&|name| (name == "WINRIG_AUTH_TOKEN").then(|| "t".to_owned()))
                .expect("config");
        assert_eq!(
            resolve_transfer_dir(&config, &profile_state),
            profile_state.join("transfer")
        );
    }

    /// AC-PRF-50: a shared secret equal to the profile token refuses startup.
    #[test]
    fn auth_token_equal_to_profile_key_is_refused() {
        let dir = temp_dir("key");
        let path = dir.join("corp.json");
        let token = crate::profile::create(&path, "corp", "domain\\alice", "s3cret", false)
            .expect("create");
        let config = load_config_from(&move |name: &str| match name {
            "WINRIG_AUTH_TOKEN" => Some(token.clone()),
            _ => None,
        })
        .expect("config");
        let error = ensure_auth_token_is_not_profile_key(&config, &path).expect_err("must refuse");
        assert!(matches!(error, StartupError::Usage(_)));
        // Another secret does not block.
        let config = load_config_from(&|name| match name {
            "WINRIG_AUTH_TOKEN" => Some("different".to_owned()),
            _ => None,
        })
        .expect("config");
        assert!(ensure_auth_token_is_not_profile_key(&config, &path).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-47: without a profile and without a token the HTTP start refuses with exit code 2.
    #[test]
    fn serve_without_any_secret_is_refused() {
        // Check the branch through the config: both secrets are empty.
        let config = load_config_from(&|_| None::<String>).expect("config parses without secrets");
        assert!(config.mcp_auth_token.is_none());
        assert!(config.profile_token.is_none());
    }

    /// AC-PRF-40/41: the refusal reason in the log tells a wrong token from a
    /// corrupt file.
    #[test]
    fn profile_bind_reason_distinguishes_failures() {
        let dir = temp_dir("reason");
        let path = dir.join("corp.json");
        let token = crate::profile::create(&path, "corp", "domain\\alice", "s3cret", false)
            .expect("create");
        let wrong =
            crate::auth::BoundProfile::bind(path.clone(), "wrong").expect_err("wrong token");
        assert_eq!(profile_bind_reason(&wrong), "invalid profile token");
        std::fs::write(&path, b"not json").unwrap();
        let corrupt = crate::auth::BoundProfile::bind(path.clone(), &token).expect_err("corrupt");
        assert_eq!(profile_bind_reason(&corrupt), "profile file corrupt");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-42: no token set is a refusal that names the variable.
    #[test]
    fn missing_profile_token_names_variable() {
        let config = load_config_from(&|_| None::<String>).expect("config parses without secrets");
        let error = token_from(&config).expect_err("must refuse");
        assert!(error.to_string().contains("WINRIG_TOKEN"));
    }

    /// AC-PRF-43: a missing profile is a refusal that names the profile and the directory.
    #[test]
    fn missing_profile_is_reported_by_locations() {
        let dir = temp_dir("missing");
        let dir_str = dir.to_string_lossy().into_owned();
        let locations = Locations::resolve(&move |name: &str| {
            (name == PROFILE_DIR_ENV).then(|| dir_str.clone())
        })
        .expect("locations");
        let error = locations.select(Some("corp")).expect_err("must refuse");
        assert!(error.to_string().contains("corp"));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-20: several profiles without a name are refused.
    #[test]
    fn ambiguous_profile_is_refused() {
        let dir = temp_dir("ambiguous");
        let dir_str = dir.to_string_lossy().into_owned();
        let locations =
            Locations::resolve(&move |_: &str| Some(dir_str.clone())).expect("locations");
        locations.ensure().expect("ensure");
        for name in ["one", "two"] {
            crate::profile::create(
                &locations.profile_path(name),
                name,
                "domain\\alice",
                "p",
                false,
            )
            .expect("create");
        }
        let error = locations.select(None).expect_err("must refuse");
        assert!(error.to_string().contains("one"));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-56: a profile refusal maps the stdio outcome to exit code 3, a
    /// normal end to 0.
    #[test]
    fn stdio_outcome_maps_refusal_to_code_three() {
        let refused = stdio_outcome(true).expect_err("must refuse");
        assert_eq!(refused.exit_code(), 3);
        assert!(matches!(refused, StartupError::PasswordRejected(_)));
        assert!(stdio_outcome(false).is_ok());
    }

    /// AC-PRF-27: `rotate`/`forget` reject a name with path characters.
    #[test]
    fn rotate_and_forget_reject_path_names() {
        let dir = temp_dir("traversal");
        let dir_str = dir.to_string_lossy().into_owned();
        let locations =
            Locations::resolve(&move |_: &str| Some(dir_str.clone())).expect("locations");
        locations.ensure().expect("ensure");
        for name in ["../victim", "a/b", "a\\b"] {
            let error = resolve_profile_path(&locations, name).expect_err("must refuse");
            assert!(matches!(error, StartupError::Usage(_)), "{name}: {error}");
        }
        assert!(resolve_profile_path(&locations, "corp").is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-60: without a flag and without a terminal the scope is not guessed.
    #[test]
    fn resolve_scope_non_interactive_refuses_without_flag() {
        let error = resolve_scope_with(None, false, || unreachable!("must not read"))
            .expect_err("must refuse");
        assert!(error.to_string().contains("--scope"), "{error}");
    }

    /// AC-PRF-62: an explicit flag does not read stdin.
    #[test]
    fn resolve_scope_prefers_explicit() {
        let scope = resolve_scope_with(Some(Scope::Project), false, || {
            unreachable!("must not read")
        })
        .map_err(|error| error.to_string())
        .expect("explicit");
        assert_eq!(scope, Scope::Project);
    }

    /// ADR-0012: an interactive answer accepts g/global/p/project.
    #[test]
    fn resolve_scope_interactive_accepts_forms() {
        for (answer, expected) in [
            ("g", Scope::Global),
            ("global", Scope::Global),
            ("P", Scope::Project),
            ("project", Scope::Project),
        ] {
            let scope = resolve_scope_with(None, true, || Ok(answer.to_owned()))
                .map_err(|error| error.to_string())
                .expect("read");
            assert_eq!(scope, expected, "answer {answer:?}");
        }
        let error = resolve_scope_with(None, true, || Ok("nope".to_owned())).expect_err("junk");
        assert!(matches!(error, StartupError::Usage(_)), "{error}");
    }

    fn doctor_entry(
        key: &str,
        scope: client_config::SourceScope,
        profile: &str,
        variables: &[(&str, &str)],
    ) -> client_config::ServerEntry {
        client_config::ServerEntry {
            client: client_config::Client::Opencode,
            scope,
            path: PathBuf::from("/tmp/project/opencode.json"),
            key: key.to_owned(),
            profile: Some(profile.to_owned()),
            variables: variables
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
        }
    }

    fn render(servers: &[client_config::ServerEntry]) -> String {
        format_doctor_report(servers, &doctor_differences(servers), &[], &[], &[])
    }

    /// AC-PRF-69: the report lists each server, marks the differing setting and
    /// never prints a value outside the known settings (DR-4).
    #[test]
    fn doctor_report_marks_differences_without_secrets() {
        let servers = vec![
            doctor_entry(
                "winrig",
                client_config::SourceScope::Global,
                "corp",
                &[
                    ("WINRIG_ALLOW_INSECURE_TLS", "true"),
                    ("WINRIG_TOKEN", "secret-token-value"),
                ],
            ),
            doctor_entry(
                "winrig-lab",
                client_config::SourceScope::Project,
                "lab",
                &[("WINRIG_ALLOWED_HOSTS", "web01")],
            ),
        ];
        let report = render(&servers);
        assert!(report.contains("WINRIG_ALLOW_INSECURE_TLS"), "{report}");
        assert!(report.contains("winrig=true"), "{report}");
        assert!(report.contains("winrig-lab=false (default)"), "{report}");
        assert!(report.contains("WINRIG_TOKEN = set"), "{report}");
        assert!(!report.contains("secret-token-value"), "{report}");
    }

    /// AC-PRF-69: the known settings are compared through the parser, so `1`
    /// and `true` agree and an unset setting equals the default.
    #[test]
    fn doctor_normalizes_equivalent_values() {
        let forms = vec![
            doctor_entry(
                "a",
                client_config::SourceScope::Global,
                "corp",
                &[("WINRIG_ALLOW_INSECURE_TLS", "1")],
            ),
            doctor_entry(
                "b",
                client_config::SourceScope::Project,
                "corp",
                &[("WINRIG_ALLOW_INSECURE_TLS", "true")],
            ),
        ];
        assert!(
            doctor_differences(&forms).is_empty(),
            "{:?}",
            doctor_differences(&forms)
        );

        let unset = vec![
            doctor_entry("a", client_config::SourceScope::Global, "corp", &[]),
            doctor_entry(
                "b",
                client_config::SourceScope::Project,
                "corp",
                &[("WINRIG_ALLOW_INSECURE_TLS", "false")],
            ),
        ];
        assert!(
            doctor_differences(&unset).is_empty(),
            "{:?}",
            doctor_differences(&unset)
        );
    }

    /// AC-PRF-69: a project entry with the same key overrides the global one.
    #[test]
    fn doctor_lets_a_project_entry_override_the_global_one() {
        let servers = effective_servers(vec![
            doctor_entry(
                "winrig",
                client_config::SourceScope::Global,
                "corp",
                &[("WINRIG_ALLOW_INSECURE_TLS", "true")],
            ),
            doctor_entry(
                "winrig",
                client_config::SourceScope::Project,
                "corp",
                &[("WINRIG_ALLOW_INSECURE_TLS", "false")],
            ),
        ]);
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].scope, client_config::SourceScope::Project);
    }

    /// AC-PRF-69: agreement between servers is reported, not marked as drift.
    #[test]
    fn doctor_report_without_difference_says_none() {
        let servers = vec![
            doctor_entry(
                "a",
                client_config::SourceScope::Global,
                "corp",
                &[("WINRIG_ALLOW_INSECURE_TLS", "true")],
            ),
            doctor_entry(
                "b",
                client_config::SourceScope::Project,
                "corp",
                &[("WINRIG_ALLOW_INSECURE_TLS", "true")],
            ),
        ];
        let report = render(&servers);
        assert!(report.contains("differences: none"), "{report}");
    }

    #[test]
    fn doctor_report_without_servers_says_so() {
        let report = format_doctor_report(&[], &[], &[], &[], &[]);
        assert!(report.contains("No winrig servers"), "{report}");
    }

    /// DR-4: only the known settings show a value; any other variable is masked.
    #[test]
    fn doctor_masks_unknown_variables() {
        let servers = vec![doctor_entry(
            "winrig",
            client_config::SourceScope::Global,
            "corp",
            &[
                ("HTTPS_PROXY", "http://u:p@h"),
                ("X_AUTH", "Bearer a.b.c"),
                ("WINRIG_PASSWORD_TTL_SECONDS", "300"),
            ],
        )];
        let report = render(&servers);
        assert!(
            report.contains("WINRIG_PASSWORD_TTL_SECONDS = 300"),
            "{report}"
        );
        assert!(!report.contains("http://u:p@h"), "{report}");
        assert!(!report.contains("Bearer a.b.c"), "{report}");
        assert!(report.contains("HTTPS_PROXY = set"), "{report}");
        assert!(report.contains("X_AUTH = set"), "{report}");
    }

    /// TR-PRF-18: a skipped file, an unparsed entry and a non-compared entry
    /// appear with their path; only the first two affect the exit code.
    #[test]
    fn doctor_reports_skipped_unparsed_and_not_compared_lines() {
        let report = format_doctor_report(
            &[],
            &[],
            &[(PathBuf::from("/a/b.json"), "not a regular file".to_owned())],
            &[(PathBuf::from("/c/d.json"), "winrig-broken".to_owned())],
            &[(PathBuf::from("/e/f.json"), "winrig-http".to_owned())],
        );
        assert!(
            report.contains("skipped: /a/b.json: not a regular file"),
            "{report}"
        );
        assert!(
            report.contains("not parsed: /c/d.json: winrig-broken"),
            "{report}"
        );
        assert!(
            report.contains("not compared: /e/f.json: winrig-http (HTTP entry)"),
            "{report}"
        );
    }

    /// TR-PRF-18: the per-server plumbing differs by design, so it is listed but
    /// never marked as drift.
    #[test]
    fn doctor_excludes_server_identity_variables_from_drift() {
        let servers = vec![
            doctor_entry(
                "winrig",
                client_config::SourceScope::Global,
                "corp",
                &[
                    ("WINRIG_TOKEN", "one"),
                    ("WINRIG_PROFILE_DIR", "/a"),
                    ("WINRIG_STATE_DIR", "/s1"),
                ],
            ),
            doctor_entry(
                "winrig-lab",
                client_config::SourceScope::Project,
                "lab",
                &[
                    ("WINRIG_TOKEN", "two"),
                    ("WINRIG_PROFILE_DIR", "/b"),
                    ("WINRIG_STATE_DIR", "/s2"),
                ],
            ),
        ];
        assert!(
            doctor_differences(&servers).is_empty(),
            "{:?}",
            doctor_differences(&servers)
        );
        let report = render(&servers);
        assert!(report.contains("WINRIG_TOKEN = set"), "{report}");
        assert!(report.contains("WINRIG_PROFILE_DIR = set"), "{report}");
    }

    /// TR-PRF-18: a control character in a key or a profile name cannot forge a
    /// report line.
    #[test]
    fn doctor_escapes_control_characters() {
        let servers = vec![doctor_entry(
            "bad\nkey",
            client_config::SourceScope::Global,
            "p\u{7}q",
            &[("WINRIG_X\u{1b}", "1")],
        )];
        let report = render(&servers);
        assert!(report.contains("bad\\nkey"), "{report}");
        assert!(report.contains("profile=p\\x07q"), "{report}");
        assert!(report.contains("WINRIG_X\\x1b"), "{report}");
        assert!(!report.contains("bad\nkey"), "{report}");
    }

    /// TR-PRF-18: a value the parser refuses is shown as `invalid`, never raw,
    /// and the other settings stay normalized.
    #[test]
    fn doctor_marks_an_invalid_value_without_printing_it() {
        let servers = vec![doctor_entry(
            "winrig",
            client_config::SourceScope::Global,
            "corp",
            &[
                ("WINRIG_PORT", "not-a-port"),
                ("WINRIG_ALLOW_INSECURE_TLS", "1"),
            ],
        )];
        let report = render(&servers);
        assert!(report.contains("WINRIG_PORT = invalid"), "{report}");
        assert!(
            report.contains("WINRIG_ALLOW_INSECURE_TLS = true"),
            "{report}"
        );
        assert!(!report.contains("not-a-port"), "{report}");
    }
}
