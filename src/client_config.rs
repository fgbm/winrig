//! Writes the MCP server definition into client configuration files (ADR-0009,
//! ADR-0012).
//!
//! `winrig setup --write-config <client>` adds a `winrig` entry and leaves the
//! other entries of the file alone. `--scope` sets the write level (ADR-0012):
//! `global` is the user config of the client, `project` is a config in the root
//! of the current project. For clients that can load a file by reference
//! (`{file:...}` in opencode), the token goes into a separate `0600` file; for
//! the others the entry holds the token as a value and the config keeps the
//! client's own permissions.
//!
//! The formats follow the client documentation: opencode uses the `mcp` key with
//! `{type, url|command, headers|environment}` entries; Claude Code uses
//! `mcpServers` in `~/.claude.json` (global) or `.mcp.json` (project); Codex uses
//! `[mcp_servers.<name>]` in `~/.codex/config.toml` or `.codex/config.toml`;
//! Cursor uses `mcpServers` in `~/.cursor/mcp.json` or `.cursor/mcp.json`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use crate::paths::PathError;
use crate::profile::ProfileError;

/// Configuration format this tool can write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Client {
    /// opencode (`~/.config/opencode/opencode.json`).
    Opencode,
    /// Claude Code (`~/.claude.json`).
    ClaudeCode,
    /// Codex (`~/.codex/config.toml`).
    Codex,
    /// Cursor (`~/.cursor/mcp.json`).
    Cursor,
}

/// Where the client config is written (ADR-0012).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The user config of the client, in effect in every project.
    Global,
    /// Config in the root of the current project.
    Project,
}

impl Scope {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Project => "project",
        }
    }

    /// True for the project scope.
    #[must_use]
    pub fn is_project(self) -> bool {
        matches!(self, Self::Project)
    }
}

impl Client {
    /// Parses a client name from the `--write-config` flag.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "opencode" | "open-code" | "open_code" => Some(Self::Opencode),
            "claude" | "claude-code" | "claude_code" => Some(Self::ClaudeCode),
            "codex" => Some(Self::Codex),
            "cursor" => Some(Self::Cursor),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Opencode => "opencode",
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::Cursor => "cursor",
        }
    }

    /// Location of the client's global config under the home directory.
    #[must_use]
    pub fn global_config_path(self) -> Option<PathBuf> {
        let home = std::env::var_os("HOME").map(PathBuf::from)?;
        Some(match self {
            Self::Opencode => std::env::var_os("XDG_CONFIG_HOME")
                .map_or_else(|| home.join(".config"), PathBuf::from)
                .join("opencode")
                .join("opencode.json"),
            Self::ClaudeCode => home.join(".claude.json"),
            Self::Codex => home.join(".codex").join("config.toml"),
            Self::Cursor => home.join(".cursor").join("mcp.json"),
        })
    }

    /// The client's project config location in the project root (ADR-0012).
    #[must_use]
    pub fn project_config_path(self, root: &Path) -> PathBuf {
        match self {
            Self::Opencode => root.join("opencode.json"),
            Self::ClaudeCode => root.join(".mcp.json"),
            Self::Codex => root.join(".codex").join("config.toml"),
            Self::Cursor => root.join(".cursor").join("mcp.json"),
        }
    }

    /// True when the client can load a file by reference.
    #[must_use]
    pub fn supports_file_reference(self) -> bool {
        matches!(self, Self::Opencode)
    }
}

/// Failure to write a client configuration file.
#[derive(Debug)]
pub enum ClientConfigError {
    /// Unknown client name.
    UnknownClient { name: String },
    /// Home directory unavailable.
    NoHome,
    /// No state directory for the opencode token at the project scope.
    NoStateDir,
    /// Existing file that cannot be parsed.
    Unreadable { path: PathBuf, reason: String },
    /// Input or output error.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl std::fmt::Display for ClientConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownClient { name } => write!(
                f,
                "unknown client {name:?}; expected one of opencode, claude-code, codex, cursor"
            ),
            Self::NoHome => write!(f, "cannot determine the home directory"),
            Self::NoStateDir => write!(
                f,
                "cannot write the winrig token: WINRIG_STATE_DIR is not set for the project scope"
            ),
            Self::Unreadable { path, reason } => {
                write!(f, "cannot parse {}: {reason}", path.display())
            }
            Self::Io { path, source } => write!(f, "cannot write {}: {source}", path.display()),
        }
    }
}

impl std::error::Error for ClientConfigError {}

/// What this tool prints and writes into a client config.
#[derive(Debug, Clone)]
pub struct ServerDefinition {
    /// Launch line: absolute path to the binary, then `stdio`.
    pub command: String,
    pub profile: String,
    pub token: String,
    /// Absolute profile directory; passed to the client so it finds the profile
    /// even when the directory differs from the default (ADR-0009).
    pub profile_dir: Option<String>,
    /// The server adds the profile name to it, exactly once, and the client
    /// receives the root for the same reason as the directory: the definition
    /// carries the root, otherwise `WINRIG_STATE_DIR` and the real state
    /// directory drift apart by one level (TR-PRF-15).
    pub state_root: Option<String>,
    /// Explicit key for the entry (`--server-name`). Without it the key comes
    /// from an existing entry for the same profile, otherwise
    /// [`DEFAULT_SERVER_NAME`].
    pub server_name: Option<String>,
    /// Value of `WINRIG_ALLOWED_HOSTS` (`--allowed-hosts`). `None` means the
    /// variable is absent from the entry and the server allows loopback only
    /// (TR-PRF-17).
    pub allowed_hosts: Option<String>,
}

/// Entry key used when no other key is given.
pub const DEFAULT_SERVER_NAME: &str = "winrig";

impl ServerDefinition {
    /// Entry name that ignores the existing config (printing the definition).
    fn plain_key(&self) -> String {
        self.server_name
            .clone()
            .unwrap_or_else(|| DEFAULT_SERVER_NAME.to_owned())
    }

    /// The name the new entry takes among the entries of an existing config (TR-PRF-14).
    ///
    /// Priority: an explicit `--server-name`; the key of an entry already
    /// declared for the same profile; [`DEFAULT_SERVER_NAME`]. The middle step
    /// is required: a second entry for one profile starts a second process, that
    /// process hits the profile lock and exits with code 2, and the client shows
    /// `Connection closed`.
    fn key_in(
        &self,
        servers: &Map<String, Value>,
        profile_of: fn(&Value) -> Option<&str>,
    ) -> String {
        if let Some(name) = &self.server_name {
            return name.clone();
        }
        servers
            .iter()
            .find(|(_, entry)| profile_of(entry) == Some(self.profile.as_str()))
            .map_or_else(|| DEFAULT_SERVER_NAME.to_owned(), |(key, _)| key.clone())
    }

    /// The variable and value pairs that launch the server.
    fn environment(&self) -> Vec<(&'static str, String)> {
        let mut env = vec![("WINRIG_TOKEN", self.token.clone())];
        if let Some(dir) = &self.profile_dir {
            env.push(("WINRIG_PROFILE_DIR", dir.clone()));
        }
        if let Some(dir) = &self.state_root {
            env.push(("WINRIG_STATE_DIR", dir.clone()));
        }
        if let Some(hosts) = &self.allowed_hosts {
            env.push(("WINRIG_ALLOWED_HOSTS", hosts.clone()));
        }
        env
    }

    fn environment_json(&self) -> serde_json::Map<String, Value> {
        let mut map = serde_json::Map::new();
        for (key, value) in self.environment() {
            map.insert(key.to_owned(), Value::String(value));
        }
        map
    }

    /// Prints the JSON server definition.
    ///
    /// # Errors
    ///
    /// A serialization error (unreachable for valid values).
    pub fn to_json(&self) -> Result<String, ClientConfigError> {
        let value = json!({
            "mcpServers": {
                self.plain_key(): {
                    "type": "stdio",
                    "command": self.command,
                    "args": ["stdio", "--profile", self.profile],
                    "env": Value::Object(self.environment_json())
                }
            }
        });
        serde_json::to_string_pretty(&value).map_err(|error| ClientConfigError::Unreadable {
            path: PathBuf::new(),
            reason: error.to_string(),
        })
    }

    /// Writes the token into a separate `0600` file next to the client config.
    ///
    /// An existing directory is left untouched: it may belong to another tool.
    ///
    /// # Errors
    ///
    /// [`ClientConfigError::Io`] when the write fails.
    pub fn write_token_file(&self, dir: &Path) -> Result<PathBuf, ClientConfigError> {
        crate::private_fs::ensure_private_dir(dir).map_err(|source| ClientConfigError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = dir.join("winrig-token");
        let body = format!("{}\n", self.token);
        crate::private_fs::open_private_truncate(&path)
            .and_then(|mut file| std::io::Write::write_all(&mut file, body.as_bytes()))
            .map_err(|source| ClientConfigError::Io {
                path: path.clone(),
                source,
            })?;
        Ok(path)
    }
}

/// The project root: the nearest ancestor of `start` with `.git`, otherwise `start`.
///
/// `.git` can be a repository directory or a worktree file; both cases mean the
/// root. This way a start from a subdirectory of a monorepo lands in the root,
/// not in the current directory (ADR-0012).
#[must_use]
pub fn find_project_root(start: &Path) -> PathBuf {
    start
        .ancestors()
        .find(|dir| dir.join(".git").exists())
        .map_or_else(|| start.to_path_buf(), Path::to_path_buf)
}

/// Writes the server entry into the client config and leaves other entries alone.
///
/// # Errors
///
/// [`ClientConfigError`] when an existing file or entry cannot be parsed.
pub fn write_client_config(
    client: Client,
    scope: Scope,
    definition: &ServerDefinition,
) -> Result<PathBuf, ClientConfigError> {
    let path = match scope {
        Scope::Global => client
            .global_config_path()
            .ok_or(ClientConfigError::NoHome)?,
        Scope::Project => {
            let cwd = std::env::current_dir().map_err(|source| ClientConfigError::Io {
                path: PathBuf::from("."),
                source,
            })?;
            client.project_config_path(&find_project_root(&cwd))
        }
    };
    write_at(client, &path, scope, definition)?;
    Ok(path)
}

fn create_parent(path: &Path) -> Result<(), ClientConfigError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| ClientConfigError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

fn write_at(
    client: Client,
    path: &Path,
    scope: Scope,
    definition: &ServerDefinition,
) -> Result<(), ClientConfigError> {
    create_parent(path)?;
    match client {
        Client::Opencode => write_opencode(path, scope, definition),
        Client::ClaudeCode | Client::Cursor => write_mcp_servers_json(path, definition),
        Client::Codex => write_codex(path, definition),
    }
}

fn read_object(path: &Path) -> Result<Map<String, Value>, ClientConfigError> {
    match std::fs::read_to_string(path) {
        Ok(raw) if !raw.trim().is_empty() => {
            let value: Value =
                serde_json::from_str(&raw).map_err(|error| ClientConfigError::Unreadable {
                    path: path.to_path_buf(),
                    reason: error.to_string(),
                })?;
            value
                .as_object()
                .cloned()
                .ok_or_else(|| ClientConfigError::Unreadable {
                    path: path.to_path_buf(),
                    reason: "the top level is not a JSON object".to_owned(),
                })
        }
        Ok(_) | Err(_) if !path.exists() => Ok(Map::new()),
        Ok(_) => Ok(Map::new()),
        Err(source) => Err(ClientConfigError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn entry_object(map: &Map<String, Value>, key: &str) -> Map<String, Value> {
    map.get(key)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

/// The command is an array and the profile follows the flag.
fn opencode_profile(entry: &Value) -> Option<&str> {
    profile_after_flag(entry.get("command")?.as_array()?)
}

/// The profile of an entry with the `mcpServers` schema: the profile sits in `args`.
fn mcp_servers_profile(entry: &Value) -> Option<&str> {
    profile_after_flag(entry.get("args")?.as_array()?)
}

fn profile_after_flag(items: &[Value]) -> Option<&str> {
    let flag = items
        .iter()
        .position(|item| item.as_str() == Some("--profile"))?;
    items.get(flag + 1)?.as_str()
}

fn write_opencode(
    path: &Path,
    scope: Scope,
    definition: &ServerDefinition,
) -> Result<(), ClientConfigError> {
    let mut root = read_object(path)?;
    let mut mcp = entry_object(&root, "mcp");
    // At the project scope the token goes into the private state directory of
    // the profile, so the secret does not land in the repository tree (ADR-0012).
    let token_dir = match scope {
        Scope::Global => path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf(),
        // The same path the server builds from `WINRIG_STATE_DIR`: the root plus
        // the profile name, once (TR-PRF-15).
        Scope::Project => PathBuf::from(
            definition
                .state_root
                .as_deref()
                .ok_or(ClientConfigError::NoStateDir)?,
        )
        .join(&definition.profile),
    };
    let token_path = definition.write_token_file(&token_dir)?;
    let mut environment = serde_json::Map::new();
    environment.insert(
        "WINRIG_TOKEN".to_owned(),
        Value::String(format!("{{file:{}}}", token_path.display())),
    );
    if let Some(dir) = &definition.profile_dir {
        environment.insert("WINRIG_PROFILE_DIR".to_owned(), Value::String(dir.clone()));
    }
    if let Some(dir) = &definition.state_root {
        environment.insert("WINRIG_STATE_DIR".to_owned(), Value::String(dir.clone()));
    }
    if let Some(hosts) = &definition.allowed_hosts {
        environment.insert(
            "WINRIG_ALLOWED_HOSTS".to_owned(),
            Value::String(hosts.clone()),
        );
    }
    let key = definition.key_in(&mcp, opencode_profile);
    mcp.insert(
        key,
        json!({
            "type": "local",
            "command": [definition.command, "stdio", "--profile", definition.profile],
            "environment": Value::Object(environment),
            // The opencode schema uses `disabled`; a missing field means enabled.
            "disabled": false
        }),
    );
    root.insert("mcp".to_owned(), Value::Object(mcp));
    // The token is in a separate file, so the config itself stays as it was.
    write_json(path, &Value::Object(root), false)
}

fn write_mcp_servers_json(
    path: &Path,
    definition: &ServerDefinition,
) -> Result<(), ClientConfigError> {
    let mut root = read_object(path)?;
    let mut servers = entry_object(&root, "mcpServers");
    let key = definition.key_in(&servers, mcp_servers_profile);
    servers.insert(
        key,
        json!({
            "type": "stdio",
            "command": definition.command,
            "args": ["stdio", "--profile", definition.profile],
            "env": Value::Object(definition.environment_json())
        }),
    );
    root.insert("mcpServers".to_owned(), Value::Object(servers));
    // The token is a value in the config itself, so make the file private (DR-4).
    write_json(path, &Value::Object(root), true)
}

/// Writes the Codex TOML config, adding the sections `[mcp_servers.winrig]` and
/// `[mcp_servers.winrig.env]`.
///
/// There is no TOML editor: any existing section under the prefix
/// `[mcp_servers.winrig` is dropped together with its lines up to the next
/// top-level header, and the other lines of the file are kept as they are. A
/// rewrite therefore leaves neither the old token nor a duplicate header
/// (AC-PRF-15).
fn write_codex(path: &Path, definition: &ServerDefinition) -> Result<(), ClientConfigError> {
    let existing = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(source) => {
            return Err(ClientConfigError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let key = codex_key(&existing, definition);
    let own_section = format!("[mcp_servers.{key}]");
    let own_prefix = format!("[mcp_servers.{key}.");
    let is_winrig_header = |line: &str| {
        let trimmed = line.trim_start();
        trimmed.starts_with(&own_section) || trimmed.starts_with(&own_prefix)
    };
    let mut kept: Vec<&str> = Vec::new();
    let mut skipping = false;
    for line in existing.lines() {
        let is_header = line.trim_start().starts_with('[');
        if is_header {
            // Only winrig sections are skipped; any other header starts a kept
            // block.
            skipping = is_winrig_header(line);
        }
        if !skipping {
            kept.push(line);
        }
    }
    while kept.last().is_some_and(|line| line.trim().is_empty()) {
        kept.pop();
    }
    let mut env_lines = String::new();
    for (key, value) in definition.environment() {
        env_lines.push_str(&format!("{key} = {value:?}\n"));
    }
    let block = format!(
        "[mcp_servers.{key}]\ncommand = {command:?}\nargs = [\"stdio\", \"--profile\", {profile:?}]\n\n[mcp_servers.{key}.env]\n{env_lines}",
        command = definition.command,
        profile = definition.profile,
    );
    let mut body = kept.join("\n");
    if !body.is_empty() {
        body.push('\n');
    }
    body.push_str(&block);
    std::fs::write(path, body).map_err(|source| ClientConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    // The token is a value in the config itself, so make the file private (DR-4).
    crate::private_fs::apply_private_file_mode(path);
    Ok(())
}

/// The section name Codex uses for the same profile (TR-PRF-14).
///
/// There is no TOML editor here, so the sections are parsed line by line: a
/// `[mcp_servers.NAME]` or `[mcp_servers.NAME.env]` header opens a block, and an
/// `args` line with the wanted profile inside the block gives the name.
fn codex_key(existing: &str, definition: &ServerDefinition) -> String {
    if let Some(name) = &definition.server_name {
        return name.clone();
    }
    let needle = format!("--profile\", {:?}", definition.profile);
    let mut current: Option<String> = None;
    for line in existing.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("[mcp_servers.") {
            current = rest
                .strip_suffix(']')
                .map(|inner| inner.split('.').next().unwrap_or(inner).to_owned());
            continue;
        }
        if trimmed.starts_with('[') {
            current = None;
            continue;
        }
        if trimmed.starts_with("args")
            && trimmed.contains(&needle)
            && let Some(name) = current.clone()
        {
            return name;
        }
    }
    DEFAULT_SERVER_NAME.to_owned()
}

fn write_json(path: &Path, value: &Value, protect: bool) -> Result<(), ClientConfigError> {
    let rendered =
        serde_json::to_string_pretty(value).map_err(|error| ClientConfigError::Unreadable {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
    std::fs::write(path, format!("{rendered}\n")).map_err(|source| ClientConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    // DR-4: where the token is a value, make the file private on Unix.
    if protect {
        crate::private_fs::apply_private_file_mode(path);
    }
    Ok(())
}

/// Turns an error into CLI text (for one output shape).
pub fn profile_error_text(error: &ProfileError) -> String {
    error.to_string()
}

/// Turns a directory error into CLI text.
pub fn path_error_text(error: &PathError) -> String {
    error.to_string()
}

/// Writes the client config to an explicit path (a test seam without the home directory).
///
/// # Errors
///
/// [`ClientConfigError`] when an existing file or entry cannot be parsed.
pub fn write_client_config_at(
    client: Client,
    path: &Path,
    scope: Scope,
    definition: &ServerDefinition,
) -> Result<(), ClientConfigError> {
    write_at(client, path, scope, definition)
}

/// Where a configuration file sits for its client (TR-PRF-18).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceScope {
    /// User-wide configuration.
    Global,
    /// Configuration in the project root (ADR-0012).
    Project,
    /// Claude Code local scope: a project entry inside the user configuration.
    Local,
}

impl SourceScope {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Project => "project",
            Self::Local => "local",
        }
    }

    /// Precedence of the scope for one server key: the narrowest scope wins.
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            Self::Local => 0,
            Self::Project => 1,
            Self::Global => 2,
        }
    }
}

/// A winrig server entry read from a client configuration (TR-PRF-18).
#[derive(Debug, Clone)]
pub struct ServerEntry {
    /// Configuration format that holds the entry (ADR-0012).
    pub client: Client,
    /// Level of the file (ADR-0012).
    pub scope: SourceScope,
    /// Absolute location of the configuration file.
    pub path: PathBuf,
    /// Name of the entry inside the configuration (TR-PRF-18).
    pub key: String,
    /// Account that the launch arguments name.
    pub profile: Option<String>,
    /// Environment of the entry, as written in the configuration.
    pub variables: BTreeMap<String, String>,
}

/// A client configuration file together with the scope it belongs to (ADR-0012).
#[derive(Debug, Clone)]
pub struct ConfigFile {
    /// Configuration format that holds the file (ADR-0012).
    pub client: Client,
    /// Level of the file (ADR-0012).
    pub scope: SourceScope,
    /// Absolute location of the configuration file.
    pub path: PathBuf,
    /// Directory of the current repository for the Claude Code local scope (TR-PRF-18).
    pub project_root: Option<String>,
}

/// The winrig servers of one configuration file, plus the winrig-looking entries
/// that the check does not compare (TR-PRF-18).
#[derive(Debug, Default)]
pub struct FileScan {
    pub servers: Vec<ServerEntry>,
    /// Keys of valid winrig launches that are not a stdio server, for example an
    /// HTTP entry.
    pub not_compared: Vec<String>,
    /// Keys of winrig-looking entries whose launch fields do not parse.
    pub unparsed: Vec<String>,
}

/// Why the environment check skipped a configuration file (TR-PRF-18).
#[derive(Debug)]
pub struct ServerReadError {
    /// Text without the path; the caller prints the path itself.
    pub reason: String,
}

impl ServerReadError {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl std::fmt::Display for ServerReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

/// Largest configuration the environment check reads; a bigger file is skipped.
const MAX_CONFIG_BYTES: u64 = 16 * 1024 * 1024;

/// Client configuration files of every scope, in a stable order (ADR-0012).
///
/// The global paths come from the home directory; the project paths come from
/// the nearest `.git` ancestor of `cwd`. The Claude Code local scope sits in the
/// user file under the absolute project root; opencode also accepts `.jsonc`.
#[must_use]
pub fn config_files(cwd: &Path) -> Vec<ConfigFile> {
    let root = find_project_root(cwd);
    let root_str = root.to_string_lossy().into_owned();
    let mut files = Vec::new();
    for client in [
        Client::Opencode,
        Client::ClaudeCode,
        Client::Codex,
        Client::Cursor,
    ] {
        let global = client.global_config_path();
        if let Some(path) = &global {
            files.push(ConfigFile {
                client,
                scope: SourceScope::Global,
                path: path.clone(),
                project_root: None,
            });
        }
        match client {
            Client::Opencode => {
                if let Some(path) = &global {
                    files.push(ConfigFile {
                        client,
                        scope: SourceScope::Global,
                        path: path.with_extension("jsonc"),
                        project_root: None,
                    });
                }
                for name in ["opencode.json", "opencode.jsonc"] {
                    files.push(ConfigFile {
                        client,
                        scope: SourceScope::Project,
                        path: root.join(name),
                        project_root: None,
                    });
                }
            }
            Client::ClaudeCode => {
                if let Some(path) = &global {
                    files.push(ConfigFile {
                        client,
                        scope: SourceScope::Local,
                        path: path.clone(),
                        project_root: Some(root_str.clone()),
                    });
                }
                files.push(ConfigFile {
                    client,
                    scope: SourceScope::Project,
                    path: root.join(".mcp.json"),
                    project_root: None,
                });
            }
            Client::Codex | Client::Cursor => files.push(ConfigFile {
                client,
                scope: SourceScope::Project,
                path: client.project_config_path(&root),
                project_root: None,
            }),
        }
    }
    files
}

/// Collect the winrig entries of one configuration file (TR-PRF-18).
///
/// # Errors
///
/// [`ServerReadError`] when the file cannot be read, is not a regular file, is
/// too large, or holds a syntax error.
pub fn read_servers(file: &ConfigFile) -> Result<FileScan, ServerReadError> {
    let text = read_config_text(&file.path)?;
    match file.client {
        Client::Opencode => scan_opencode(file, &text),
        Client::ClaudeCode | Client::Cursor => scan_mcp_servers(file, &text),
        Client::Codex => scan_codex(file, &text),
    }
}

fn read_config_text(path: &Path) -> Result<String, ServerReadError> {
    match std::fs::metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(error) => return Err(ServerReadError::new(format!("cannot read: {error}"))),
        Ok(metadata) => {
            if !metadata.is_file() {
                return Err(ServerReadError::new("not a regular file"));
            }
            if metadata.len() > MAX_CONFIG_BYTES {
                return Err(ServerReadError::new(format!(
                    "larger than {MAX_CONFIG_BYTES} bytes"
                )));
            }
        }
    }
    std::fs::read_to_string(path)
        .map_err(|error| ServerReadError::new(format!("cannot read: {error}")))
}

fn scan_opencode(file: &ConfigFile, text: &str) -> Result<FileScan, ServerReadError> {
    let Some(value) = parse_jsonc(text)? else {
        return Ok(FileScan::default());
    };
    let Some(mcp) = value.get("mcp").and_then(Value::as_object) else {
        return Ok(FileScan::default());
    };
    let mut scan = FileScan::default();
    for (key, entry) in mcp {
        collect(
            file,
            key,
            entry,
            string_map(entry.get("environment")),
            &mut scan,
        );
    }
    Ok(scan)
}

fn scan_mcp_servers(file: &ConfigFile, text: &str) -> Result<FileScan, ServerReadError> {
    let Some(value) = parse_json(text)? else {
        return Ok(FileScan::default());
    };
    let Some(table) = mcp_servers_table(&value, file) else {
        return Ok(FileScan::default());
    };
    let mut scan = FileScan::default();
    for (key, entry) in table {
        collect(file, key, entry, string_map(entry.get("env")), &mut scan);
    }
    Ok(scan)
}

fn mcp_servers_table<'a>(value: &'a Value, file: &ConfigFile) -> Option<&'a Map<String, Value>> {
    match file.scope {
        SourceScope::Local => {
            let root = file.project_root.as_deref()?;
            value
                .get("projects")?
                .get(root)?
                .get("mcpServers")?
                .as_object()
        }
        _ => value.get("mcpServers").and_then(Value::as_object),
    }
}

fn scan_codex(file: &ConfigFile, text: &str) -> Result<FileScan, ServerReadError> {
    if text.trim().is_empty() {
        return Ok(FileScan::default());
    }
    let value: toml::Value = toml::from_str(text).map_err(|error| toml_reason(text, &error))?;
    let Some(servers) = value.get("mcp_servers").and_then(toml::Value::as_table) else {
        return Ok(FileScan::default());
    };
    let mut scan = FileScan::default();
    for (key, entry) in servers {
        // The launch fields are inspected as JSON, so one classifier serves every
        // client format.
        let as_json = serde_json::to_value(entry).unwrap_or(Value::Null);
        collect(file, key, &as_json, toml_env(entry), &mut scan);
    }
    Ok(scan)
}

fn toml_env(entry: &toml::Value) -> BTreeMap<String, String> {
    entry
        .get("env")
        .and_then(toml::Value::as_table)
        .map(|table| {
            table
                .iter()
                .filter_map(|(name, value)| {
                    value.as_str().map(|text| (name.clone(), text.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn collect(
    file: &ConfigFile,
    key: &str,
    entry: &Value,
    variables: BTreeMap<String, String>,
    scan: &mut FileScan,
) {
    match entry_launch(entry) {
        EntryLaunch::Stdio(items) => {
            let items: Vec<&str> = items.iter().map(String::as_str).collect();
            scan.servers.push(ServerEntry {
                client: file.client,
                scope: file.scope,
                path: file.path.clone(),
                key: key.to_owned(),
                profile: profile_from(&items),
                variables,
            });
        }
        EntryLaunch::Other => scan.not_compared.push(key.to_owned()),
        EntryLaunch::Broken => scan.unparsed.push(key.to_owned()),
        EntryLaunch::Unrelated => {}
    }
}

/// How one entry launches its server (TR-PRF-18).
enum EntryLaunch {
    /// A winrig stdio launch that the check compares.
    Stdio(Vec<String>),
    /// A valid launch that is not a winrig stdio server, such as an HTTP entry.
    Other,
    /// A winrig-looking entry whose launch fields do not parse.
    Broken,
    /// Entry that does not concern winrig.
    Unrelated,
}

fn entry_launch(entry: &Value) -> EntryLaunch {
    let mut items: Vec<String> = Vec::new();
    let mut mentions = false;
    let mut wellformed = true;
    let mut has_launch = false;
    for field in ["command", "args"] {
        match entry.get(field) {
            Some(Value::String(text)) => {
                has_launch = true;
                mentions |= contains_winrig(text);
                items.push(text.clone());
            }
            Some(Value::Array(parts)) => {
                has_launch = true;
                for part in parts {
                    match part.as_str() {
                        Some(text) => {
                            mentions |= contains_winrig(text);
                            items.push(text.to_owned());
                        }
                        None => wellformed = false,
                    }
                }
            }
            Some(_) => wellformed = false,
            None => {}
        }
    }
    match entry.get("url") {
        Some(Value::String(url)) => {
            has_launch = true;
            mentions |= contains_winrig(url);
        }
        Some(_) => wellformed = false,
        None => {}
    }
    if !mentions {
        return EntryLaunch::Unrelated;
    }
    if !wellformed || !has_launch {
        return EntryLaunch::Broken;
    }
    let refs: Vec<&str> = items.iter().map(String::as_str).collect();
    if is_winrig_stdio(&refs) {
        EntryLaunch::Stdio(items)
    } else {
        EntryLaunch::Other
    }
}

fn contains_winrig(text: &str) -> bool {
    text.to_ascii_lowercase().contains("winrig")
}

/// A JSON object, or `None` for an empty file. The reason carries the position
/// only: a parser message can echo the file content (DR-4).
fn parse_json(text: &str) -> Result<Option<Value>, ServerReadError> {
    if text.trim().is_empty() {
        return Ok(None);
    }
    serde_json::from_str(text)
        .map(Some)
        .map_err(|error| json_reason(&error))
}

fn parse_jsonc(text: &str) -> Result<Option<Value>, ServerReadError> {
    if text.trim().is_empty() {
        return Ok(None);
    }
    let stripped = remove_trailing_commas(&strip_jsonc_comments(text));
    serde_json::from_str(&stripped)
        .map(Some)
        .map_err(|error| json_reason(&error))
}

/// Position-only text for a JSON syntax error (DR-4).
fn json_reason(error: &serde_json::Error) -> ServerReadError {
    ServerReadError::new(format!(
        "cannot parse JSON at line {} column {}",
        error.line(),
        error.column()
    ))
}

/// Position-only text for a TOML syntax error (DR-4).
fn toml_reason(text: &str, error: &toml::de::Error) -> ServerReadError {
    let (line, column) = error
        .span()
        .map_or((1, 1), |span| line_column(text, span.start));
    ServerReadError::new(format!("cannot parse TOML at line {line} column {column}"))
}

/// One-based position of a byte offset.
fn line_column(text: &str, offset: usize) -> (usize, usize) {
    let mut line = 1;
    let mut column = 1;
    for (index, character) in text.char_indices() {
        if index >= offset {
            break;
        }
        if character == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    (line, column)
}

/// Blanks `//` and `/* */` comments outside strings, keeping the length, so a
/// `.jsonc` file parses and a position still points at the original line.
fn strip_jsonc_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(character) = chars.next() {
        if in_string {
            out.push(character);
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }
        match character {
            '"' => {
                in_string = true;
                out.push(character);
            }
            '/' => match chars.peek() {
                Some('/') => {
                    chars.next();
                    out.push(' ');
                    for next in chars.by_ref() {
                        if next == '\n' {
                            out.push('\n');
                            break;
                        }
                        out.push(' ');
                    }
                }
                Some('*') => {
                    chars.next();
                    out.push(' ');
                    let mut previous = '\0';
                    for next in chars.by_ref() {
                        if previous == '*' && next == '/' {
                            out.push(' ');
                            break;
                        }
                        out.push(if next == '\n' { '\n' } else { ' ' });
                        previous = next;
                    }
                }
                _ => out.push(character),
            },
            _ => out.push(character),
        }
    }
    out
}

/// Blanks a comma that only whitespace separates from a closing brace or bracket,
/// outside strings; the position is kept.
fn remove_trailing_commas(text: &str) -> String {
    let characters: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut escaped = false;
    let mut index = 0;
    while index < characters.len() {
        let character = characters[index];
        if in_string {
            out.push(character);
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if character == '"' {
            in_string = true;
            out.push(character);
            index += 1;
            continue;
        }
        if character == ',' {
            let mut look = index + 1;
            while look < characters.len() && characters[look].is_whitespace() {
                look += 1;
            }
            if look < characters.len() && matches!(characters[look], '}' | ']') {
                out.push(' ');
                index += 1;
                continue;
            }
        }
        out.push(character);
        index += 1;
    }
    out
}

fn string_map(value: Option<&Value>) -> BTreeMap<String, String> {
    value
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|text| (key.clone(), text.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn is_winrig_stdio(items: &[&str]) -> bool {
    items
        .first()
        .is_some_and(|program| binary_is_winrig(program))
        && items.contains(&"stdio")
}

fn binary_is_winrig(program: &str) -> bool {
    let name = program
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(program)
        .to_ascii_lowercase();
    name.strip_suffix(".exe").unwrap_or(name.as_str()) == "winrig"
}

/// Account named by the launch arguments, in both flag forms (TR-PRF-18).
fn profile_from(items: &[&str]) -> Option<String> {
    for (index, item) in items.iter().enumerate() {
        if *item == "--profile" {
            return items.get(index + 1).map(|value| (*value).to_owned());
        }
        if let Some(value) = item.strip_prefix("--profile=") {
            return Some(value.to_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "winrig-clientcfg-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn definition() -> ServerDefinition {
        ServerDefinition {
            command: "/usr/local/bin/winrig".to_owned(),
            profile: "corp".to_owned(),
            token: "tok-123".to_owned(),
            profile_dir: Some("/tmp/profiles".to_owned()),
            state_root: Some("/tmp/state".to_owned()),
            server_name: None,
            allowed_hosts: None,
        }
    }

    /// AC-PRF-68: `--allowed-hosts` reaches the entry of every client, and a
    /// rewrite without the flag removes the variable (TR-PRF-17, ADR-0015 §9).
    #[test]
    fn allowed_hosts_are_written_and_removed_for_every_client() {
        let dir = temp_dir("allowed-hosts");
        for (client, file) in [
            (Client::Opencode, "opencode.json"),
            (Client::ClaudeCode, "claude.json"),
            (Client::Cursor, "cursor.json"),
            (Client::Codex, "config.toml"),
        ] {
            let path = dir.join(file);
            let mut with_hosts = definition();
            with_hosts.allowed_hosts = Some("host1,.corp.example".to_owned());
            write_client_config_at(client, &path, Scope::Global, &with_hosts).expect("write");
            let written = std::fs::read_to_string(&path).expect("read");
            assert!(
                written.contains("WINRIG_ALLOWED_HOSTS") && written.contains("host1,.corp.example"),
                "{client:?}: {written}"
            );

            write_client_config_at(client, &path, Scope::Global, &definition()).expect("rewrite");
            let rewritten = std::fs::read_to_string(&path).expect("read");
            assert!(
                !rewritten.contains("WINRIG_ALLOWED_HOSTS"),
                "{client:?} kept the variable: {rewritten}"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The printed definition carries the host list too.
    #[test]
    fn printed_definition_carries_allowed_hosts() {
        let mut with_hosts = definition();
        with_hosts.allowed_hosts = Some("*".to_owned());
        let rendered = with_hosts.to_json().expect("json");
        assert!(
            rendered.contains("\"WINRIG_ALLOWED_HOSTS\": \"*\""),
            "{rendered}"
        );
        assert!(
            !definition()
                .to_json()
                .expect("json")
                .contains("WINRIG_ALLOWED_HOSTS")
        );
    }

    /// The definition carries the profile and state directories; otherwise a
    /// client with a non-standard location does not find the profile.
    #[test]
    fn definition_carries_directories() {
        let rendered = definition().to_json().expect("json");
        assert!(rendered.contains("WINRIG_PROFILE_DIR"));
        assert!(rendered.contains("WINRIG_STATE_DIR"));
        assert!(rendered.contains("/tmp/profiles"));
        assert!(rendered.contains("/tmp/state"));
    }

    /// AC-PRF-66: `WINRIG_STATE_DIR` is the state root, and the token lives
    /// where the server builds the path itself. Otherwise the profile name is
    /// added twice and the lock misses the directory declared in the config.
    #[test]
    fn state_dir_in_the_entry_is_the_root() {
        let dir = temp_dir("stateroot");
        let project = dir.join("project");
        let state = dir.join("state");
        std::fs::create_dir_all(&project).unwrap();
        let path = project.join("opencode.json");
        let mut definition = definition();
        definition.state_root = Some(state.to_string_lossy().into_owned());
        write_client_config_at(Client::Opencode, &path, Scope::Project, &definition)
            .expect("write");
        let value: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let environment = &value["mcp"]["winrig"]["environment"];
        assert_eq!(
            environment["WINRIG_STATE_DIR"].as_str().unwrap(),
            state.to_string_lossy(),
            "the config gets the root, without the profile name"
        );
        let token_reference = environment["WINRIG_TOKEN"].as_str().unwrap();
        let expected = state.join("corp").join("winrig-token");
        assert_eq!(
            token_reference,
            format!("{{file:{}}}", expected.display()),
            "the token reference points into the profile directory"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-64: the same profile is already declared under its own key, so
    /// the entry is updated in place. A second entry would start a second
    /// process for one profile, it would hit the lock, and the client would see
    /// `Connection closed`.
    #[test]
    fn opencode_updates_the_existing_entry_for_the_same_profile() {
        let dir = temp_dir("samekey");
        let path = dir.join("opencode.json");
        std::fs::write(
            &path,
            r#"{"mcp":{"winrig-tm":{"type":"local","command":["/old/winrig","stdio","--profile","corp"],"disabled":false}}}"#,
        )
        .unwrap();
        write_client_config_at(Client::Opencode, &path, Scope::Global, &definition())
            .expect("write");
        let value: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let keys: Vec<&String> = value["mcp"].as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            vec!["winrig-tm"],
            "the key is kept, with no duplicate"
        );
        assert_eq!(
            value["mcp"]["winrig-tm"]["command"][0],
            "/usr/local/bin/winrig"
        );
    }

    /// AC-PRF-64: an entry for another profile is left alone; it is a different
    /// server and does not share the lock.
    #[test]
    fn opencode_leaves_entries_for_other_profiles_alone() {
        let dir = temp_dir("otherprofile");
        let path = dir.join("opencode.json");
        std::fs::write(
            &path,
            r#"{"mcp":{"winrig-lab":{"type":"local","command":["/old/winrig","stdio","--profile","lab"]}}}"#,
        )
        .unwrap();
        write_client_config_at(Client::Opencode, &path, Scope::Global, &definition())
            .expect("write");
        let value: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let mcp = value["mcp"].as_object().unwrap();
        assert_eq!(mcp.len(), 2, "the lab profile stays, corp is added");
        assert_eq!(mcp["winrig-lab"]["command"][2], "--profile");
        assert_eq!(mcp["winrig"]["command"][3], "corp");
    }

    /// AC-PRF-65: `--server-name` sets the key explicitly.
    #[test]
    fn explicit_server_name_is_used_as_the_key() {
        let dir = temp_dir("servername");
        let path = dir.join("opencode.json");
        std::fs::write(&path, b"{}").unwrap();
        let mut definition = definition();
        definition.server_name = Some("winrig-prod".to_owned());
        write_client_config_at(Client::Opencode, &path, Scope::Global, &definition).expect("write");
        let value: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(value["mcp"].get("winrig-prod").is_some());
        assert!(value["mcp"].get("winrig").is_none());
    }

    /// AC-PRF-64: the same for clients with the `mcpServers` schema.
    #[test]
    fn mcp_servers_updates_the_existing_entry_for_the_same_profile() {
        let dir = temp_dir("samekeyclaude");
        let path = dir.join("claude.json");
        std::fs::write(
            &path,
            r#"{"mcpServers":{"winrig-tm":{"type":"stdio","command":"/old/winrig","args":["stdio","--profile","corp"]}}}"#,
        )
        .unwrap();
        write_client_config_at(Client::ClaudeCode, &path, Scope::Global, &definition())
            .expect("write");
        let value: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let keys: Vec<&String> = value["mcpServers"].as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["winrig-tm"]);
        assert_eq!(
            value["mcpServers"]["winrig-tm"]["command"],
            "/usr/local/bin/winrig"
        );
    }

    /// AC-PRF-15: the other entries of the file are untouched, the token is present, the password is not.
    #[test]
    fn opencode_preserves_other_entries() {
        let dir = temp_dir("opencode");
        let path = dir.join("opencode.json");
        std::fs::write(&path, r#"{"mcp":{"other":{"type":"local"}}}"#).unwrap();
        write_client_config_at(Client::Opencode, &path, Scope::Global, &definition())
            .expect("write");
        let value: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(value["mcp"]["other"]["type"], "local");
        assert_eq!(value["mcp"]["winrig"]["type"], "local");
        let rendered = std::fs::read_to_string(&path).unwrap();
        assert!(
            !rendered.contains("tok-123"),
            "token must be a file reference"
        );
        assert!(rendered.contains("{file:"));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-15: Claude Code and Cursor get an mcpServers entry with an env token.
    #[test]
    fn mcp_servers_clients_write_stdio_entry() {
        for (client, name) in [(Client::ClaudeCode, "claude"), (Client::Cursor, "cursor")] {
            let dir = temp_dir(name);
            let path = dir.join("mcp.json");
            std::fs::write(&path, r#"{"mcpServers":{"other":{"command":"x"}}}"#).unwrap();
            write_client_config_at(client, &path, Scope::Global, &definition()).expect("write");
            let value: Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            assert_eq!(value["mcpServers"]["other"]["command"], "x");
            assert_eq!(value["mcpServers"]["winrig"]["type"], "stdio");
            assert_eq!(
                value["mcpServers"]["winrig"]["env"]["WINRIG_TOKEN"],
                "tok-123"
            );
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    /// AC-PRF-15: Codex gets a `[mcp_servers.winrig]` section; an existing
    /// section of the same name is replaced and the other lines are kept.
    #[test]
    fn codex_replaces_only_its_own_section() {
        let dir = temp_dir("codex");
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            "[other]\nkey = \"value\"\n\n[mcp_servers.winrig]\ncommand = \"old\"\n",
        )
        .unwrap();
        write_client_config_at(Client::Codex, &path, Scope::Global, &definition()).expect("write");
        let rendered = std::fs::read_to_string(&path).unwrap();
        assert!(rendered.contains("[other]"));
        assert!(rendered.contains("key = \"value\""));
        assert!(!rendered.contains("command = \"old\""));
        assert!(rendered.contains("[mcp_servers.winrig]"));
        assert!(rendered.contains("WINRIG_TOKEN = \"tok-123\""));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-15: a Codex rewrite also replaces the `.env` section; neither the
    /// old token nor a duplicate header remains.
    #[test]
    fn codex_rewrite_replaces_env_section() {
        let dir = temp_dir("codex-rewrite");
        let path = dir.join("config.toml");
        std::fs::write(&path, "[other]\nkey = \"value\"\n").unwrap();
        write_client_config_at(Client::Codex, &path, Scope::Global, &definition()).expect("first");
        let mut updated = definition();
        updated.token = "tok-456".to_owned();
        write_client_config_at(Client::Codex, &path, Scope::Global, &updated).expect("second");

        let rendered = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            rendered.matches("[mcp_servers.winrig]").count(),
            1,
            "header must appear once: {rendered}"
        );
        assert_eq!(
            rendered.matches("[mcp_servers.winrig.env]").count(),
            1,
            "env header must appear once: {rendered}"
        );
        assert!(
            !rendered.contains("tok-123"),
            "old token must be gone: {rendered}"
        );
        assert!(
            rendered.contains("tok-456"),
            "new token must be present: {rendered}"
        );
        assert!(
            rendered.contains("[other]"),
            "other section lost: {rendered}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-15: a Claude/Cursor rewrite replaces the entry instead of duplicating it.
    #[test]
    fn mcp_servers_rewrite_replaces_entry() {
        let dir = temp_dir("mcp-rewrite");
        let path = dir.join("mcp.json");
        std::fs::write(&path, r#"{"mcpServers":{"other":{"command":"x"}}}"#).unwrap();
        write_client_config_at(Client::ClaudeCode, &path, Scope::Global, &definition())
            .expect("first");
        let mut updated = definition();
        updated.token = "tok-456".to_owned();
        write_client_config_at(Client::ClaudeCode, &path, Scope::Global, &updated).expect("second");
        let value: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(value["mcpServers"]["other"]["command"], "x");
        assert_eq!(
            value["mcpServers"]["winrig"]["env"]["WINRIG_TOKEN"],
            "tok-456"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-15: a broken Codex config is not overwritten silently.
    #[test]
    fn codex_broken_file_is_reported_not_overwritten() {
        let dir = temp_dir("codex-broken");
        let path = dir.join("config.toml");
        // The file is readable, but it contains a foreign header that is already
        // taken and must not be lost.
        std::fs::write(&path, "[mcp_servers.winrig]\nbroken\n").unwrap();
        write_client_config_at(Client::Codex, &path, Scope::Global, &definition()).expect("write");
        let rendered = std::fs::read_to_string(&path).unwrap();
        assert_eq!(rendered.matches("[mcp_servers.winrig]").count(), 1);
        assert!(!rendered.contains("broken"));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-15: an unknown client is refused with no file changes.
    #[test]
    fn unknown_client_is_rejected() {
        assert!(Client::parse("vscode").is_none());
        assert_eq!(Client::parse("OpenCode"), Some(Client::Opencode));
        assert_eq!(Client::parse("claude-code"), Some(Client::ClaudeCode));
    }

    /// Where the token is a value, the config file is private on Unix; opencode
    /// does not touch the mode of its config (the token is in a separate file).
    #[cfg(unix)]
    #[test]
    fn inline_token_config_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("private");
        let claude = dir.join("claude.json");
        std::fs::write(&claude, b"{}").unwrap();
        write_client_config_at(Client::ClaudeCode, &claude, Scope::Global, &definition())
            .expect("claude");
        assert_eq!(
            std::fs::metadata(&claude).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let opencode = dir.join("opencode.json");
        std::fs::write(&opencode, b"{}").unwrap();
        std::fs::set_permissions(&opencode, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        write_client_config_at(Client::Opencode, &opencode, Scope::Global, &definition())
            .expect("opencode");
        assert_eq!(
            std::fs::metadata(&opencode).unwrap().permissions().mode() & 0o777,
            0o644,
            "opencode config keeps its mode: the token is a file reference"
        );
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o755,
            "an existing foreign directory must keep its mode"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An unreadable (non-UTF-8) config is not overwritten silently.
    #[test]
    fn unreadable_config_is_reported_not_overwritten() {
        let dir = temp_dir("unreadable");
        let path = dir.join("config.toml");
        // Invalid UTF-8: read_to_string returns an error.
        std::fs::write(&path, [0xff, 0xfe, 0x00, 0x01]).unwrap();
        let error = write_client_config_at(Client::Codex, &path, Scope::Global, &definition())
            .expect_err("must refuse to overwrite");
        assert!(matches!(error, ClientConfigError::Io { .. }), "{error}");
        assert_eq!(std::fs::read(&path).unwrap(), [0xff, 0xfe, 0x00, 0x01]);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// ADR-0012: the project root is the nearest ancestor with `.git`, otherwise
    /// the directory itself; a `.git` worktree file counts as a root like a
    /// directory.
    #[test]
    fn find_project_root_walks_up_to_git() {
        let dir = temp_dir("project-root");
        let repo = dir.join("repo");
        let nested = repo.join("packages").join("web");
        std::fs::create_dir_all(&nested).unwrap();
        assert_eq!(find_project_root(&nested), nested);
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        assert_eq!(find_project_root(&nested), repo);

        let worktree = dir.join("worktree");
        let worktree_sub = worktree.join("sub");
        std::fs::create_dir_all(&worktree_sub).unwrap();
        std::fs::write(worktree.join(".git"), "gitdir: ../.git/worktrees/w\n").unwrap();
        assert_eq!(find_project_root(&worktree_sub), worktree);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// ADR-0012: the project path differs per client.
    #[test]
    fn project_config_paths_per_client() {
        let root = Path::new("/tmp/proj");
        assert_eq!(
            Client::Opencode.project_config_path(root),
            Path::new("/tmp/proj/opencode.json")
        );
        assert_eq!(
            Client::ClaudeCode.project_config_path(root),
            Path::new("/tmp/proj/.mcp.json")
        );
        assert_eq!(
            Client::Codex.project_config_path(root),
            Path::new("/tmp/proj/.codex/config.toml")
        );
        assert_eq!(
            Client::Cursor.project_config_path(root),
            Path::new("/tmp/proj/.cursor/mcp.json")
        );
    }

    /// AC-PRF-61: at the project scope the opencode token goes into the private
    /// state directory, not into the project tree.
    #[test]
    fn opencode_project_token_goes_to_state_dir() {
        let dir = temp_dir("opencode-project");
        let project = dir.join("project");
        let state = dir.join("state");
        std::fs::create_dir_all(&project).unwrap();
        let path = project.join("opencode.json");
        let mut definition = definition();
        definition.state_root = Some(state.to_string_lossy().into_owned());
        write_client_config_at(Client::Opencode, &path, Scope::Project, &definition)
            .expect("write");

        let rendered = std::fs::read_to_string(&path).unwrap();
        assert!(
            !rendered.contains("tok-123"),
            "token must stay a file reference"
        );
        assert!(rendered.contains("{file:"));
        // TR-PRF-15: the profile directory is built exactly once; the server
        // gets the root and adds the profile name itself.
        let token_file = state.join("corp").join("winrig-token");
        assert!(
            token_file.is_file(),
            "the token file must live in the profile's state dir"
        );
        assert!(
            !project.join("winrig-token").exists(),
            "no token file in the project tree"
        );
        assert!(
            std::fs::read_to_string(&token_file)
                .unwrap()
                .contains("tok-123")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// ADR-0012: the opencode project scope without a state directory is
    /// refused instead of putting the token into the project.
    #[test]
    fn opencode_project_without_state_dir_is_refused() {
        let dir = temp_dir("opencode-project-nostate");
        let project = dir.join("project");
        std::fs::create_dir_all(&project).unwrap();
        let path = project.join("opencode.json");
        let mut definition = definition();
        definition.state_root = None;
        let error = write_client_config_at(Client::Opencode, &path, Scope::Project, &definition)
            .expect_err("must refuse");
        assert!(matches!(error, ClientConfigError::NoStateDir), "{error}");
        assert!(!project.join("winrig-token").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-69: doctor reads each winrig entry with its settings and skips an
    /// entry that is not winrig.
    #[test]
    fn doctor_reads_opencode_entries() {
        let dir = temp_dir("doctor-opencode");
        let path = dir.join("opencode.json");
        std::fs::write(
            &path,
            r#"{"mcp":{
                "other":{"type":"local","command":["/usr/bin/other","stdio"]},
                "winrig":{"type":"local","command":["/usr/local/bin/winrig","stdio","--profile","corp"],"environment":{"WINRIG_ALLOW_INSECURE_TLS":"true"}},
                "winrig-lab":{"type":"local","command":["/usr/local/bin/winrig","stdio","--profile","lab"],"environment":{"WINRIG_ALLOWED_HOSTS":"web01"}}
            }}"#,
        )
        .unwrap();
        let scan =
            read_servers(&config_file(Client::Opencode, SourceScope::Global, path)).expect("read");
        let mut keys: Vec<&str> = scan
            .servers
            .iter()
            .map(|server| server.key.as_str())
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["winrig", "winrig-lab"], "{:?}", scan.servers);
        let corp = scan
            .servers
            .iter()
            .find(|server| server.key == "winrig")
            .expect("winrig");
        assert_eq!(corp.profile.as_deref(), Some("corp"));
        assert_eq!(
            corp.variables
                .get("WINRIG_ALLOW_INSECURE_TLS")
                .map(String::as_str),
            Some("true")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-69: the mcpServers clients and the Codex TOML are read too.
    #[test]
    fn doctor_reads_mcp_servers_and_codex() {
        let dir = temp_dir("doctor-multi");
        let claude = dir.join("claude.json");
        std::fs::write(
            &claude,
            r#"{"mcpServers":{"winrig":{"type":"stdio","command":"/opt/winrig","args":["stdio","--profile","corp"],"env":{"WINRIG_ALLOW_FILE_WRITE":"true"}}}}"#,
        )
        .unwrap();
        let scan = read_servers(&config_file(
            Client::ClaudeCode,
            SourceScope::Global,
            claude,
        ))
        .expect("read");
        assert_eq!(scan.servers.len(), 1, "{:?}", scan.servers);
        assert_eq!(scan.servers[0].profile.as_deref(), Some("corp"));
        assert_eq!(
            scan.servers[0]
                .variables
                .get("WINRIG_ALLOW_FILE_WRITE")
                .map(String::as_str),
            Some("true")
        );

        let codex = dir.join("config.toml");
        std::fs::write(
            &codex,
            "[other]\nx = 1\n\n[mcp_servers.winrig]\ncommand = \"/opt/winrig\"\nargs = [\"stdio\", \"--profile\", \"corp\"]\n\n[mcp_servers.winrig.env]\nWINRIG_ALLOWED_HOSTS = \"web01\"\n",
        )
        .unwrap();
        let scan =
            read_servers(&config_file(Client::Codex, SourceScope::Global, codex)).expect("read");
        assert_eq!(scan.servers.len(), 1, "{:?}", scan.servers);
        assert_eq!(scan.servers[0].key, "winrig");
        assert_eq!(scan.servers[0].profile.as_deref(), Some("corp"));
        assert_eq!(
            scan.servers[0]
                .variables
                .get("WINRIG_ALLOWED_HOSTS")
                .map(String::as_str),
            Some("web01")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-69: a missing configuration file holds no server and is not an error.
    #[test]
    fn doctor_missing_file_is_empty() {
        let dir = temp_dir("doctor-missing");
        let scan = read_servers(&config_file(
            Client::Opencode,
            SourceScope::Project,
            dir.join("nope.json"),
        ))
        .expect("read");
        assert!(scan.servers.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-69: a malformed configuration is skipped with a reason, not a panic.
    #[test]
    fn doctor_malformed_file_is_reported() {
        let dir = temp_dir("doctor-bad");
        let path = dir.join("opencode.json");
        std::fs::write(&path, b"{ not json").unwrap();
        let error = read_servers(&config_file(Client::Opencode, SourceScope::Global, path))
            .expect_err("must refuse");
        assert!(error.reason.contains("cannot parse"), "{error}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-69: `opencode.jsonc` is read with `//` and `/* */` comments; a
    /// comment marker inside a string is kept.
    #[test]
    fn doctor_reads_jsonc_with_comments() {
        let dir = temp_dir("doctor-jsonc");
        let path = dir.join("opencode.jsonc");
        std::fs::write(
            &path,
            r#"// leading comment
            {
                /* block
                   comment */
                "note": "http://host/path/*keep*/",
                "mcp": {
                    "winrig": {
                        "type": "local", // inline comment
                        "command": ["/opt/winrig", "stdio", "--profile=corp"],
                        "environment": { "WINRIG_ALLOW_INSECURE_TLS": "1" }
                    }
                }
            }"#,
        )
        .unwrap();
        let scan = read_servers(&config_file(Client::Opencode, SourceScope::Global, path))
            .expect("read jsonc");
        assert_eq!(scan.servers.len(), 1, "{:?}", scan.servers);
        assert_eq!(scan.servers[0].profile.as_deref(), Some("corp"));
        assert_eq!(
            scan.servers[0]
                .variables
                .get("WINRIG_ALLOW_INSECURE_TLS")
                .map(String::as_str),
            Some("1")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-69: a JSONC file with trailing commas parses.
    #[test]
    fn doctor_reads_jsonc_with_trailing_commas() {
        let dir = temp_dir("doctor-trailing");
        let path = dir.join("opencode.jsonc");
        std::fs::write(
            &path,
            r#"{
                "mcp": {
                    "winrig": {
                        "command": ["/opt/winrig", "stdio", "--profile", "corp"],
                        "environment": { "WINRIG_ALLOW_INSECURE_TLS": "true", },
                    },
                },
            }"#,
        )
        .unwrap();
        let scan = read_servers(&config_file(Client::Opencode, SourceScope::Global, path))
            .expect("read jsonc");
        assert_eq!(scan.servers.len(), 1, "{:?}", scan.servers);
        assert_eq!(scan.servers[0].profile.as_deref(), Some("corp"));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-69: a Codex file with a multiline `args` array and an inline `env`
    /// table is read.
    #[test]
    fn doctor_reads_codex_multiline_and_inline_env() {
        let dir = temp_dir("doctor-codex");
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            "[mcp_servers.winrig]\ncommand = \"/opt/winrig\"\nargs = [\n  \"stdio\",\n  \"--profile\",\n  \"corp\",\n]\nenv = { WINRIG_ALLOWED_HOSTS = \"web01\", WINRIG_ALLOW_FILE_WRITE = \"true\" }\n",
        )
        .unwrap();
        let scan =
            read_servers(&config_file(Client::Codex, SourceScope::Global, path)).expect("read");
        assert_eq!(scan.servers.len(), 1, "{:?}", scan.servers);
        assert_eq!(scan.servers[0].profile.as_deref(), Some("corp"));
        assert_eq!(
            scan.servers[0]
                .variables
                .get("WINRIG_ALLOWED_HOSTS")
                .map(String::as_str),
            Some("web01")
        );
        assert_eq!(
            scan.servers[0]
                .variables
                .get("WINRIG_ALLOW_FILE_WRITE")
                .map(String::as_str),
            Some("true")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-69: the Claude Code local scope sits under the absolute project
    /// root inside the user file; the top-level `mcpServers` is not used there.
    #[test]
    fn doctor_reads_claude_local_scope() {
        let dir = temp_dir("doctor-claude-local");
        let path = dir.join("claude.json");
        std::fs::write(
            &path,
            r#"{"mcpServers":{"winrig":{"command":"/opt/winrig","args":["stdio","--profile","global"]}},
                "projects":{"/proj/root":{"mcpServers":{"winrig":{"command":"/opt/winrig","args":["stdio","--profile","corp"]}}}}}"#,
        )
        .unwrap();
        let mut file = config_file(Client::ClaudeCode, SourceScope::Local, path);
        file.project_root = Some("/proj/root".to_owned());
        let scan = read_servers(&file).expect("read");
        assert_eq!(scan.servers.len(), 1, "{:?}", scan.servers);
        assert_eq!(scan.servers[0].key, "winrig");
        assert_eq!(scan.servers[0].profile.as_deref(), Some("corp"));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-69: a valid winrig launch that is not stdio (an HTTP entry) is
    /// reported as not compared, not as a parse failure.
    #[test]
    fn doctor_reports_a_non_stdio_winrig_entry_as_not_compared() {
        let dir = temp_dir("doctor-http");
        let path = dir.join("opencode.json");
        std::fs::write(
            &path,
            r#"{"mcp":{"winrig-http":{"type":"remote","command":["/opt/winrig","serve"]}}}"#,
        )
        .unwrap();
        let scan =
            read_servers(&config_file(Client::Opencode, SourceScope::Global, path)).expect("read");
        assert!(scan.servers.is_empty());
        assert!(scan.unparsed.is_empty());
        assert_eq!(scan.not_compared, ["winrig-http"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-69: a winrig-looking entry whose launch fields do not parse is
    /// reported as unparsed.
    #[test]
    fn doctor_flags_a_broken_winrig_entry_as_unparsed() {
        let dir = temp_dir("doctor-broken");
        let path = dir.join("opencode.json");
        std::fs::write(
            &path,
            r#"{"mcp":{"winrig-broken":{"command":["/opt/winrig","stdio",42]}}}"#,
        )
        .unwrap();
        let scan =
            read_servers(&config_file(Client::Opencode, SourceScope::Global, path)).expect("read");
        assert!(scan.servers.is_empty());
        assert!(scan.not_compared.is_empty());
        assert_eq!(scan.unparsed, ["winrig-broken"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-69: a non-regular file and an oversized file are skipped with a
    /// reason.
    #[test]
    fn doctor_skips_non_regular_and_large_files() {
        let dir = temp_dir("doctor-skip");
        let as_dir = dir.join("opencode.json");
        std::fs::create_dir_all(&as_dir).unwrap();
        let error = read_servers(&config_file(Client::Opencode, SourceScope::Global, as_dir))
            .expect_err("directory");
        assert_eq!(error.reason, "not a regular file");

        // The cap is 16 MiB, so a 17 MiB file is skipped and a small one is not.
        let big = dir.join("big.json");
        std::fs::write(&big, vec![b' '; 16 * 1024 * 1024 + 1]).unwrap();
        let error = read_servers(&config_file(Client::Opencode, SourceScope::Global, big))
            .expect_err("large");
        assert!(error.reason.contains("larger than"), "{error}");
        std::fs::remove_dir_all(&dir).ok();
    }

    fn config_file(client: Client, scope: SourceScope, path: PathBuf) -> ConfigFile {
        ConfigFile {
            client,
            scope,
            path,
            project_root: None,
        }
    }
}
