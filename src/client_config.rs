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

use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use crate::paths::PathError;
use crate::profile::ProfileError;

/// Configuration format this tool can write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// Absolute **root** of the state directory; passed to the client for the
    /// same reason. The server adds the profile name to it, exactly once: the
    /// definition carries the root, otherwise `WINRIG_STATE_DIR` and the real
    /// state directory drift apart by one level (TR-PRF-15).
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

    /// Which key the new entry takes in an existing client config (TR-PRF-14).
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

/// The profile of an opencode entry: the command is an array and the profile follows the flag.
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

/// Turns a profile error into CLI text (for one output shape).
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
}
