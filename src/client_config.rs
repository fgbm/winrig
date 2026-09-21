//! Запись определения MCP-сервера в конфиги клиентов (ADR-0009, ADR-0012).
//!
//! `winrig setup --write-config <client>` добавляет запись `winrig`, не трогая
//! остальные записи файла. Уровень записи задаёт `--scope` (ADR-0012):
//! `global` — пользовательский конфиг клиента, `project` — конфиг в корне
//! текущего проекта. Для клиентов, умеющих подставлять содержимое файла
//! (`{file:...}` в opencode), токен выносится в отдельный файл `0600`; для
//! остальных запись содержит токен как значение, а сам конфиг остаётся с
//! правами клиента.
//!
//! Форматы подтверждены по документации клиентов: opencode — ключ `mcp` с
//! записями `{type, url|command, headers|environment}`; Claude Code —
//! `mcpServers` в `~/.claude.json` (global) или `.mcp.json` (project); Codex —
//! `[mcp_servers.<name>]` в `~/.codex/config.toml` или `.codex/config.toml`;
//! Cursor — `mcpServers` в `~/.cursor/mcp.json` или `.cursor/mcp.json`.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use crate::paths::PathError;
use crate::profile::ProfileError;

/// Поддерживаемый клиент записи конфигурации.
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

/// Уровень записи конфига клиента (ADR-0012).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Пользовательский конфиг клиента, действующий во всех проектах.
    Global,
    /// Конфиг в корне текущего проекта.
    Project,
}

impl Scope {
    /// Каноническое имя уровня.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Project => "project",
        }
    }

    /// Истина, если уровень проектный.
    #[must_use]
    pub fn is_project(self) -> bool {
        matches!(self, Self::Project)
    }
}

impl Client {
    /// Разбирает имя клиента из флага `--write-config`.
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

    /// Каноническое имя клиента.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Opencode => "opencode",
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::Cursor => "cursor",
        }
    }

    /// Путь к глобальному конфигу клиента в домашнем каталоге.
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

    /// Путь к проектному конфигу клиента в корне проекта (ADR-0012).
    #[must_use]
    pub fn project_config_path(self, root: &Path) -> PathBuf {
        match self {
            Self::Opencode => root.join("opencode.json"),
            Self::ClaudeCode => root.join(".mcp.json"),
            Self::Codex => root.join(".codex").join("config.toml"),
            Self::Cursor => root.join(".cursor").join("mcp.json"),
        }
    }

    /// Истина, если клиент умеет подставлять содержимое файла ссылкой.
    #[must_use]
    pub fn supports_file_reference(self) -> bool {
        matches!(self, Self::Opencode)
    }
}

/// Ошибка записи конфига клиента.
#[derive(Debug)]
pub enum ClientConfigError {
    /// Клиент неизвестен.
    UnknownClient {
        /// Переданное имя.
        name: String,
    },
    /// Домашний каталог недоступен.
    NoHome,
    /// Для токена opencode на project-уровне не задан каталог состояния.
    NoStateDir,
    /// Файл существует, но не разобран.
    Unreadable {
        /// Путь к файлу.
        path: PathBuf,
        /// Причина.
        reason: String,
    },
    /// Ошибка ввода-вывода.
    Io {
        /// Путь.
        path: PathBuf,
        /// Причина.
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

/// Определение MCP-сервера для печати и записи.
#[derive(Debug, Clone)]
pub struct ServerDefinition {
    /// Команда запуска (абсолютный путь к бинарю, затем `stdio`).
    pub command: String,
    /// Имя профиля.
    pub profile: String,
    /// Токен доступа.
    pub token: String,
    /// Абсолютный каталог профилей; передаётся клиенту, чтобы он нашёл профиль
    /// даже когда каталог отличается от стандартного (ADR-0009).
    pub profile_dir: Option<String>,
    /// Абсолютный **корень** каталога состояния; передаётся клиенту по той же
    /// причине. Имя профиля к нему добавляет сервер, и ровно один раз: в
    /// определение уходит корень, иначе `WINRIG_STATE_DIR` и реальный каталог
    /// состояния разъезжаются на один уровень (TR-PRF-15).
    pub state_root: Option<String>,
    /// Явное имя записи MCP-сервера (`--server-name`). Без него ключ берётся у
    /// существующей записи на тот же профиль, иначе [`DEFAULT_SERVER_NAME`].
    pub server_name: Option<String>,
}

/// Имя записи MCP-сервера по умолчанию.
pub const DEFAULT_SERVER_NAME: &str = "winrig";

impl ServerDefinition {
    /// Имя записи без оглядки на существующий конфиг (печать определения).
    fn plain_key(&self) -> String {
        self.server_name
            .clone()
            .unwrap_or_else(|| DEFAULT_SERVER_NAME.to_owned())
    }

    /// Ключ записи в существующем конфиге клиента (TR-PRF-14).
    ///
    /// Приоритет: явное `--server-name`; ключ уже объявленной записи на тот же
    /// профиль; [`DEFAULT_SERVER_NAME`]. Средний шаг обязателен: вторая запись
    /// на один профиль поднимает второй процесс, тот ловит lock профиля и
    /// выходит с кодом 2, а клиент показывает `Connection closed`.
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

    /// Пары «переменная окружения → значение» для запуска сервера.
    fn environment(&self) -> Vec<(&'static str, String)> {
        let mut env = vec![("WINRIG_TOKEN", self.token.clone())];
        if let Some(dir) = &self.profile_dir {
            env.push(("WINRIG_PROFILE_DIR", dir.clone()));
        }
        if let Some(dir) = &self.state_root {
            env.push(("WINRIG_STATE_DIR", dir.clone()));
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

    /// Печатает JSON-определение сервера.
    ///
    /// # Errors
    ///
    /// Ошибка сериализации (недостижима для корректных значений).
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

    /// Записывает токен в отдельный файл `0600` рядом с конфигом клиента.
    ///
    /// Каталог не трогается, если существует: это может быть чужой каталог
    /// конфигов. # Errors
    ///
    /// [`ClientConfigError::Io`] при ошибке записи.
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

/// Возвращает корень проекта: ближайший предок `start` с `.git`, иначе `start`.
///
/// `.git` может быть каталогом репозитория или файлом воркtree; оба случая
/// означают корень. Так запуск из подкаталога монорепозитория попадает в
/// корень, а не в текущий каталог (ADR-0012).
#[must_use]
pub fn find_project_root(start: &Path) -> PathBuf {
    start
        .ancestors()
        .find(|dir| dir.join(".git").exists())
        .map_or_else(|| start.to_path_buf(), Path::to_path_buf)
}

/// Пишет запись сервера в конфиг клиента, не трогая другие записи.
///
/// # Errors
///
/// [`ClientConfigError`] при разборе существующего файла или записи.
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

/// Профиль записи opencode: команда — массив, профиль идёт следом за флагом.
fn opencode_profile(entry: &Value) -> Option<&str> {
    profile_after_flag(entry.get("command")?.as_array()?)
}

/// Профиль записи со схемой `mcpServers`: профиль лежит в `args`.
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
    // На project-уровне токен уходит в приватный state-каталог профиля, чтобы
    // секрет не оказался в дереве репозитория (ADR-0012).
    let token_dir = match scope {
        Scope::Global => path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf(),
        // Тот же путь, что соберёт сервер из `WINRIG_STATE_DIR`: корень плюс
        // имя профиля, один раз (TR-PRF-15).
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
    let key = definition.key_in(&mcp, opencode_profile);
    mcp.insert(
        key,
        json!({
            "type": "local",
            "command": [definition.command, "stdio", "--profile", definition.profile],
            "environment": Value::Object(environment),
            // Схема opencode использует `disabled`; отсутствие поля = включён.
            "disabled": false
        }),
    );
    root.insert("mcp".to_owned(), Value::Object(mcp));
    // Токен вынесен в отдельный файл, поэтому сам конфиг остаётся как был.
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
    // Токен записан значением в самом конфиге — делаем файл приватным (DR-4).
    write_json(path, &Value::Object(root), true)
}

/// Пишет TOML-конфиг Codex, добавляя секции `[mcp_servers.winrig]` и
/// `[mcp_servers.winrig.env]`.
///
/// Реализовано без TOML-редактора: любая существующая секция под префиксом
/// `[mcp_servers.winrig` удаляется вместе со своими строками до следующего
/// заголовка верхнего вида, остальные строки файла сохраняются как есть.
/// Поэтому повторная запись не оставляет ни старого токена, ни дубликата
/// заголовка (AC-PRF-15).
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
            // Пропускаем только секции winrig; любой другой заголовок начинает
            // сохраняемый блок.
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
    // Токен записан значением в самом конфиге — делаем файл приватным (DR-4).
    crate::private_fs::apply_private_file_mode(path);
    Ok(())
}

/// Ключ секции Codex для того же профиля (TR-PRF-14).
///
/// TOML-редактора здесь нет, поэтому секции разбираются построчно: заголовок
/// `[mcp_servers.NAME]` или `[mcp_servers.NAME.env]` открывает блок, а строка
/// `args` с нужным профилем внутри блока и выдаёт имя.
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
    // DR-4: там, где токен записан значением, файл делаем приватным на Unix.
    if protect {
        crate::private_fs::apply_private_file_mode(path);
    }
    Ok(())
}

/// Преобразует ошибку профиля в текст CLI (для единого вывода).
pub fn profile_error_text(error: &ProfileError) -> String {
    error.to_string()
}

/// Преобразует ошибку каталогов в текст CLI.
pub fn path_error_text(error: &PathError) -> String {
    error.to_string()
}

/// Записывает конфиг клиента в явный путь (тестовый шов без домашнего каталога).
///
/// # Errors
///
/// [`ClientConfigError`] при разборе существующего файла или записи.
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
        }
    }

    /// Определение несёт каталоги профиля и состояния, иначе клиент с
    /// нестандартным расположением не найдёт профиль.
    #[test]
    fn definition_carries_directories() {
        let rendered = definition().to_json().expect("json");
        assert!(rendered.contains("WINRIG_PROFILE_DIR"));
        assert!(rendered.contains("WINRIG_STATE_DIR"));
        assert!(rendered.contains("/tmp/profiles"));
        assert!(rendered.contains("/tmp/state"));
    }

    /// AC-PRF-66: `WINRIG_STATE_DIR` — корень состояния, а токен лежит там,
    /// куда сервер соберёт путь сам. Иначе имя профиля добавляется дважды и
    /// lock уезжает мимо каталога, объявленного в конфиге.
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
            "в конфиг уходит корень, без имени профиля"
        );
        let token_reference = environment["WINRIG_TOKEN"].as_str().unwrap();
        let expected = state.join("corp").join("winrig-token");
        assert_eq!(
            token_reference,
            format!("{{file:{}}}", expected.display()),
            "ссылка на токен указывает в каталог профиля"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-64: тот же профиль уже объявлен под своим ключом — запись
    /// обновляется на месте. Вторая запись подняла бы второй процесс на один
    /// профиль, тот поймал бы lock и клиент увидел бы `Connection closed`.
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
        assert_eq!(keys, vec!["winrig-tm"], "ключ сохраняется, дубля нет");
        assert_eq!(
            value["mcp"]["winrig-tm"]["command"][0],
            "/usr/local/bin/winrig"
        );
    }

    /// AC-PRF-64: чужой профиль под своим ключом не трогаем — это другой
    /// сервер, и lock он не делит.
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
        assert_eq!(mcp.len(), 2, "профиль lab остаётся, corp добавляется");
        assert_eq!(mcp["winrig-lab"]["command"][2], "--profile");
        assert_eq!(mcp["winrig"]["command"][3], "corp");
    }

    /// AC-PRF-65: `--server-name` задаёт ключ явно.
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

    /// AC-PRF-64: то же для клиентов со схемой `mcpServers`.
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

    /// AC-PRF-15: другие записи файла не тронуты, токен есть, пароля нет.
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

    /// AC-PRF-15: Claude Code и Cursor получают mcpServers с env-токеном.
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

    /// AC-PRF-15: Codex получает секцию `[mcp_servers.winrig]`; существующая
    /// одноимённая секция заменяется, прочие строки сохраняются.
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

    /// AC-PRF-15: повторная запись Codex заменяет и `.env`-секцию: старого
    /// токена и дубликата заголовка не остаётся.
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

    /// AC-PRF-15: повторная запись Claude/Cursor заменяет запись, не плодит её.
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

    /// AC-PRF-15: битый конфиг Codex не затирается молча.
    #[test]
    fn codex_broken_file_is_reported_not_overwritten() {
        let dir = temp_dir("codex-broken");
        let path = dir.join("config.toml");
        // Файл читается, но содержит уже занятый чужой заголовок, который
        // не должен быть потерян.
        std::fs::write(&path, "[mcp_servers.winrig]\nbroken\n").unwrap();
        write_client_config_at(Client::Codex, &path, Scope::Global, &definition()).expect("write");
        let rendered = std::fs::read_to_string(&path).unwrap();
        assert_eq!(rendered.matches("[mcp_servers.winrig]").count(), 1);
        assert!(!rendered.contains("broken"));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-15: неизвестный клиент отвергается без изменений файлов.
    #[test]
    fn unknown_client_is_rejected() {
        assert!(Client::parse("vscode").is_none());
        assert_eq!(Client::parse("OpenCode"), Some(Client::Opencode));
        assert_eq!(Client::parse("claude-code"), Some(Client::ClaudeCode));
    }

    /// Там, где токен записан значением, файл конфига приватный на Unix;
    /// opencode не трогает права своего конфига (токен в отдельном файле).
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

    /// Нечитаемый (не-UTF-8) конфиг не затирается молча.
    #[test]
    fn unreadable_config_is_reported_not_overwritten() {
        let dir = temp_dir("unreadable");
        let path = dir.join("config.toml");
        // Невалидный UTF-8: read_to_string вернёт ошибку.
        std::fs::write(&path, [0xff, 0xfe, 0x00, 0x01]).unwrap();
        let error = write_client_config_at(Client::Codex, &path, Scope::Global, &definition())
            .expect_err("must refuse to overwrite");
        assert!(matches!(error, ClientConfigError::Io { .. }), "{error}");
        assert_eq!(std::fs::read(&path).unwrap(), [0xff, 0xfe, 0x00, 0x01]);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// ADR-0012: корень проекта — ближайший предок с `.git`, иначе сам каталог;
    /// `.git`-файл воркtree считается корнем наравне с каталогом.
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

    /// ADR-0012: проектный путь различается по клиенту.
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

    /// AC-PRF-61: на project-уровне токен opencode уходит в приватный
    /// state-каталог, а не в дерево проекта.
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
        // TR-PRF-15: каталог профиля собирается ровно один раз — сервер
        // получает корень и сам добавит имя профиля.
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

    /// ADR-0012: project-уровень opencode без state-каталога отвергается, а не
    /// кладёт токен в проект.
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
