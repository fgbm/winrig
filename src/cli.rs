//! CLI `winrig`: подкоманды serve, stdio, setup, list, rotate, forget (ADR-0009).
//!
//! Разбор аргументов отделён от выполнения, чтобы точки входа было удобно
//! тестировать. `setup` вводит пароль без эха, генерирует токен и печатает его
//! ровно один раз вместе с определением MCP-сервера; по флагу записывает это
//! определение в конфиг выбранного клиента, не трогая другие записи.

use clap::{Parser, Subcommand};

use crate::client_config::{Client, Scope, ServerDefinition};

/// Аргументы командной строки.
#[derive(Debug, Parser)]
#[command(
    name = "winrig",
    about = "MCP server for remote Windows administration over WinRM/NTLM",
    version
)]
pub struct Cli {
    /// Подкоманда; без неё сервер запускается в режиме HTTP.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Секрет, переданный аргументом CLI.
///
/// `Debug` редактирует значение: аргументы попадают в сообщения об ошибках,
/// журналы и `ps`, и секрет не должен утекать ни туда, ни туда (DR-4).
#[derive(Clone)]
pub struct SecretArg(String);

impl SecretArg {
    /// Значение секрета.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretArg([REDACTED])")
    }
}

impl std::str::FromStr for SecretArg {
    type Err = std::convert::Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self(value.to_owned()))
    }
}

/// Подкоманды `winrig`.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the HTTP server on /mcp (default when no subcommand is given).
    Serve {
        /// Profile name; omitted when exactly one profile exists.
        #[arg(long)]
        profile: Option<String>,
        /// Port to listen on; overrides WINRIG_PORT.
        #[arg(long, value_name = "PORT")]
        port: Option<u16>,
        /// Bind address; overrides WINRIG_BIND_HOST.
        #[arg(long, value_name = "ADDR")]
        host: Option<String>,
        /// Access token for the profile; overrides WINRIG_TOKEN. Passing a
        /// secret as an argument exposes it in the process list; prefer the
        /// environment or the client config when possible.
        #[arg(long, value_name = "TOKEN")]
        token: Option<SecretArg>,
        /// Shared secret for the header path; overrides WINRIG_AUTH_TOKEN.
        /// Passing a secret as an argument exposes it in the process list.
        #[arg(long, value_name = "SECRET")]
        auth_token: Option<SecretArg>,
    },
    /// Run the MCP server over stdin/stdout; requires WINRIG_TOKEN.
    Stdio {
        /// Profile name; omitted when exactly one profile exists.
        #[arg(long)]
        profile: Option<String>,
    },
    /// Create an encrypted profile, print its token once.
    Setup {
        /// Profile name, e.g. 'corp'.
        name: String,
        /// AD account in DOMAIN\\user form.
        #[arg(long)]
        user: Option<String>,
        /// Replace an existing profile.
        #[arg(long)]
        overwrite: bool,
        /// Write the server definition into this client's config.
        #[arg(long, value_name = "CLIENT")]
        write_config: Option<String>,
        /// Config level for --write-config: 'global' (user-wide) or 'project'
        /// (current project). Asked interactively when omitted; required in a
        /// non-interactive run.
        #[arg(long, value_name = "SCOPE", value_parser = parse_scope)]
        scope: Option<Scope>,
        /// Name of the MCP server entry. Defaults to the entry that already
        /// serves this profile, or 'winrig' when there is none.
        #[arg(long, value_name = "NAME")]
        server_name: Option<String>,
        /// Hosts the server may connect to, written as WINRIG_ALLOWED_HOSTS:
        /// comma-separated names or IPs, '.suffix' entries, or '*' for any
        /// host. Without it the entry has no list and only loopback is allowed.
        #[arg(long, value_name = "HOSTS", value_parser = parse_allowed_hosts)]
        allowed_hosts: Option<String>,
    },
    /// List profiles without secrets.
    List {
        /// Print the list as JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Re-encrypt a profile under a fresh token.
    Rotate {
        /// Profile name.
        name: String,
    },
    /// Delete a profile.
    Forget {
        /// Profile name.
        name: String,
    },
}

/// Строит определение MCP-сервера для печати и записи.
///
/// Каталоги профилей и состояния передаются клиенту, чтобы сервер нашёл профиль
/// даже при нестандартном расположении (ADR-0009).
#[must_use]
pub fn server_definition(
    binary: std::path::PathBuf,
    profile: &str,
    token: &str,
    profile_dir: &std::path::Path,
    state_root: &std::path::Path,
    server_name: Option<&str>,
    allowed_hosts: Option<&str>,
) -> ServerDefinition {
    ServerDefinition {
        command: binary.to_string_lossy().into_owned(),
        profile: profile.to_owned(),
        token: token.to_owned(),
        profile_dir: Some(profile_dir.to_string_lossy().into_owned()),
        state_root: Some(state_root.to_string_lossy().into_owned()),
        server_name: server_name.map(str::to_owned),
        allowed_hosts: allowed_hosts.map(str::to_owned),
    }
}

/// Разбирает клиента записи конфига.
///
/// # Errors
///
/// Текст ошибки с перечнем допустимых имён.
pub fn parse_client(value: &str) -> Result<Client, String> {
    Client::parse(value).ok_or_else(|| {
        format!("unknown client {value:?}; expected one of opencode, claude-code, codex, cursor")
    })
}

/// Разбирает `--allowed-hosts` в значение `WINRIG_ALLOWED_HOSTS` (TR-PRF-17).
///
/// Грамматика та же, что у переменной (`policy::parse_allowed_hosts`). Флаг,
/// заданный без единого хоста, — ошибка: без флага сервер и так разрешает
/// только loopback.
///
/// # Errors
///
/// Текст ошибки, называющий флаг и ожидаемую форму.
pub fn parse_allowed_hosts(value: &str) -> Result<String, String> {
    let refuse = |detail: String| {
        format!(
            "invalid --allowed-hosts {value:?}: {detail}; expected {}",
            crate::policy::ALLOWED_HOSTS_FORM
        )
    };
    let entries = crate::policy::parse_allowed_hosts(value)
        .map_err(|entry| refuse(format!("entry {entry:?} is not valid")))?;
    if entries.is_empty() {
        return Err(refuse("no hosts given".to_owned()));
    }
    Ok(entries.join(","))
}

/// Разбирает уровень записи конфига из флага `--scope` (ADR-0012).
///
/// # Errors
///
/// Текст ошибки с перечнем допустимых значений.
pub fn parse_scope(value: &str) -> Result<Scope, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "global" | "g" => Ok(Scope::Global),
        "project" | "p" => Ok(Scope::Project),
        _ => Err(format!(
            "unknown scope {value:?}; expected one of global, project"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AC-PRF-68: список приводится к той форме, которую читает сервер.
    #[test]
    fn allowed_hosts_are_normalized() {
        assert_eq!(
            parse_allowed_hosts(" Host1 , .Corp.Example,127.0.0.1,[::1] ").as_deref(),
            Ok("host1,.corp.example,127.0.0.1,[::1]")
        );
        assert_eq!(parse_allowed_hosts("*").as_deref(), Ok("*"));
        assert_eq!(parse_allowed_hosts("a,,b").as_deref(), Ok("a,b"));
    }

    /// AC-PRF-68: неверный список отвергается с именем флага и формой.
    #[test]
    fn malformed_allowed_hosts_name_the_flag() {
        for raw in ["", " , ", "*.corp.example", "host one", "host\\x", "."] {
            let error = parse_allowed_hosts(raw).expect_err(raw);
            assert!(error.contains("--allowed-hosts"), "{raw:?}: {error}");
        }
    }
}
