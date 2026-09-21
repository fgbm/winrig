//! Оркестрация `winrig`: подкоманды, журналирование, режимы serve/stdio (ADR-0009).
//!
//! Библиотечный слой держит всю логику, поэтому CLI-пути, журналирование и оба
//! режима покрываются тестами без запуска процесса. `src/main.rs` — тонкая
//! обёртка, возвращающая код выхода.

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

/// Ошибка верхнего уровня с кодом выхода.
pub enum StartupError {
    /// Невалидная конфигурация или профиль: код 2.
    Usage(String),
    /// Профиль отвергнут дважды: код 3 (AC-PRF-56).
    PasswordRejected(String),
    /// Прочие ошибки времени выполнения: код 1.
    Runtime(String),
}

impl StartupError {
    /// Код выхода процесса.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => 2,
            Self::PasswordRejected(_) => 3,
            Self::Runtime(_) => 1,
        }
    }
}

impl std::fmt::Display for StartupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(message) | Self::PasswordRejected(message) | Self::Runtime(message) => {
                f.write_str(message)
            }
        }
    }
}

/// Разбирает аргументы и выполняет подкоманду. Возвращает код выхода.
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

/// Выполняет разобранную команду.
///
/// # Errors
///
/// [`StartupError`] с кодом выхода.
pub fn run(cli: Cli) -> Result<(), StartupError> {
    match cli.command {
        Some(Command::Setup {
            name,
            user,
            overwrite,
            write_config,
            scope,
            server_name,
        }) => setup_command(
            &name,
            user.as_deref(),
            overwrite,
            write_config.as_deref(),
            scope,
            server_name.as_deref(),
        ),
        Some(Command::List { json }) => list_command(json),
        Some(Command::Rotate { name }) => rotate_command(&name),
        Some(Command::Forget { name }) => forget_command(&name),
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

/// Каталоги и конфигурация, общие для подкоманд.
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

/// AC-PRF-50: общий секрет не должен совпадать с токеном профиля.
fn ensure_auth_token_is_not_profile_key(
    config: &AppConfig,
    profile_path: &std::path::Path,
) -> Result<(), StartupError> {
    let Some(token) = config.mcp_auth_token.as_deref() else {
        return Ok(());
    };
    if profile::decrypts(profile_path, token) {
        return Err(StartupError::Usage(
            "WINRIG_AUTH_TOKEN must not be the profile access token: the profile key must not be \
             stored on the server"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Загружает профиль и привязывает его к процессу.
/// Причина отказа привязки профиля для журнала (AC-PRF-40/41). Значение
/// токена не участвует.
fn profile_bind_reason(error: &profile::ProfileError) -> &'static str {
    match error {
        profile::ProfileError::InvalidToken { .. } => "invalid profile token",
        profile::ProfileError::Corrupt { .. } => "profile file corrupt",
        profile::ProfileError::UnsupportedVersion { .. } => "profile version unsupported",
        _ => "profile load failed",
    }
}

/// Загружает профиль и привязывает его к процессу.
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
            // AC-PRF-40/41: причина различается в журнале; значение токена не
            // логируется.
            tracing::warn!(
                target: "winrig::auth",
                profile = %name,
                reason = profile_bind_reason(&error),
                "profile could not be bound"
            );
            StartupError::Usage(format!("profile error: {error}"))
        })
}

/// Разрешает имя профиля и держит lock процесса (AC-PRF-54).
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

/// Журналы без `WINRIG_LOG_DIR` идут в каталог состояния профиля (AC-PRF-08/09).
fn resolve_log_dir(config: &AppConfig, profile_state: &std::path::Path) -> std::path::PathBuf {
    config
        .log_dir
        .as_ref()
        .map_or_else(|| profile_state.to_path_buf(), std::path::PathBuf::from)
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
// Профильные подкоманды
// ---------------------------------------------------------------------------

/// Читает пароль без эха с терминала; без tty берёт строку из stdin.
///
/// В неинтерактивном запуске (скрипт, конвейер) эхо подавить нельзя, поэтому
/// пароль читается построчно из stdin — это используется и тестами.
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
) -> Result<(), StartupError> {
    use std::io::Write;

    let (locations, _config) = load()?;
    if name.trim().is_empty() {
        return Err(StartupError::Usage(
            "profile name must not be empty".to_owned(),
        ));
    }
    // Уровень записи решается до создания профиля: отказ не оставляет ни
    // профиля, ни конфига (ADR-0012).
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

    // Каталог состояния профиля нужен и серверу, и клиенту: кладём его в
    // определение, чтобы запись была самодостаточной (ADR-0009). В конфиг
    // уходит корень — имя профиля сервер добавит сам, один раз (TR-PRF-15).
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
                println!("The token is referenced from a private file, not inlined.");
            } else if scope.is_project() {
                eprintln!(
                    "warning: {} may be committed to version control and contains the profile \
                     token; keep it out of the repository",
                    written.display()
                );
            }
        }
        None => println!("Profile {name:?} created at {}", path.display()),
    }
    println!();
    println!("Access token (shown once, store it with the client; the server keeps no key):");
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

/// Разрешает уровень записи конфига: явный флаг, вопрос в терминале либо
/// отказ в неинтерактивном запуске (ADR-0012).
fn resolve_scope(explicit: Option<Scope>) -> Result<Scope, StartupError> {
    use std::io::IsTerminal;
    resolve_scope_with(explicit, std::io::stdin().is_terminal(), || {
        prompt("Write the winrig MCP entry to (g)lobal or (p)roject config? [g/p]: ")
    })
}

/// Тестируемое ядро выбора уровня: без флага и без терминала — отказ, а не
/// молчаливый выбор (ADR-0012).
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
            "no config scope: pass --scope global or --scope project (interactive input is not \
             available)"
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

/// Читает строку из stdin, печатая приглашение в stderr.
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

/// Печатает профили: таблицу с заголовками или JSON (`--json`).
///
/// Секретов нет ни в одном формате: только имя, учётная запись, время
/// создания и путь.
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
    println!("New access token (shown once):");
    println!("{token}");
    Ok(())
}

/// Разрешает путь профиля, отвергая имя с символами пути (AC-PRF-27).
///
/// Без этой проверки `rotate`/`forget` с именем вида `../victim` обратились бы
/// к файлу вне каталога профилей.
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
// Серверные режимы
// ---------------------------------------------------------------------------

/// Запускает HTTP-режим: с профилем (токен профиля) или только по общему
/// секрету. Хотя бы один секрет обязателен (AC-PRF-47).
///
/// `port`/`host` и `token`/`auth_token` — явные флаги CLI; они перекрывают
/// `WINRIG_PORT`/`WINRIG_BIND_HOST` и `WINRIG_TOKEN`/`WINRIG_AUTH_TOKEN`
/// (CLI > env). Секреты, переданные аргументом, видны в списке процессов,
/// поэтому их `Debug` редактирован.
fn run_serve(
    requested: Option<&str>,
    port: Option<u16>,
    host: Option<&str>,
    token: Option<&SecretArg>,
    auth_token: Option<&SecretArg>,
) -> Result<(), StartupError> {
    let (locations, mut config) = load()?;
    // Явные флаги перекрывают окружение.
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
            "no secret configured: create a profile and pass --token/WINRIG_TOKEN, or set \
             --auth-token/WINRIG_AUTH_TOKEN for the header path"
                .to_owned(),
        ));
    }

    // Профиль используется, если задан его токен; иначе работает только
    // путь по заголовкам с WINRIG_AUTH_TOKEN.
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

    let registry = registry_for(&config);
    let auth = AuthState {
        mcp_auth_token: config.mcp_auth_token.clone().map(Arc::new),
        profile: bound.clone(),
    };
    // Флаги CLI перекрывают окружение.
    let bind_host = host.unwrap_or(&config.mcp_bind_host).to_owned();
    let bind_port = port.unwrap_or(config.mcpo_port);
    tracing::info!(profile = %name, host = %bind_host, port = bind_port, "winrig starting (streamable-http on /mcp)");
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
    let (locations, config, name, _lock, state_dir) = prepare_profile(requested)?;
    let log_dir = resolve_log_dir(&config, &state_dir);
    setup_logging(&config, &log_dir)
        .map_err(|error| StartupError::Runtime(format!("logging error: {error}")))?;

    let bound = bind_profile(&locations, &name, &token_from(&config)?)?;
    let registry = registry_for(&config);
    tracing::info!(profile = %name, "winrig starting (stdio)");
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

/// Собирает и запускает axum-сервер с гейтом и MCP-эндпоинтом.
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

/// Обслуживает MCP по stdin/stdout до закрытия входа.
///
/// Если профиль отвергнут дважды (AC-PRF-56), фоновая проверка отменяет
/// сервис, и функция возвращает [`StartupError::PasswordRejected`] (код 3).
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

    // Наблюдатель за отказом профиля: stdio обслуживает один профиль, поэтому
    // достаточно периодической проверки его имени.
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

/// Итог stdio-сессии: отказ профиля даёт [`StartupError::PasswordRejected`]
/// (код 3), нормальное завершение — успех (AC-PRF-56).
fn stdio_outcome(profile_refused: bool) -> Result<(), StartupError> {
    if profile_refused {
        return Err(StartupError::PasswordRejected(
            "The profile password was rejected twice; the profile is refused until it is updated. \
             Run 'winrig setup' to change it."
                .to_owned(),
        ));
    }
    Ok(())
}

/// Ждёт SIGINT (Ctrl+C) или, на Unix, SIGTERM.
///
/// systemd останавливает процесс SIGTERM; без его обработки сервер завершался
/// без graceful shutdown, обрывая активные запросы.
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

/// Настраивает журналирование: stderr плюс файл с ротацией.
///
/// Аудит (`target = "winrig::audit"`) всегда пишется в отдельный файл на уровне
/// INFO, независимо от `WINRIG_LOG_LEVEL`.
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

/// Пишет и в stderr, и в файл: stderr виден в консоли, файл переживает рестарт.
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

/// Абсолютный путь к текущему бинарю.
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

    /// AC-PRF-08/09: журнал идёт в каталог состояния профиля либо в WINRIG_LOG_DIR.
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

    /// AC-PRF-50: общий секрет, совпавший с токеном профиля, отказывает старту.
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
        // Отличный секрет не мешает.
        let config = load_config_from(&|name| match name {
            "WINRIG_AUTH_TOKEN" => Some("different".to_owned()),
            _ => None,
        })
        .expect("config");
        assert!(ensure_auth_token_is_not_profile_key(&config, &path).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-47: без профиля и без токена HTTP-старт отказывает с кодом 2.
    #[test]
    fn serve_without_any_secret_is_refused() {
        // Проверяем ветку через конфиг: оба секрета пусты.
        let config = load_config_from(&|_| None::<String>).expect("config parses without secrets");
        assert!(config.mcp_auth_token.is_none());
        assert!(config.profile_token.is_none());
    }

    /// AC-PRF-40/41: причина отказа в журнале различает неверный токен и
    /// повреждённый файл.
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

    /// AC-PRF-42: токен не задан — отказ с упоминанием переменной.
    #[test]
    fn missing_profile_token_names_variable() {
        let config = load_config_from(&|_| None::<String>).expect("config parses without secrets");
        let error = token_from(&config).expect_err("must refuse");
        assert!(error.to_string().contains("WINRIG_TOKEN"));
    }

    /// AC-PRF-43: профиль не найден — отказ с именем и каталогом.
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

    /// AC-PRF-20: несколько профилей без имени — отказ.
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

    /// AC-PRF-56: отказ профиля переводит stdio-итог в код 3, обычное
    /// завершение — в 0.
    #[test]
    fn stdio_outcome_maps_refusal_to_code_three() {
        let refused = stdio_outcome(true).expect_err("must refuse");
        assert_eq!(refused.exit_code(), 3);
        assert!(matches!(refused, StartupError::PasswordRejected(_)));
        assert!(stdio_outcome(false).is_ok());
    }

    /// AC-PRF-27: `rotate`/`forget` отвергают имя с символами пути.
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

    /// AC-PRF-60: без флага и без терминала уровень не угадывается.
    #[test]
    fn resolve_scope_non_interactive_refuses_without_flag() {
        let error = resolve_scope_with(None, false, || unreachable!("must not read"))
            .expect_err("must refuse");
        assert!(error.to_string().contains("--scope"), "{error}");
    }

    /// AC-PRF-62: явный флаг не читает stdin.
    #[test]
    fn resolve_scope_prefers_explicit() {
        let scope = resolve_scope_with(Some(Scope::Project), false, || {
            unreachable!("must not read")
        })
        .map_err(|error| error.to_string())
        .expect("explicit");
        assert_eq!(scope, Scope::Project);
    }

    /// ADR-0012: интерактивный ответ принимает g/global/p/project.
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
}
