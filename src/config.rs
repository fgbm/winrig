//! Единая точка чтения и валидации конфигурации (DR-8, ADR-0004).
//!
//! Любая невалидная переменная окружения останавливает старт: [`load_config`]
//! возвращает [`ConfigError`] с именем переменной и ожидаемым форматом.
//! Секреты в сообщениях не раскрываются. Значения читаются через замыкание
//! `Fn(&str) -> Option<String>`, а не напрямую из `std::env`, чтобы
//! конфигурацию можно было тестировать без изменения окружения процесса.

use std::fmt;

/// Минимальный допустимый номер TCP-порта.
pub const MIN_PORT: u16 = 1;
/// Максимальный допустимый номер TCP-порта.
pub const MAX_PORT: u16 = 65535;

const TRUE_VALUES: [&str; 4] = ["1", "true", "yes", "on"];
const FALSE_VALUES: [&str; 4] = ["0", "false", "no", "off"];

/// Источник значений переменных окружения.
pub type Env = dyn Fn(&str) -> Option<String>;

/// Невалидная конфигурация: сообщение называет переменную и формат.
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

/// Уровень журнала сервера.
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
    /// Каноническая запись для подсистемы логирования.
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

    /// Директива для `tracing_subscriber::EnvFilter`.
    ///
    /// `EnvFilter` знает уровни `trace/debug/info/warn/error`; `WARNING` и
    /// `CRITICAL` для него — не уровень, а имя target, поэтому передавать
    /// `as_str()` напрямую нельзя: фильтр принимает строку за target и глушит
    /// весь остальной журнал. Здесь уровни отображаются явно.
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

/// Провалидированные параметры окружения.
///
/// `Debug` реализован вручную: секреты (`mcp_auth_token`, `profile_token`) не
/// должны попасть в случайный вывод через `{:?}` (DR-4).
#[derive(Clone)]
pub struct AppConfig {
    /// Общий секрет для пути по заголовкам (`X-AD-User`); необязателен, если
    /// используется профиль (DR-1, ADR-0009).
    pub mcp_auth_token: Option<String>,
    /// Адрес, на котором слушает HTTP-сервер.
    pub mcp_bind_host: String,
    /// TCP-порт HTTP-сервера.
    pub mcpo_port: u16,
    /// Имя профиля; `None` — выбрать единственный доступный (ADR-0009).
    pub profile_name: Option<String>,
    /// Токен доступа к профилю; в stdio-режиме обязателен (ADR-0009).
    pub profile_token: Option<String>,
    /// Время жизни кэшированного пароля AD в покое, секунды (0 — без истечения).
    pub ad_password_idle_ttl_seconds: u64,
    /// Каталог журналов и аудита; `None` — каталог состояния профиля.
    pub log_dir: Option<String>,
    /// Уровень серверного журнала.
    pub log_level: LogLevel,
    /// Размер журнала до ротации, байты.
    pub log_max_bytes: u64,
    /// Сколько ротированных файлов хранить.
    pub log_backup_count: u32,
    /// Порог отказов AD, после которого пароль временно не предъявляется (TR-SEC-01).
    pub ad_lockout_max_attempts: u32,
    /// Окно блокировки после отказов, секунды.
    pub ad_lockout_window_seconds: u64,
    /// Минимальная длина секрета, редактируемого в ответе агенту.
    pub secret_redact_min_length: usize,
    /// Allowlist хостов; пустой список разрешает всё (TR-SEC-05).
    pub allowed_hosts: Vec<String>,
    /// Разрешено ли понижение проверки TLS (TR-SEC-06).
    pub allow_insecure_tls: bool,
    /// Сколько символов вывода каждого вызова хранить в аудите.
    pub audit_max_output_chars: usize,
    /// Писать ли в аудит тело команды и вывода или только метаданные.
    pub audit_log_body: bool,
    /// Сколько секунд ждать ответа на запрос подтверждения модификации.
    pub confirm_timeout_seconds: u64,
    /// Время жизни кэшированных SFTP-учётных данных в покое, секунды.
    pub sftp_cred_idle_ttl_seconds: u64,
    /// Разрешена ли запись файлов на хост (TR-FS-01, ADR-0013).
    pub allow_file_write: bool,
    /// Предел размера записываемого содержимого, байты (TR-FS-04).
    pub max_write_bytes: usize,
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
            .field(
                "sftp_cred_idle_ttl_seconds",
                &self.sftp_cred_idle_ttl_seconds,
            )
            .finish()
    }
}

/// Читает переменную, обрезая пробелы; пустая строка трактуется как отсутствие.
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
            "{name}={raw:?} is not a valid integer; expected {expected}"
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
        "{name}={raw:?} is not a valid boolean; expected one of true/false, 1/0, yes/no, on/off"
    )))
}

fn read_log_level(env: &Env, name: &str, default: LogLevel) -> Result<LogLevel, ConfigError> {
    let Some(raw) = read(env, name) else {
        return Ok(default);
    };
    LogLevel::parse(&raw).ok_or_else(|| {
        ConfigError::new(format!(
            "{name}={raw:?} is not a valid log level; expected one of DEBUG, ERROR, INFO, WARNING, CRITICAL"
        ))
    })
}

fn read_allowed_hosts(env: &Env) -> Vec<String> {
    match read(env, "WINRIG_ALLOWED_HOSTS") {
        Some(raw) => raw
            .split(',')
            .map(|item| item.trim().to_ascii_lowercase())
            .filter(|item| !item.is_empty())
            .collect(),
        None => Vec::new(),
    }
}

fn load_auth_token(env: &Env) -> Option<String> {
    read(env, "WINRIG_AUTH_TOKEN")
}

/// Имя выбранного профиля; пустая строка трактуется как отсутствие.
fn read_profile_name(env: &Env) -> Option<String> {
    read(env, "WINRIG_PROFILE")
}

/// Токен доступа к профилю; в stdio-режиме обязателен.
fn read_profile_token(env: &Env) -> Option<String> {
    read(env, "WINRIG_TOKEN")
}

/// Читает целое и преобразует его в целевой тип без паники.
///
/// Верхняя граница типа проверяется через `TryFrom`, поэтому слишком большое
/// значение даёт [`ConfigError`] с именем переменной, а не панику (DR-8).
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

/// Старые имена переменных, заменённые на нотацию `WINRIG_*` (ADR-0010).
///
/// Чистый разрыв: если задано старое имя, старт отказывает с указанием
/// нового, чтобы оператор не думал, что значение применилось.
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

/// Отказывает, если задано любое из старых имён переменных.
///
/// Проверяются все старые имена сразу, чтобы сообщение перечислило полный
/// список найденных, а не первое.
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
        "environment variable names changed to the WINRIG_* notation; rename: {}",
        found.join(", ")
    )))
}

/// Читает и валидирует переменные из переданного источника.
///
/// # Errors
///
/// Возвращает [`ConfigError`] при первом старом имени переменной или первой
/// невалидной переменной, называя её.
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
        allowed_hosts: read_allowed_hosts(env),
        allow_insecure_tls: read_bool(env, "WINRIG_ALLOW_INSECURE_TLS", true)?,
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
        // Нижняя граница — один кусок: меньший предел означал бы инструмент,
        // который отказывает всегда (ADR-0013 §8, §11).
        max_write_bytes: read_uint(
            env,
            "WINRIG_MAX_WRITE_BYTES",
            64 * 1024,
            Some(crate::ps::WRITE_CHUNK_BYTES as i64),
            None,
        )?,
    })
}

/// Читает и валидирует переменные окружения процесса.
///
/// # Errors
///
/// Возвращает [`ConfigError`] при первой невалидной переменной, называя её.
pub fn load_config() -> Result<AppConfig, ConfigError> {
    load_config_from(&|name| std::env::var(name).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Источник значений: отсутствующие ключи дают `None`.
    ///
    /// `+ use<>` обязателен: в Rust 2024 `impl Trait` иначе захватывает
    /// лайфтайм аргумента, и временный срез переживает вызов.
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
        assert!(config.allow_insecure_tls);
        assert_eq!(config.audit_max_output_chars, 2000);
        assert!(config.audit_log_body);
        assert_eq!(config.sftp_cred_idle_ttl_seconds, 3600);
        assert_eq!(config.confirm_timeout_seconds, 300);
        // TR-FS-01: запись файла выключена, пока оператор её не включил.
        assert!(!config.allow_file_write);
        // TR-FS-04: предел терпения, а не протокола (ADR-0013 §11).
        assert_eq!(config.max_write_bytes, 64 * 1024);
    }

    /// TR-FS-01: настройка включается обычными булевыми значениями.
    #[test]
    fn file_write_is_switched_by_the_operator() {
        let env = source(&with(&[("WINRIG_ALLOW_FILE_WRITE", "true")]));
        assert!(load_config_from(&env).expect("valid").allow_file_write);
        let env = source(&with(&[("WINRIG_ALLOW_FILE_WRITE", "0")]));
        assert!(!load_config_from(&env).expect("valid").allow_file_write);
    }

    /// TR-FS-04: предел не может быть меньше одного куска — иначе инструмент
    /// отказывал бы всегда, а причина читалась бы как ошибка размера.
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

    /// AC-PRF-47: без профиля и без токена конфигурация читается, решение
    /// «хотя бы один секрет» принимает точка входа.
    #[test]
    fn no_secret_is_accepted_by_parser() {
        let env = source(&[]);
        let config = load_config_from(&env).expect("valid");
        assert_eq!(config.mcp_auth_token, None);
        assert_eq!(config.profile_name, None);
        assert_eq!(config.profile_token, None);
    }

    /// AC-PRF-21: токены не выводятся через Debug.
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

    /// AC-PRF-04/42: имя профиля и токен читаются из окружения.
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

    /// AC-PRF-09: LOG_DIR остаётся явным переопределением.
    #[test]
    fn log_dir_override_is_read() {
        let env = source(&with(&[("WINRIG_LOG_DIR", "/tmp/winrig-logs")]));
        assert_eq!(
            load_config_from(&env).expect("valid").log_dir.as_deref(),
            Some("/tmp/winrig-logs")
        );
    }

    /// Чистый разрыв: старое имя переменной отказывает старту и называет новое.
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

    /// Несколько старых имён перечисляются в одном сообщении.
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

    /// Новые имена читаются, старые — нет.
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
            ("WINRIG_ALLOW_INSECURE_TLS", "false"),
        ]));
        let config = load_config_from(&env).expect("valid");
        assert_eq!(config.ad_lockout_max_attempts, 7);
        assert_eq!(config.ad_lockout_window_seconds, 60);
        assert_eq!(config.secret_redact_min_length, 8);
        assert!(!config.allow_insecure_tls);
    }

    #[test]
    fn allowed_hosts_parsed_and_case_folded() {
        let env = source(&with(&[(
            "WINRIG_ALLOWED_HOSTS",
            " HOST1 , *.Example.com ,host2,, ",
        )]));
        let config = load_config_from(&env).expect("valid");
        assert_eq!(config.allowed_hosts, ["host1", "*.example.com", "host2"]);
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
        // `WARNING`/`CRITICAL` не существуют для EnvFilter: он принял бы их за
        // target и отключил журнал. Директива обязана быть валидным уровнем.
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
        // DR-8: слишком большое значение не должно паниковать (было exit 101).
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
}
