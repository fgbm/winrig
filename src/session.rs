//! Пул WinRM-сессий, кэш паролей, блокировка отказов и аудит.
//!
//! Порт `agent/session_manager.py`. Модуль знает о транспорте только через
//! трейт [`WinRmTransport`], поэтому автотесты работают на фиктивном
//! транспорте, записывающем переданные команды, и сети не касаются (ADR-0003,
//! AGENTS.md §4).
//!
//! Идентичность передаётся явно в каждый вызов: кэши ключуются по имени
//! пользователя, сессии — по паре (пользователь, `session_id`), поэтому
//! пользователь не видит объекты другого (DR-3).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};
use winrm_rs::{ExposeSecret, SecretString};

use crate::executor::{
    SEPARATOR, escape_log_field, neutralize_separator, redact, sanitize_log_value, truncate,
};

/// Порт WinRM по умолчанию для HTTP.
pub const DEFAULT_HTTP_PORT: u16 = 5985;
/// Порт WinRM по умолчанию для HTTPS.
pub const DEFAULT_HTTPS_PORT: u16 = 5986;

/// Преамбула, включающая UTF-8 вывод PowerShell.
///
/// `winrm-rs` задаёт `WINRS_CODEPAGE=65001` на уровне cmd-шелла, но
/// `powershell.exe` для перенаправленного вывода использует собственную
/// `[Console]::OutputEncoding`. На локализованном Windows она не вмещает
/// системный язык, и PowerShell заменяет неотображаемые символы на `?` ещё до
/// отправки байтов, поэтому никакое декодирование на этой стороне их не вернёт.
/// Обёртка в try/catch нужна для хоста без консоли (порт `UTF8_PREAMBLE` из
/// Python-версии).
pub const UTF8_PREAMBLE: &str = "try { [Console]::OutputEncoding = [Text.Encoding]::UTF8; \
     $OutputEncoding = [Text.Encoding]::UTF8 } catch { }; ";

/// Идентичность вызывающего пользователя (DR-2).
#[derive(Debug, Clone)]
pub struct UserIdentity {
    /// Имя учётной записи AD.
    pub username: String,
    /// Пароль из заголовка `X-AD-Password` или из профиля, если он был передан.
    pub password: Option<SecretString>,
    /// Откуда пришёл пароль: заголовок или профиль (ADR-0009).
    pub origin: IdentityOrigin,
}

impl UserIdentity {
    /// Идентичность без пароля: пароль берётся из кэша или запрашивается.
    #[must_use]
    pub fn new(username: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: None,
            origin: IdentityOrigin::Headers,
        }
    }

    /// Идентичность с паролем из заголовка.
    #[must_use]
    pub fn with_password(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: Some(SecretString::from(password.into())),
            origin: IdentityOrigin::Headers,
        }
    }

    /// Идентичность с паролем из профиля.
    #[must_use]
    pub fn from_profile(username: impl Into<String>, password: SecretString) -> Self {
        Self {
            username: username.into(),
            password: Some(password),
            origin: IdentityOrigin::Profile,
        }
    }
}

/// Результат удалённой команды.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteOutput {
    /// Стандартный вывод.
    pub stdout: Vec<u8>,
    /// Стандартный поток ошибок.
    pub stderr: Vec<u8>,
    /// Код возврата; `-1`, если сервер его не сообщил.
    pub exit_code: i32,
}

/// Ошибка транспорта WinRM.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    /// Сервер отверг учётные данные.
    #[error("authentication failed: {0}")]
    AuthFailed(String),
    /// Учётные данные приняты, но сам запрос отвергнут хостом (TR-SEC-10).
    #[error("request rejected: {0}")]
    Rejected(String),
    /// Любая другая ошибка транспорта.
    #[error("transport error: {0}")]
    Other(String),
}

impl TransportError {
    /// Истина, если это отказ в учётных данных (для сброса кэша пароля).
    ///
    /// [`Self::Rejected`] сюда не входит: там пароль уже принят, и сбрасывать
    /// кэш или двигать счётчик блокировки не за что (TR-SEC-10).
    #[must_use]
    pub fn is_auth_failure(&self) -> bool {
        matches!(self, Self::AuthFailed(_))
    }
}

/// Параметры одного подключения к Windows-хосту.
#[derive(Debug, Clone)]
pub struct SessionTarget {
    /// Хост.
    pub host: String,
    /// Порт WinRM.
    pub port: u16,
    /// Использовать HTTPS.
    pub use_tls: bool,
    /// Проверять TLS-сертификат.
    pub verify_cert: bool,
    /// Учётная запись.
    pub username: String,
    /// Пароль (обнуляется при освобождении).
    pub password: SecretString,
}

/// Шов транспорта: реальный WinRM или фиктивный записывающий.
#[async_trait::async_trait]
pub trait WinRmTransport: Send + Sync {
    /// Выполнить PowerShell-скрипт на хосте.
    ///
    /// # Errors
    ///
    /// [`TransportError`], если подключение или аутентификация не удались.
    async fn run_powershell(
        &self,
        target: &SessionTarget,
        script: &str,
    ) -> Result<RemoteOutput, TransportError>;
}

/// Разбирает учётную запись на имя пользователя и домен для NTLM.
///
/// `winrm-rs` не разбирает `DOMAIN\user` сам: он подставляет `username` в
/// NTLMv2-хеш целиком (`UPPER(username) + domain`), поэтому при пустом домене
/// `contoso\alice` уходит как `CONTOSO\ALICE` и AD отвергает вход.
///
/// Разбор повторяет `spnego` (движок `requests-ntlm` под `pywinrm`, на котором
/// работала Python-версия): имя делится по первому `\\`; UPN (`user@realm`) и
/// голое имя остаются целиком именем пользователя с пустым доменом, а регистр
/// домена не меняется — сервер пересчитывает хеш по тому, что прислал клиент.
#[must_use]
pub fn split_account(account: &str) -> (String, String) {
    match account.split_once('\\') {
        Some((domain, user)) => (user.to_owned(), domain.to_owned()),
        None => (account.to_owned(), String::new()),
    }
}

/// Реальный транспорт поверх `winrm-rs`.
#[derive(Debug, Default, Clone)]
pub struct WinrmTransportImpl;

/// Собирает учётные данные `winrm-rs`, разбирая `DOMAIN\user`.
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

/// Подсказка для пустого 500: слушатель отверг нешифрованное сообщение.
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

/// Отделяет настоящий отказ учётных данных от отвергнутого запроса.
///
/// `winrm-rs` складывает в `AuthFailed` и отказ NTLM, и любой неуспешный
/// HTTP-статус (`auth/ntlm.rs`, `transport.rs`). Второе приходит уже после
/// принятого NTLM, поэтому отказом пароля не является и не должно ни сбрасывать
/// кэш, ни двигать счётчик блокировки (TR-SEC-10).
fn classify_auth_failure(message: String) -> TransportError {
    if !message.starts_with("HTTP ") {
        return TransportError::AuthFailed(message);
    }
    if is_empty_internal_error(&message) {
        return TransportError::Rejected(UNENCRYPTED_HINT.to_owned());
    }
    TransportError::Rejected(message)
}

/// Истина для `HTTP 500 ...:` с пустым телом — подписи отказа в нешифрованном
/// сообщении. Ошибка WS-Man пришла бы SOAP-fault'ом и с телом.
fn is_empty_internal_error(message: &str) -> bool {
    message.starts_with("HTTP 500")
        && message
            .split_once(':')
            .is_some_and(|(_, body)| body.trim().is_empty())
}

/// Настройки реестра, собранные из `AppConfig`.
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// Время жизни пароля в покое; 0 — без истечения.
    pub password_idle_ttl: Duration,
    /// Порог отказов AD до блокировки.
    pub lockout_max_attempts: u32,
    /// Окно блокировки.
    pub lockout_window: Duration,
    /// Порог редактирования в ответе агенту.
    pub secret_redact_min_length: usize,
    /// Предел вывода в аудите.
    pub audit_max_output_chars: usize,
    /// Писать ли тело команды и вывода в аудит.
    pub audit_log_body: bool,
    /// Порт по умолчанию.
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

/// Кэшированный пароль с временем последнего использования.
#[derive(Debug, Clone)]
struct CachedPassword {
    value: SecretString,
    last_used: Instant,
}

/// Состояние отказов AD для текущего пароля.
#[derive(Debug, Clone)]
struct FailureState {
    /// SHA-256 отклонённого пароля; сам пароль не хранится (DR-4).
    password_hash: [u8; 32],
    count: u32,
    first_failure: Instant,
}

impl FailureState {
    /// Секунды до истечения окна, отсчитываемого от первого отказа.
    fn window_remaining(&self, window: Duration, now: Instant) -> i64 {
        let elapsed = now.saturating_duration_since(self.first_failure);
        window.as_secs() as i64 - elapsed.as_secs() as i64
    }
}

/// Откуда пришёл пароль: определяет, распространяется ли на него правило
/// двух блокировок (ADR-0009, AC-PRF-56).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityOrigin {
    /// Пароль предъявлен заголовком; клиент может сменить его вручную.
    Headers,
    /// Пароль расшифрован из профиля; смена требует `setup`.
    Profile,
}

/// Открытая сессия пользователя.
#[derive(Debug, Clone)]
struct Session {
    target: SessionTarget,
    connected_at: SystemTime,
    last_used: SystemTime,
    command_count: u64,
}

/// Реестр сессий и кэшей, изолированных по пользователю (DR-3).
pub struct SessionRegistry {
    transport: Arc<dyn WinRmTransport>,
    config: RegistryConfig,
    passwords: Mutex<HashMap<String, CachedPassword>>,
    failures: Mutex<HashMap<String, FailureState>>,
    /// Число срабатываний порога отказов с последнего успешного `connect`.
    lockout_streak: Mutex<HashMap<String, u32>>,
    /// Пользователи, чей профиль отвергнут дважды: отказ до перезапуска.
    profile_refused: Mutex<std::collections::HashSet<String>>,
    sessions: Mutex<HashMap<(String, String), Session>>,
}

impl SessionRegistry {
    /// Создаёт реестр с заданным транспортом и настройками.
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

    /// Кладёт пароль в кэш пользователя, сбрасывая сессии при смене пароля.
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

    /// Есть ли у пользователя неизрасходованный пароль; обновляет время жизни.
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

    /// Убирает пароль и сессии пользователя, чтобы следующий `connect` снова спросил.
    pub fn invalidate_password(&self, username: &str) {
        lock(&self.passwords).remove(username);
        self.drop_sessions(username);
    }

    /// Истина, если профиль пользователя отвергнут дважды и не предъявляется
    /// до перезапуска (AC-PRF-56). В stdio это сигнал завершить процесс.
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

    /// Открывает сессию: проверяет блокировку, выполняет пробную команду.
    ///
    /// Возвращает ответ инструмента: при успехе — сведения о хосте, при
    /// отказе — поле `error`.
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

        // AC-PRF-56: профиль, отвергнутый дважды, не предъявляется снова до
        // перезапуска процесса.
        if identity.origin == IdentityOrigin::Profile
            && lock(&self.profile_refused).contains(&username)
        {
            return json!({
                "error": "The profile password was rejected twice; the profile is refused until \
                          the process restarts. Run 'winrig setup' to update it.",
                "auth_failed": true,
            });
        }

        if let Some(locked) = self.check_lockout(&username) {
            return locked;
        }

        let password = match identity
            .password
            .clone()
            .or_else(|| self.cached_password(&username))
        {
            Some(password) => password,
            None => {
                return json!({
                    "error": "AD password is not cached or has expired. Call connect to enter it again."
                });
            }
        };

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
                // DR-4: поля, пришедшие от хоста, тоже могут содержать секрет,
                // поэтому редактируются перед аудитом и ответом.
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
                // DR-4: текст ошибки хоста может содержать пароль. Аудит
                // редактируется безусловно, ответ агенту — по порогу.
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
                    // AC-PRF-56: второй набор порога отказов для профиля
                    // переводит его в отказ до перезапуска процесса.
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

    /// Закрывает сессию пользователя.
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

    /// Перечисляет сессии пользователя.
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

    /// Выполняет PowerShell-команду в открытой сессии с редактированием и аудитом.
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

        // DR-4: пароль самой сессии редактируется всегда, даже если инструмент
        // не передал его отдельно. Иначе `set_registry` с секретом в значении
        // попал бы в аудит открытым текстом.
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

        // Преамбула добавляется только к исполнению; аудит хранит команду,
        // которую запросил инструмент.
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

    /// Имя пользователя, которому принадлежит неизрасходованный пароль.
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

    /// Учитывает достижение порога отказов; `true` — если это уже второй раз
    /// подряд (AC-PRF-56). Счётчик обнуляется успешным `connect` (AC-PRF-57).
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

    /// Сдвигает окно блокировки в прошлое — только для тестов истечения окна.
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

/// Строит тело записи аудита для одной команды (TR-SEC-09, DR-4).
///
/// Чистая функция: редактирует команду и вывод безусловно (`min_length=1`),
/// усекает и оформляет. Вынесена из `run_ps`, чтобы проверяться без глобальной
/// подсистемы трассировки.
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

/// Метка источника пароля для аудита (ADR-0009).
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

/// Захватывает мьютекс, восстанавливаясь после отравления.
///
/// Паника в потоке с захваченным мьютексом не должна превращать следующие
/// запросы в панику: состояние реестра — это кэши и счётчики, а не инвариант,
/// который нельзя восстановить. Аудит и логирование должны продолжать работать.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn strip_clixml(stderr: &str) -> String {
    // PowerShell упаковывает прогресс в CLIXML; вырезаем блок `<Objs>...</Objs>`.
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
    // Без внешнего крэйта дат: выводим секунды эпохи, что стабильно и
    // достаточно для метаданных сессии.
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => format!("{}", duration.as_secs()),
        Err(_) => "0".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// Фиктивный транспорт: записывает команды и отдаёт заранее заданные ответы.
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

    /// `DOMAIN\user` разбирается на домен и имя: без этого NTLM подставляет
    /// строку с обратным слэшем в хеш и AD отвергает вход. Разбор совпадает с
    /// `spnego`: UPN и голое имя не делятся, регистр не меняется.
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
        // UPN: spnego не делит его, поэтому домен остаётся пустым.
        assert_eq!(
            split_account("alice@contoso.local"),
            ("alice@contoso.local".to_owned(), String::new())
        );
        assert_eq!(split_account("alice"), ("alice".to_owned(), String::new()));
        // Деление по первому слэшу, остаток остаётся именем.
        assert_eq!(
            split_account("dom\\nested\\user"),
            ("nested\\user".to_owned(), "dom".to_owned())
        );
    }

    /// `credentials_for` передаёт в `winrm-rs` чистое имя без домена.
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
    async fn connect_without_password_reports_expired_cache() {
        let transport = Arc::new(FakeTransport::returning(output("", "", 0)));
        let registry = registry(transport);
        let reply = registry
            .connect(&UserIdentity::new("bob"), "host1", None, None, true)
            .await;
        assert!(reply["error"].as_str().is_some());
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

    /// TR-SEC-10: `winrm-rs` кладёт в `AuthFailed` любой неуспешный
    /// HTTP-статус, а не только отказ учётных данных. Пустой 500 приходит уже
    /// ПОСЛЕ принятого NTLM, поэтому отказом пароля он не является.
    #[test]
    fn empty_500_is_not_an_auth_failure() {
        let rejected = map_error(winrm_rs::WinrmError::AuthFailed(
            "HTTP 500 Internal Server Error: ".to_owned(),
        ));
        assert!(!rejected.is_auth_failure());
        let text = rejected.to_string();
        assert!(text.contains("5986"), "нужна подсказка про HTTPS: {text}");
        assert!(
            text.contains("AllowUnencrypted"),
            "нужна подсказка про AllowUnencrypted: {text}"
        );
        assert!(
            !text.contains("authentication failed"),
            "это не отказ учётных данных: {text}"
        );
    }

    /// TR-SEC-10: прочие HTTP-статусы тоже не отказ пароля, но и подсказку про
    /// шифрование к ним не приписываем.
    #[test]
    fn other_http_status_is_rejected_without_the_hint() {
        let rejected = map_error(winrm_rs::WinrmError::AuthFailed(
            "HTTP 503 Service Unavailable: busy".to_owned(),
        ));
        assert!(!rejected.is_auth_failure());
        let text = rejected.to_string();
        assert!(text.contains("503"), "статус должен сохраниться: {text}");
        assert!(
            !text.contains("AllowUnencrypted"),
            "лишняя подсказка: {text}"
        );
    }

    /// TR-SEC-10: настоящий отказ учётных данных распознаётся по-прежнему.
    #[test]
    fn ntlm_rejection_stays_an_auth_failure() {
        let error = map_error(winrm_rs::WinrmError::AuthFailed(
            "NTLM authentication rejected (bad credentials or CBT mismatch)".to_owned(),
        ));
        assert!(error.is_auth_failure());
    }

    /// TR-SEC-10: отвергнутый запрос не трогает кэш пароля — иначе неверно
    /// настроенный слушатель заставляет вводить пароль заново.
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
            "не отказ учётных данных: {reply}"
        );
        assert!(registry.has_cached_password("alice"));
    }

    /// TR-SEC-10: сколько бы раз слушатель ни отверг запрос, профиль не уходит
    /// в отказ и блокировка не включается (ср. AC-PRF-56).
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
            "профиль не должен быть отвергнут"
        );
        // Транспорт вызван все шесть раз: блокировка ни разу не вмешалась.
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
        // Боевой путь: сервер передаёт пустой список, но пароль самой сессии
        // обязан редактироваться из ответа и аудита (DR-4).
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

    /// AC-PRF-14: пароль из профиля редактируется на боевом пути `run_ps` так
    /// же, как пароль из заголовка.
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
        // DR-4: аудит редактируется безусловно (min_length=1), даже если
        // секрет короче WINRIG_SECRET_REDACT_MIN_LENGTH (этот порог — только для
        // ответа агенту, ADR-0005 §2). Проверяем чистую функцию детерминированно.
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
        // Алиса подключается по HTTPS (session_id "host1:5986"), Боб — по HTTP
        // (session_id "host1"). Идентификаторы не совпадают, и Боб не должен
        // получить доступ к сессии Алисы.
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
        // DR-4: пароль, попавший в текст ошибки хоста, не должен утечь в ответ.
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
        // AC-SEC01-4: по истечении окна тот же пароль снова доходит до транспорта.
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
        // Четвёртая попытка заблокирована без транспорта.
        let before = transport.calls().len();
        let identity = UserIdentity::with_password("alice", "wrong");
        let locked = registry.connect(&identity, "host1", None, None, true).await;
        assert_eq!(locked["locked_out"], true);
        assert_eq!(transport.calls().len(), before);

        // Окно истекло: та же попытка снова уходит в транспорт.
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
            // Пробная команда connect прошла; теперь команда инструмента
            // завершается ненулевым кодом без вывода.
            transport.set_result(Ok(output("", "", 1)));
            let reply = registry
                .run_ps("alice", "host1", "Get-Service nope", "", &[])
                .await;
            assert!(reply["error"].as_str().unwrap().contains("suppressed"));
        });
    }

    /// AC-PRF-05/13: пароль из профиля доходит до транспорта под тем же
    /// пользователем, что и заголовок.
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

    /// AC-PRF-05: источник идентичности в аудите различает профиль и заголовок.
    #[test]
    fn origin_label_distinguishes_sources() {
        assert_eq!(origin_label(IdentityOrigin::Profile), "profile");
        assert_eq!(origin_label(IdentityOrigin::Headers), "headers");
    }

    /// AC-PRF-13: блокировка работает и для пароля из профиля.
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

    /// AC-PRF-56: второй набор порога отказов для профиля переводит его в
    /// отказ, транспорт больше не вызывается.
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
        // Окно истекло: вторая тройка отказов.
        registry.force_lockout_window_elapsed("alice");
        for _ in 0..3 {
            let identity = UserIdentity::from_profile("alice", SecretString::from("wrong"));
            let _ = registry.connect(&identity, "host1", None, None, true).await;
        }
        assert!(
            registry.is_profile_refused("alice"),
            "профиль должен быть отвергнут"
        );
        let before = transport.calls().len();
        let identity = UserIdentity::from_profile("alice", SecretString::from("wrong"));
        let refused = registry.connect(&identity, "host1", None, None, true).await;
        assert_eq!(refused["auth_failed"], true);
        assert_eq!(transport.calls().len(), before);
        // Ровно шесть вызовов транспорта за две тройки отказов.
        assert_eq!(before, 6);
    }

    /// AC-PRF-56: пароль из заголовка не переводит профиль в отказ.
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

    /// AC-PRF-57: успешный connect сбрасывает счёт подряд идущих блокировок.
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
        // Счёт подряд идущих блокировок пуст: следующая блокировка снова первая.
        assert!(lock(&registry.lockout_streak).get("alice").is_none());
    }
}
