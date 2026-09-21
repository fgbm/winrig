//! MCP-сервер: инструменты и их привязка к реестру сессий.
//!
//! Идентичность читается из заголовков текущего запроса (DR-2,
//! [`crate::identity`]). Модифицирующие инструменты требуют подтверждения через
//! elicitation и при его недоступности не выполняются (DR-5, fail-closed).

use std::sync::Arc;
use std::time::Duration;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ServerCapabilities, ServerConfig};
use rmcp::service::{ElicitationError, RequestContext};
use rmcp::{RoleServer, ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use crate::config::AppConfig;
use crate::executor::sanitize_prompt_value;
use crate::identity::RequestIdentity;
use crate::policy::{
    DeleteScan, FileScan, decide_delete_path, decide_delete_scan, decide_file_delete, decide_host,
    decide_overwrite, decide_port, decide_tls, decide_write_path,
};
use crate::ps;
use crate::session::{SessionRegistry, UserIdentity};

/// Сервер инструментов `winrig`.
#[derive(Clone)]
pub struct WinrigServer {
    registry: Arc<SessionRegistry>,
    config: Arc<AppConfig>,
    /// Идентичность профиля для stdio, где нет HTTP-запроса (ADR-0009).
    local_identity: Option<Arc<crate::identity::ProfileIdentity>>,
    tool_router: ToolRouter<Self>,
}

impl std::fmt::Debug for WinrigServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WinrigServer").finish_non_exhaustive()
    }
}

/// Ответ на подтверждение модифицирующей операции.
#[derive(Debug, Deserialize, JsonSchema)]
struct ConfirmResponse {
    /// `true` — выполнить операцию.
    confirm: bool,
}

rmcp::elicit_safe!(ConfirmResponse);

impl WinrigServer {
    /// Создаёт сервер поверх готового реестра и конфигурации.
    #[must_use]
    pub fn new(registry: Arc<SessionRegistry>, config: Arc<AppConfig>) -> Self {
        let tool_router = Self::router_for(&config);
        Self {
            registry,
            config,
            local_identity: None,
            tool_router,
        }
    }

    /// Собирает маршрутизатор под конфигурацию: выключенные инструменты
    /// снимаются, а не прячутся (TR-FS-01, ADR-0013 §2).
    ///
    /// Снятый маршрут не появляется в `tools/list` и не вызывается: агент не
    /// должен видеть возможность, которой у него нет, и строить на ней план.
    fn router_for(config: &AppConfig) -> ToolRouter<Self> {
        let mut router = Self::tool_router();
        if !config.allow_file_write {
            router.remove_route("write_file");
        }
        router
    }

    /// Создаёт сервер stdio: идентичность берётся из профиля, HTTP-запроса нет.
    #[must_use]
    pub fn with_profile_identity(
        registry: Arc<SessionRegistry>,
        config: Arc<AppConfig>,
        identity: Arc<crate::identity::ProfileIdentity>,
    ) -> Self {
        let tool_router = Self::router_for(&config);
        Self {
            registry,
            config,
            local_identity: Some(identity),
            tool_router,
        }
    }

    /// Возвращает идентичность вызова: из запроса либо из профиля (stdio).
    ///
    /// # Errors
    ///
    /// [`rmcp::model::ErrorData`] с `INVALID_PARAMS`, если идентичности нет.
    fn identity(
        &self,
        ctx: &RequestContext<RoleServer>,
    ) -> Result<RequestIdentity, rmcp::model::ErrorData> {
        if crate::identity::request_parts(ctx).is_some() {
            return crate::identity::identity_from_context(ctx);
        }
        match &self.local_identity {
            Some(profile) => Ok(RequestIdentity {
                username: profile.username.clone(),
                password: Some(profile.password.clone()),
                source: crate::identity::IdentitySource::Profile,
            }),
            None => crate::identity::identity_from_context(ctx),
        }
    }

    /// Преобразует идентичность запроса в идентичность сессии.
    fn user(identity: &RequestIdentity) -> UserIdentity {
        UserIdentity {
            username: identity.username.clone(),
            password: identity.password.clone(),
            origin: match identity.source {
                crate::identity::IdentitySource::Profile => crate::session::IdentityOrigin::Profile,
                crate::identity::IdentitySource::Headers => crate::session::IdentityOrigin::Headers,
            },
        }
    }

    /// Выполняет команду в сессии и оборачивает ответ в результат инструмента.
    async fn run(
        &self,
        identity: &RequestIdentity,
        session_id: &str,
        command: &str,
        tool_name: &str,
    ) -> CallToolResult {
        self.run_redacted(identity, session_id, command, tool_name, &[])
            .await
    }

    /// Выполняет команду с дополнительными секретами для редактирования.
    async fn run_redacted(
        &self,
        identity: &RequestIdentity,
        session_id: &str,
        command: &str,
        tool_name: &str,
        extra_secrets: &[String],
    ) -> CallToolResult {
        CallToolResult::structured(
            self.run_value_redacted(identity, session_id, command, tool_name, extra_secrets)
                .await,
        )
    }

    /// Выполняет команду в сессии и возвращает ответ реестра как JSON.
    async fn run_value(
        &self,
        identity: &RequestIdentity,
        session_id: &str,
        command: &str,
        tool_name: &str,
    ) -> serde_json::Value {
        self.run_value_redacted(identity, session_id, command, tool_name, &[])
            .await
    }

    /// Выполняет команду с дополнительными секретами для редактирования.
    ///
    /// Пароль самой сессии `run_ps` добавляет всегда; здесь передаются
    /// значения из аргументов инструмента (например значение реестра), чтобы
    /// они не попали в аудит открытым текстом (DR-4).
    async fn run_value_redacted(
        &self,
        identity: &RequestIdentity,
        session_id: &str,
        command: &str,
        tool_name: &str,
        extra_secrets: &[String],
    ) -> serde_json::Value {
        self.registry
            .run_ps(
                &identity.username,
                session_id,
                command,
                tool_name,
                extra_secrets,
            )
            .await
    }

    /// Извлекает `stdout` из ответа реестра, если команда завершилась успешно.
    ///
    /// `None` означает, что команда не выполнилась или хост вернул ошибку —
    /// вызывающая сторона обязана отказать (fail-closed).
    fn successful_stdout(reply: &serde_json::Value) -> Option<String> {
        if reply.get("error").is_some() {
            return None;
        }
        let code = reply.get("status_code").and_then(serde_json::Value::as_i64);
        if code != Some(0) {
            return None;
        }
        reply
            .get("stdout")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    }

    /// Возвращает состояние службы для показа в подтверждении.
    ///
    /// Чтение read-only и выполняется до подтверждения: если оно не удалось,
    /// подтверждение всё равно показывается, просто без блока состояния.
    async fn service_state(
        &self,
        identity: &RequestIdentity,
        session_id: &str,
        name: &str,
    ) -> String {
        let reply = self
            .run_value(
                identity,
                session_id,
                &service_state_command(name),
                "get_services",
            )
            .await;
        Self::successful_stdout(&reply)
            .map(|stdout| stdout.trim().to_owned())
            .filter(|stdout| !stdout.is_empty())
            .unwrap_or_else(|| "(state unavailable)".to_owned())
    }

    /// Возвращает имя и старт процесса для показа в подтверждении.
    ///
    /// Пустой PID или несуществующий процесс дают честную строку, а не пустоту:
    /// подтверждение должно показывать цель даже тогда, когда её уже нет.
    async fn process_details(
        &self,
        identity: &RequestIdentity,
        session_id: &str,
        pid: i64,
    ) -> String {
        let command = format!(
            "$p = Get-Process -Id {pid} -ErrorAction SilentlyContinue; \
             if ($p) {{ [PSCustomObject]@{{ Name=$p.ProcessName; \
             Started=if($p.StartTime){{$p.StartTime.ToString('yyyy-MM-dd HH:mm:ss')}}else{{'N/A'}} }} \
             | ConvertTo-Json -Compress }} else {{ Write-Output 'process not found' }}"
        );
        let reply = self
            .run_value(identity, session_id, &command, "list_processes")
            .await;
        Self::successful_stdout(&reply)
            .map(|stdout| stdout.trim().to_owned())
            .filter(|stdout| !stdout.is_empty())
            .unwrap_or_else(|| "process details unavailable".to_owned())
    }

    /// Запрашивает подтверждение.
    ///
    /// `Ok(())` — пользователь явно согласился. `Err(result)` — операция не
    /// выполняется: отказ, отмена, таймаут или отсутствие канала подтверждения
    /// (DR-5, fail-closed); `result` — готовый ответ инструмента. Аргументы
    /// санитизируются, чтобы значение не подделало структуру диалога.
    async fn confirm(
        ctx: &RequestContext<RoleServer>,
        action: &str,
        details: &str,
        timeout: Duration,
    ) -> Result<(), CallToolResult> {
        let action = sanitize_prompt_value(action);
        let details = sanitize_prompt_value(details);
        let message = format!("Confirm {action}?\n\n{details}");
        match ctx
            .peer
            .elicit_with_timeout::<ConfirmResponse>(message, Some(timeout))
            .await
        {
            Ok(Some(response)) if response.confirm => Ok(()),
            Ok(Some(_)) | Ok(None) => Err(cancelled(&action)),
            Err(ElicitationError::UserDeclined | ElicitationError::UserCancelled) => {
                Err(cancelled(&action))
            }
            Err(ElicitationError::Service(rmcp::service::ServiceError::Timeout { .. })) => {
                Err(CallToolResult::structured(json!({
                    "error": format!(
                        "Confirmation for {action} timed out after {}s and was not performed",
                        timeout.as_secs()
                    ),
                    "status": "timeout",
                })))
            }
            Err(error) => Err(CallToolResult::structured(json!({
                "error": format!(
                    "Cannot ask for confirmation, so {action} was not performed: {error}"
                ),
            }))),
        }
    }
}

/// Случайный шестнадцатеричный суффикс для имени временного файла.
fn random_suffix() -> String {
    let mut bytes = [0u8; 8];
    rand::fill(&mut bytes);
    bytes.iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Вытаскивает аргументы `FromBase64String('...')` для редакции (DR-4).
///
/// Тело записываемого файла попадает в команду только так, поэтому список
/// из одного-двух элементов покрывает весь секрет в теле команды.
fn base64_payloads(command: &str) -> Vec<String> {
    const OPEN: &str = "FromBase64String('";
    let mut out = Vec::new();
    let mut rest = command;
    while let Some(start) = rest.find(OPEN) {
        rest = &rest[start + OPEN.len()..];
        let Some(end) = rest.find('\'') else { break };
        let payload = &rest[..end];
        if !payload.is_empty() {
            out.push(payload.to_owned());
        }
        rest = &rest[end..];
    }
    out
}

fn cancelled(action: &str) -> CallToolResult {
    CallToolResult::structured(json!({
        "status": "cancelled",
        "message": format!("{action} cancelled by user"),
    }))
}

/// Возвращает из инструмента готовый ответ, если подтверждение не получено.
macro_rules! require_confirmation {
    ($self:expr, $ctx:expr, $action:expr, $details:expr) => {
        if let Err(result) = WinrigServer::confirm(
            $ctx,
            $action,
            $details,
            std::time::Duration::from_secs($self.config.confirm_timeout_seconds),
        )
        .await
        {
            return Ok(result);
        }
    };
}

// ---------------------------------------------------------------------------
// Параметры инструментов
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
struct ConnectParams {
    /// Windows hostname or IP to connect to, e.g. 'web-server-01'.
    host: String,
    /// WinRM port. Defaults to 5985 for HTTP and 5986 for HTTPS.
    #[serde(default)]
    port: Option<i64>,
    /// Use HTTPS transport. Derived from the port when omitted.
    #[serde(default)]
    use_ssl: Option<bool>,
    /// Validate the server TLS certificate on HTTPS.
    #[serde(default = "default_true")]
    verify_cert: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SessionIdParams {
    /// Session ID returned by connect.
    session_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ListDirectoryParams {
    /// Session ID returned by connect.
    session_id: String,
    /// Absolute directory path to list, e.g. 'C:\\Users' or 'D:\\Logs'.
    path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct FindFilesParams {
    /// Session ID returned by connect.
    session_id: String,
    /// Root directory to start the recursive search from.
    path: String,
    /// Filename wildcard to match, e.g. '*.log'.
    pattern: String,
    /// Maximum recursion depth, default 5, capped at 10.
    #[serde(default = "default_depth")]
    max_depth: i64,
    /// Include each file's size in the output.
    #[serde(default = "default_true")]
    include_size: bool,
}

fn default_depth() -> i64 {
    5
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ReadFileParams {
    /// Session ID returned by connect.
    session_id: String,
    /// Absolute path of the file to read.
    path: String,
    /// First 1-based line to return in range mode.
    #[serde(default = "default_one")]
    start_line: i64,
    /// Last line in range mode, or line count from end in tail mode.
    #[serde(default = "default_200")]
    end_line: i64,
    /// Read the last N lines instead of a range.
    #[serde(default)]
    tail: bool,
    /// File encoding, default UTF8.
    #[serde(default = "default_utf8")]
    encoding: String,
}

fn default_one() -> i64 {
    1
}
fn default_200() -> i64 {
    200
}
fn default_utf8() -> String {
    "UTF8".to_owned()
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SearchFileContentParams {
    /// Session ID returned by connect.
    session_id: String,
    /// Single file, or narrowest directory to search recursively.
    path: String,
    /// Distinctive literal text to find; no regex or wildcards.
    pattern: String,
    /// Filename wildcard for directory searches.
    #[serde(default = "default_star")]
    file_filter: String,
    /// Max matching lines to return, capped at 100.
    #[serde(default = "default_50")]
    max_results: i64,
    /// Lines shown before and after each match, max 10.
    #[serde(default)]
    context_lines: i64,
    /// Only search files changed within this many hours; 0 means all files.
    #[serde(default)]
    modified_after_hours: i64,
}

fn default_star() -> String {
    "*".to_owned()
}
fn default_50() -> i64 {
    50
}

#[derive(Debug, Deserialize, JsonSchema)]
struct CompareFilesParams {
    /// Session ID returned by connect.
    session_id: String,
    /// Absolute path to the first file (reference).
    path_a: String,
    /// Absolute path to the second file (difference).
    path_b: String,
    /// Maximum differing lines to show, capped at 200.
    #[serde(default = "default_50")]
    max_diffs: i64,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct EventLogParams {
    /// Session ID returned by connect.
    session_id: String,
    /// Event log to read: System (default), Application, or Security.
    #[serde(default = "default_system")]
    log_name: String,
    /// Severity threshold including higher: Critical, Error, Warning, Info.
    #[serde(default = "default_error_level")]
    level: String,
    /// How many hours back to search, capped at 720.
    #[serde(default = "default_24")]
    hours_back: i64,
    /// Provider name filter, wildcards allowed.
    #[serde(default)]
    source: String,
    /// Max events to return, capped at 100.
    #[serde(default = "default_25")]
    count: i64,
}

fn default_system() -> String {
    "System".to_owned()
}
fn default_error_level() -> String {
    "Error".to_owned()
}
fn default_24() -> i64 {
    24
}
fn default_25() -> i64 {
    25
}

#[derive(Debug, Deserialize, JsonSchema)]
struct GetServicesParams {
    /// Session ID returned by connect.
    session_id: String,
    /// Wildcard on Name or DisplayName.
    #[serde(default)]
    name_filter: String,
    /// Filter by state: Running, Stopped, or All.
    #[serde(default = "default_all")]
    status_filter: String,
    /// Deep JSON inspection per service.
    #[serde(default)]
    detail: bool,
}

fn default_all() -> String {
    "All".to_owned()
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ListProcessesParams {
    /// Session ID returned by connect.
    session_id: String,
    /// Wildcard on process name.
    #[serde(default)]
    name_filter: String,
    /// Sort descending by CPU or Memory.
    #[serde(default = "default_memory")]
    sort_by: String,
    /// Number of processes to show, capped at 100.
    #[serde(default = "default_30")]
    top: i64,
}

fn default_memory() -> String {
    "Memory".to_owned()
}
fn default_30() -> i64 {
    30
}

#[derive(Debug, Deserialize, JsonSchema)]
struct PerfParams {
    /// Session ID returned by connect.
    session_id: String,
    /// Seconds between samples; kept for compatibility, capped at 10.
    #[serde(default = "default_two")]
    interval_sec: i64,
    /// Wildcard for per-process stats; empty omits that section.
    #[serde(default)]
    process_filter: String,
}

fn default_two() -> i64 {
    2
}

#[derive(Debug, Deserialize, JsonSchema)]
struct RegistryReadParams {
    /// Session ID returned by connect.
    session_id: String,
    /// Registry path with 'HKLM:\\' prefix; HKEY_LOCAL_MACHINE form also accepted.
    key: String,
    /// Single value to read; empty dumps all values under the key.
    #[serde(default)]
    value_name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct CertificatesParams {
    /// Session ID returned by connect.
    session_id: String,
    /// Certificate store location: LocalMachine or CurrentUser.
    #[serde(default = "default_localmachine")]
    store: String,
    /// Only show certs expiring within this many days; 0 shows all.
    #[serde(default)]
    days_until_expiry: i64,
}

fn default_localmachine() -> String {
    "LocalMachine".to_owned()
}

#[derive(Debug, Deserialize, JsonSchema)]
struct TestNetworkParams {
    /// Session ID returned by connect.
    session_id: String,
    /// Hostname or IP to test connectivity to.
    target: String,
    /// TCP port to test, or 0 (default) for an ICMP ping.
    #[serde(default)]
    port: i64,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct EnvParams {
    /// Session ID returned by connect.
    session_id: String,
    /// Wildcard on variable name.
    #[serde(default)]
    name_filter: String,
    /// Variable scope: Machine, User, or Process.
    #[serde(default = "default_machine")]
    scope: String,
}

fn default_machine() -> String {
    "Machine".to_owned()
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ScheduledTasksParams {
    /// Session ID returned by connect.
    session_id: String,
    /// Wildcard on task name.
    #[serde(default)]
    name_filter: String,
    /// Include disabled tasks.
    #[serde(default)]
    include_disabled: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct UserGroupsParams {
    /// Session ID returned by connect.
    session_id: String,
    /// User to look up; empty lists all local groups.
    #[serde(default)]
    username: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct TcpConnectionsParams {
    /// Session ID returned by connect.
    session_id: String,
    /// State filter: Established (default), Listen, TimeWait, CloseWait, or All.
    #[serde(default = "default_established")]
    state_filter: String,
    /// Only show connections involving this port; 0 means all ports.
    #[serde(default)]
    port_filter: i64,
}

fn default_established() -> String {
    "Established".to_owned()
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DnsCacheParams {
    /// Session ID returned by connect.
    session_id: String,
    /// Wildcard on record name.
    #[serde(default)]
    name_filter: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct InstalledSoftwareParams {
    /// Session ID returned by connect.
    session_id: String,
    /// Wildcard on software name.
    #[serde(default)]
    name_filter: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ResolveDnsParams {
    /// Session ID returned by connect.
    session_id: String,
    /// Hostname or FQDN to resolve.
    name: String,
    /// Record type: A (default), AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT.
    #[serde(default = "default_a")]
    record_type: String,
    /// Specific DNS server to query; empty uses the system default.
    #[serde(default)]
    dns_server: String,
}

fn default_a() -> String {
    "A".to_owned()
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ServiceNameParams {
    /// Session ID returned by connect.
    session_id: String,
    /// Exact service name, not display name.
    name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct KillProcessParams {
    /// Session ID returned by connect.
    session_id: String,
    /// Process ID to kill.
    pid: i64,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SetRegistryParams {
    /// Session ID returned by connect.
    session_id: String,
    /// Registry path, e.g. 'HKLM:\\SOFTWARE\\MyApp'.
    key: String,
    /// Name of the registry value to set.
    value_name: String,
    /// Data to write as a string.
    value_data: String,
    /// Value type: String, DWord, QWord, ExpandString, MultiString, Binary.
    #[serde(default = "default_string")]
    value_type: String,
}

fn default_string() -> String {
    "String".to_owned()
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DeleteFileParams {
    /// Session ID returned by connect.
    session_id: String,
    /// Absolute path to the file to delete.
    path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct WriteFileParams {
    /// Session ID returned by connect.
    session_id: String,
    /// Absolute path of the file to write on the remote host.
    path: String,
    /// Full contents to write. The file is replaced, not appended to.
    content: String,
    /// Replace the file when it already exists. Without this the call is
    /// refused, so creating a file cannot destroy one by accident.
    #[serde(default)]
    overwrite: bool,
    /// Encoding of the written file; defaults to UTF-8 without a BOM.
    #[serde(default = "default_write_encoding")]
    encoding: String,
}

fn default_write_encoding() -> String {
    "utf8".to_owned()
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DeleteDirectoryParams {
    /// Session ID returned by connect.
    session_id: String,
    /// Absolute path to the directory to delete recursively.
    path: String,
    /// Safety cap; refuse if more items exist.
    #[serde(default = "default_5000")]
    max_items: i64,
}

fn default_5000() -> i64 {
    5000
}

// ---------------------------------------------------------------------------
// Инструменты
// ---------------------------------------------------------------------------

#[tool_router]
impl WinrigServer {
    /// Open a WinRM session to a Windows host and return a session_id; this is
    /// the required first step before any other tool.
    #[tool(
        name = "connect",
        description = "Open a WinRM session to a Windows host and return a session_id; this is the required first step before any other tool. The AD password is taken from the X-AD-Password request header and cached only in server memory."
    )]
    async fn connect(
        &self,
        Parameters(params): Parameters<ConnectParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        for decision in [
            decide_host(&params.host, &self.config.allowed_hosts),
            decide_port(params.port),
            decide_tls(params.verify_cert, self.config.allow_insecure_tls),
        ] {
            if !decision.allow {
                return Ok(CallToolResult::structured(
                    json!({ "error": decision.reason }),
                ));
            }
        }
        let port = params.port.and_then(|value| u16::try_from(value).ok());
        let reply = self
            .registry
            .connect(
                &Self::user(&identity),
                &params.host,
                port,
                params.use_ssl,
                params.verify_cert,
            )
            .await;
        Ok(CallToolResult::structured(reply))
    }

    /// Close an active WinRM session.
    #[tool(
        name = "disconnect",
        description = "Close an active WinRM session and release it; sessions are not auto-cleaned, so always disconnect when done."
    )]
    async fn disconnect(
        &self,
        Parameters(params): Parameters<SessionIdParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        Ok(CallToolResult::structured(
            self.registry
                .disconnect(&identity.username, &params.session_id),
        ))
    }

    /// List active WinRM sessions.
    #[tool(
        name = "list_sessions",
        description = "List active WinRM sessions with host, connection time, last used time, and command count."
    )]
    async fn list_sessions(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        Ok(CallToolResult::structured(
            self.registry.list_sessions(&identity.username),
        ))
    }

    /// List files and directories at a path.
    #[tool(
        name = "list_directory",
        description = "List files and directories at a path as tabular text (Mode, LastWriteTime, Length, Name)."
    )]
    async fn list_directory(
        &self,
        Parameters(params): Parameters<ListDirectoryParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &ps::list_directory(&params.path),
                "list_directory",
            )
            .await)
    }

    /// Recursively find files matching a wildcard pattern.
    #[tool(
        name = "find_files",
        description = "Recursively find files matching a wildcard pattern (max 100 results). Matches files only."
    )]
    async fn find_files(
        &self,
        Parameters(params): Parameters<FindFilesParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &ps::find_files(
                    &params.path,
                    &params.pattern,
                    params.max_depth,
                    params.include_size,
                ),
                "find_files",
            )
            .await)
    }

    /// Read file contents as numbered lines.
    #[tool(
        name = "read_file",
        description = "Read file contents as numbered lines (max 500 per call). Range mode reads start_line through end_line; tail mode reads the last N lines."
    )]
    async fn read_file(
        &self,
        Parameters(params): Parameters<ReadFileParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        let command = match ps::read_file(
            &params.path,
            params.start_line,
            params.end_line,
            params.tail,
            &params.encoding,
        ) {
            Ok(command) => command,
            Err(error) => return Ok(CallToolResult::structured(json!({ "error": error }))),
        };
        Ok(self
            .run(&identity, &params.session_id, &command, "read_file")
            .await)
    }

    /// Search for literal text inside files like grep.
    #[tool(
        name = "search_file_content",
        description = "Search for literal text inside files like grep; pass a file path to search one file or a directory to search recursively."
    )]
    async fn search_file_content(
        &self,
        Parameters(params): Parameters<SearchFileContentParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &ps::search_file_content(
                    &params.path,
                    &params.pattern,
                    &params.file_filter,
                    params.max_results,
                    params.context_lines,
                    params.modified_after_hours,
                ),
                "search_file_content",
            )
            .await)
    }

    /// Return JSON metadata for one file or directory.
    #[tool(
        name = "file_info",
        description = "Return JSON metadata for one file or directory: size, timestamps, and attributes."
    )]
    async fn file_info(
        &self,
        Parameters(params): Parameters<ListDirectoryParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &ps::file_info(&params.path),
                "file_info",
            )
            .await)
    }

    /// Compare two files line by line.
    #[tool(
        name = "compare_files",
        description = "Compare two files line by line like diff, showing each differing line and which file it came from."
    )]
    async fn compare_files(
        &self,
        Parameters(params): Parameters<CompareFilesParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &ps::compare_files(&params.path_a, &params.path_b, params.max_diffs),
                "compare_files",
            )
            .await)
    }

    /// Read the Windows Event Log.
    #[tool(
        name = "get_event_log",
        description = "Read the Windows Event Log for crashes, service failures, auth errors, and disk warnings."
    )]
    async fn get_event_log(
        &self,
        Parameters(params): Parameters<EventLogParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        let command = match ps::get_event_log(
            &params.log_name,
            &params.level,
            params.hours_back,
            &params.source,
            params.count,
        ) {
            Ok(command) => command,
            Err(error) => return Ok(CallToolResult::structured(json!({ "error": error }))),
        };
        Ok(self
            .run(&identity, &params.session_id, &command, "get_event_log")
            .await)
    }

    /// List Windows services.
    #[tool(
        name = "get_services",
        description = "List Windows services: summary mode returns tabular Name, Status, StartType, DisplayName; detail mode returns JSON per service."
    )]
    async fn get_services(
        &self,
        Parameters(params): Parameters<GetServicesParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &ps::get_services(&params.name_filter, &params.status_filter, params.detail),
                "get_services",
            )
            .await)
    }

    /// List running processes.
    #[tool(
        name = "list_processes",
        description = "List running processes as tabular text with PID, name, CPU seconds, memory MB, handle count, and start time."
    )]
    async fn list_processes(
        &self,
        Parameters(params): Parameters<ListProcessesParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &ps::list_processes(&params.name_filter, &params.sort_by, params.top),
                "list_processes",
            )
            .await)
    }

    /// Return a JSON system overview.
    #[tool(
        name = "get_system_info",
        description = "Return a JSON system overview in one call: OS version, uptime, last boot, total/free RAM, CPU count, domain, and timezone."
    )]
    async fn get_system_info(
        &self,
        Parameters(params): Parameters<SessionIdParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &ps::get_system_info(),
                "get_system_info",
            )
            .await)
    }

    /// Return disk space for all fixed drives.
    #[tool(
        name = "get_disk_space",
        description = "Return disk space for all fixed drives as tabular text: DeviceID, Total_GB, Free_GB, and Used_Pct."
    )]
    async fn get_disk_space(
        &self,
        Parameters(params): Parameters<SessionIdParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &ps::get_disk_space(),
                "get_disk_space",
            )
            .await)
    }

    /// Capture a locale-independent performance snapshot.
    #[tool(
        name = "get_perf_snapshot",
        description = "Capture a locale-independent performance snapshot as JSON: CPU, memory, disk I/O, network, and optionally per-process stats."
    )]
    async fn get_perf_snapshot(
        &self,
        Parameters(params): Parameters<PerfParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &ps::get_perf_snapshot(params.interval_sec, &params.process_filter),
                "get_perf_snapshot",
            )
            .await)
    }

    /// Read a registry key or a single value.
    #[tool(
        name = "get_registry",
        description = "Read a registry key or a single value (read-only) and return JSON."
    )]
    async fn get_registry(
        &self,
        Parameters(params): Parameters<RegistryReadParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &ps::get_registry(&params.key, &params.value_name),
                "get_registry",
            )
            .await)
    }

    /// List certificates from the Personal store.
    #[tool(
        name = "get_certificates",
        description = "List certificates from the Personal (My) store sorted by days until expiry, showing Subject, Expires, DaysLeft, and Thumbprint."
    )]
    async fn get_certificates(
        &self,
        Parameters(params): Parameters<CertificatesParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        let command = match ps::get_certificates(&params.store, params.days_until_expiry) {
            Ok(command) => command,
            Err(error) => return Ok(CallToolResult::structured(json!({ "error": error }))),
        };
        Ok(self
            .run(&identity, &params.session_id, &command, "get_certificates")
            .await)
    }

    /// Return per-NIC network configuration.
    #[tool(
        name = "get_network_config",
        description = "Return per-NIC network configuration as tabular text: interface name, status, IPv4, gateway, and DNS servers."
    )]
    async fn get_network_config(
        &self,
        Parameters(params): Parameters<SessionIdParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &ps::get_network_config(),
                "get_network_config",
            )
            .await)
    }

    /// Test connectivity from the remote host.
    #[tool(
        name = "test_network",
        description = "Test connectivity from the remote Windows host's perspective: port=0 sends three ICMP pings; port>0 runs a TCP test."
    )]
    async fn test_network(
        &self,
        Parameters(params): Parameters<TestNetworkParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &ps::test_network(&params.target, params.port),
                "test_network",
            )
            .await)
    }

    /// Return environment variables by scope.
    #[tool(
        name = "get_environment_variables",
        description = "Return environment variables (name and value) for the chosen scope as tabular text."
    )]
    async fn get_environment_variables(
        &self,
        Parameters(params): Parameters<EnvParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        let command = match ps::get_environment_variables(&params.name_filter, &params.scope) {
            Ok(command) => command,
            Err(error) => return Ok(CallToolResult::structured(json!({ "error": error }))),
        };
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &command,
                "get_environment_variables",
            )
            .await)
    }

    /// List Windows scheduled tasks.
    #[tool(
        name = "get_scheduled_tasks",
        description = "List Windows scheduled tasks as tabular text with name, state, last run time, last result, and next run time."
    )]
    async fn get_scheduled_tasks(
        &self,
        Parameters(params): Parameters<ScheduledTasksParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &ps::get_scheduled_tasks(&params.name_filter, params.include_disabled),
                "get_scheduled_tasks",
            )
            .await)
    }

    /// List local user accounts.
    #[tool(
        name = "get_local_users",
        description = "List local user accounts as tabular text with name, enabled status, last logon, and description."
    )]
    async fn get_local_users(
        &self,
        Parameters(params): Parameters<SessionIdParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &ps::get_local_users(),
                "get_local_users",
            )
            .await)
    }

    /// Show local group memberships.
    #[tool(
        name = "get_user_groups",
        description = "Show local group memberships: with no username it lists all local groups and members; with a username it shows that user's local groups."
    )]
    async fn get_user_groups(
        &self,
        Parameters(params): Parameters<UserGroupsParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &ps::get_user_groups(&params.username),
                "get_user_groups",
            )
            .await)
    }

    /// Show the session security context (like whoami /all).
    #[tool(
        name = "get_security_context",
        description = "Show the current WinRM session's security context as JSON: identity, group memberships, privileges, and integrity level."
    )]
    async fn get_security_context(
        &self,
        Parameters(params): Parameters<SessionIdParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &ps::get_security_context(),
                "get_security_context",
            )
            .await)
    }

    /// Return the ACL for a file or folder.
    #[tool(
        name = "get_permissions",
        description = "Return the access control list (ACL) for a file or folder as tabular text: identity, Allow/Deny type, rights, and inheritance."
    )]
    async fn get_permissions(
        &self,
        Parameters(params): Parameters<ListDirectoryParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &ps::get_permissions(&params.path),
                "get_permissions",
            )
            .await)
    }

    /// List active TCP connections.
    #[tool(
        name = "get_tcp_connections",
        description = "List active TCP connections as tabular text with local/remote addresses, ports, state, and owning process."
    )]
    async fn get_tcp_connections(
        &self,
        Parameters(params): Parameters<TcpConnectionsParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &ps::get_tcp_connections(&params.state_filter, params.port_filter),
                "get_tcp_connections",
            )
            .await)
    }

    /// Read the local DNS client cache.
    #[tool(
        name = "get_dns_cache",
        description = "Read the local DNS client cache as tabular text: record name, type, TTL, and resolved data."
    )]
    async fn get_dns_cache(
        &self,
        Parameters(params): Parameters<DnsCacheParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &ps::get_dns_cache(&params.name_filter),
                "get_dns_cache",
            )
            .await)
    }

    /// List installed software.
    #[tool(
        name = "get_installed_software",
        description = "List installed software as tabular text with name, version, publisher, and install date, reading both 64-bit and 32-bit uninstall keys."
    )]
    async fn get_installed_software(
        &self,
        Parameters(params): Parameters<InstalledSoftwareParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &ps::get_installed_software(&params.name_filter),
                "get_installed_software",
            )
            .await)
    }

    /// Resolve a DNS name from the remote host.
    #[tool(
        name = "resolve_dns_name",
        description = "Resolve a DNS name from the remote server's perspective as tabular text, showing the full resolution chain including CNAMEs."
    )]
    async fn resolve_dns_name(
        &self,
        Parameters(params): Parameters<ResolveDnsParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        let command =
            match ps::resolve_dns_name(&params.name, &params.record_type, &params.dns_server) {
                Ok(command) => command,
                Err(error) => return Ok(CallToolResult::structured(json!({ "error": error }))),
            };
        Ok(self
            .run(&identity, &params.session_id, &command, "resolve_dns_name")
            .await)
    }

    // ---- Модифицирующие операции: требуют подтверждения (DR-5) ----

    /// Clear the DNS client cache on the remote server.
    #[tool(
        name = "flush_dns",
        description = "Clear the local DNS client cache on the remote server; prompts for confirmation."
    )]
    async fn flush_dns(
        &self,
        Parameters(params): Parameters<SessionIdParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        require_confirmation!(
            &self,
            &ctx,
            "FLUSH DNS CACHE",
            "This will clear all cached DNS entries on the remote server."
        );
        let command = "$before = (Get-DnsClientCache -ErrorAction SilentlyContinue | Measure-Object).Count; \
             Clear-DnsClientCache; \
             $after = (Get-DnsClientCache -ErrorAction SilentlyContinue | Measure-Object).Count; \
             Write-Output \"DNS cache flushed. Entries before: $before, after: $after\"";
        Ok(self
            .run(&identity, &params.session_id, command, "flush_dns")
            .await)
    }

    /// Restart a Windows service.
    #[tool(
        name = "restart_service",
        description = "Restart a Windows service, prompting for confirmation and returning pre and post state."
    )]
    async fn restart_service(
        &self,
        Parameters(params): Parameters<ServiceNameParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        let command = format!(
            "Restart-Service -Name '{}' -Force -ErrorAction Stop; Start-Sleep -Seconds 2; {}",
            ps::escape(&params.name),
            service_state_command(&params.name)
        );
        let before = self
            .service_state(&identity, &params.session_id, &params.name)
            .await;
        require_confirmation!(
            &self,
            &ctx,
            "RESTART SERVICE",
            &format!(
                "Service: {}\nState before: {before}\nAfter restart: state is re-read and returned.",
                params.name
            )
        );
        Ok(self
            .run(&identity, &params.session_id, &command, "restart_service")
            .await)
    }

    /// Stop a Windows service.
    #[tool(
        name = "stop_service",
        description = "Stop a running Windows service, prompting for confirmation and returning pre and post state."
    )]
    async fn stop_service(
        &self,
        Parameters(params): Parameters<ServiceNameParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        let command = format!(
            "Stop-Service -Name '{}' -Force -ErrorAction Stop; Start-Sleep -Seconds 2; {}",
            ps::escape(&params.name),
            service_state_command(&params.name)
        );
        let before = self
            .service_state(&identity, &params.session_id, &params.name)
            .await;
        require_confirmation!(
            &self,
            &ctx,
            "STOP SERVICE",
            &format!("Service: {}\nState before: {before}", params.name)
        );
        Ok(self
            .run(&identity, &params.session_id, &command, "stop_service")
            .await)
    }

    /// Start a stopped Windows service.
    #[tool(
        name = "start_service",
        description = "Start a stopped Windows service, prompting for confirmation and returning pre and post state."
    )]
    async fn start_service(
        &self,
        Parameters(params): Parameters<ServiceNameParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        let command = format!(
            "Start-Service -Name '{}' -ErrorAction Stop; Start-Sleep -Seconds 2; {}",
            ps::escape(&params.name),
            service_state_command(&params.name)
        );
        let before = self
            .service_state(&identity, &params.session_id, &params.name)
            .await;
        require_confirmation!(
            &self,
            &ctx,
            "START SERVICE",
            &format!("Service: {}\nState before: {before}", params.name)
        );
        Ok(self
            .run(&identity, &params.session_id, &command, "start_service")
            .await)
    }

    /// Force-terminate a process by PID.
    #[tool(
        name = "kill_process",
        description = "Force-terminate a process by PID, showing its details in the confirmation prompt."
    )]
    async fn kill_process(
        &self,
        Parameters(params): Parameters<KillProcessParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        let pid = params.pid;
        let command = format!(
            "Stop-Process -Id {pid} -Force -ErrorAction Stop; \
             Write-Output 'Process {pid} terminated'; Start-Sleep -Milliseconds 500; \
             $still = Get-Process -Id {pid} -ErrorAction SilentlyContinue; \
             if ($still) {{ Write-Output 'WARNING: process still running' }} \
             else {{ Write-Output 'Confirmed: process no longer exists' }}"
        );
        // Показываем, что именно будет завершено: PID без имени — слепое
        // подтверждение.
        let details = format!(
            "PID: {pid}\n{}",
            self.process_details(&identity, &params.session_id, pid)
                .await
        );
        require_confirmation!(&self, &ctx, "KILL PROCESS", &details);
        Ok(self
            .run(&identity, &params.session_id, &command, "kill_process")
            .await)
    }

    /// Set a registry value.
    #[tool(
        name = "set_registry",
        description = "Set a registry value, creating it if absent, and show old vs new in the confirmation prompt."
    )]
    async fn set_registry(
        &self,
        Parameters(params): Parameters<SetRegistryParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        let ps_type = match params.value_type.trim().to_lowercase().as_str() {
            "string" => "String",
            "dword" => "DWord",
            "qword" => "QWord",
            "expandstring" => "ExpandString",
            "multistring" => "MultiString",
            "binary" => "Binary",
            other => {
                return Ok(CallToolResult::structured(json!({
                    "error": format!(
                        "Invalid value_type '{other}'. Valid: String, DWord, QWord, ExpandString, MultiString, Binary"
                    ),
                })));
            }
        };
        let mut key = params.key.trim().to_owned();
        if key.to_uppercase().starts_with("HKEY_") {
            key = format!("Registry::{key}");
        }
        let safe_key = ps::escape(&key);
        let safe_value = ps::escape(&params.value_name);
        let safe_data = ps::escape(&params.value_data);
        let command = format!(
            "if (-not (Test-Path -LiteralPath '{safe_key}')) {{ New-Item -Path '{safe_key}' -Force | Out-Null }}; \
             Set-ItemProperty -LiteralPath '{safe_key}' -Name '{safe_value}' -Value '{safe_data}' -Type {ps_type} -ErrorAction Stop; \
             $v = Get-ItemProperty -LiteralPath '{safe_key}' -Name '{safe_value}' -ErrorAction Stop; \
             [PSCustomObject]@{{ Key='{safe_key}'; Name='{safe_value}'; Value=[string]$v.'{safe_value}'; Type='{ps_type}' }} \
             | ConvertTo-Json -Compress"
        );
        // Показываем текущее значение до записи: подтверждение без «старого»
        // не даёт оператору увидеть, что именно меняется.
        let read_command = ps::get_registry(&key, &params.value_name);
        let before_reply = self
            .run_value_redacted(
                &identity,
                &params.session_id,
                &read_command,
                "get_registry",
                std::slice::from_ref(&params.value_data),
            )
            .await;
        let before = Self::successful_stdout(&before_reply)
            .map(|stdout| stdout.trim().to_owned())
            .filter(|stdout| !stdout.is_empty())
            .unwrap_or_else(|| "(value not present)".to_owned());
        require_confirmation!(
            &self,
            &ctx,
            "SET REGISTRY VALUE",
            &format!(
                "Key: {key}\nValue: {}\nType: {ps_type}\nOld value: {before}",
                params.value_name
            )
        );
        // Значение записывается как секрет: оно может содержать пароль, и
        // аудит не должен его раскрывать (DR-4).
        let secrets = vec![params.value_data.clone()];
        Ok(self
            .run_redacted(
                &identity,
                &params.session_id,
                &command,
                "set_registry",
                &secrets,
            )
            .await)
    }

    /// Write a file on the remote host.
    #[tool(
        name = "write_file",
        description = "Write a file on the remote host, replacing it as a whole. Refuses protected paths, and refuses an existing file unless overwrite is set. Content travels in ~2 KB chunks because the WinRS command line is limited, so this suits configuration files and scripts rather than large payloads. To run a script too long for one command, write it here and then execute it by path."
    )]
    async fn write_file(
        &self,
        Parameters(params): Parameters<WriteFileParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        // DR-6: лексический отказ до любой сети.
        let decision = decide_write_path(&params.path);
        if !decision.allow {
            return Ok(CallToolResult::structured(
                json!({ "error": decision.reason }),
            ));
        }
        // План строится целиком до сети: предел размера и неизвестная кодировка
        // отказывают, не оставив на хосте ничего (TR-FS-04).
        // Уникальность на вызов: два параллельных вызова в один путь иначе
        // делят временный файл, куски перемешиваются, и первое же
        // переименование забирает файл из-под второго вызова. Суффикс
        // случайный, а не pid со счётчиком: два экземпляра winrig на разных
        // машинах могут получить одинаковый pid и писать на один хост.
        let temp_path = format!("{}.winrig-{}.part", params.path, random_suffix());
        let plan = match ps::write_plan(
            &params.path,
            &temp_path,
            &params.content,
            &params.encoding,
            self.config.max_write_bytes,
        ) {
            Ok(plan) => plan,
            Err(error) => return Ok(CallToolResult::structured(json!({ "error": error }))),
        };

        // Существование цели выясняем у хоста: гонку это не закрывает, но
        // отличает создание от перезаписи в подтверждении (TR-FS-03).
        let probe = self
            .run_value(
                &identity,
                &params.session_id,
                &ps::write_precheck(&params.path),
                "write_file",
            )
            .await;
        let Some(probe_stdout) = Self::successful_stdout(&probe) else {
            return Ok(CallToolResult::structured(json!({
                "error": probe
                    .get("stderr")
                    .and_then(serde_json::Value::as_str)
                    .or_else(|| probe.get("error").and_then(serde_json::Value::as_str))
                    .unwrap_or("Write pre-check failed"),
                "probe": probe,
            })));
        };
        let exists = probe_stdout.trim() == "EXISTS";
        let overwrite_decision = decide_overwrite(&params.path, exists, params.overwrite);
        if !overwrite_decision.allow {
            return Ok(CallToolResult::structured(
                json!({ "error": overwrite_decision.reason }),
            ));
        }

        let bytes = params.content.len();
        require_confirmation!(
            &self,
            &ctx,
            if exists {
                "OVERWRITE FILE"
            } else {
                "WRITE FILE"
            },
            &format!(
                "Path: {}\nBytes: {bytes}\nEncoding: {}\nExisting file: {}\n\n\
                 The file is replaced as a whole.",
                params.path,
                params.encoding,
                if exists { "yes" } else { "no" }
            )
        );

        // Куски и замена идут одной последовательностью: отказ на середине
        // убирает временный файл, цель остаётся прежней (TR-FS-05).
        // DR-4: содержимое едет в команде как base64 и может быть секретом.
        // `redact` ищет подстроку, поэтому редактируем именно то, что в команде
        // и лежит, — саму строку base64. Открытый текст сюда не попадает.
        let steps = plan.len();
        for (index, command) in plan.iter().enumerate() {
            let secrets = base64_payloads(command);
            let reply = self
                .run_value_redacted(
                    &identity,
                    &params.session_id,
                    command,
                    "write_file",
                    &secrets,
                )
                .await;
            if Self::successful_stdout(&reply).is_none() {
                let _ = self
                    .run_value(
                        &identity,
                        &params.session_id,
                        &ps::write_abort(&temp_path),
                        "write_file",
                    )
                    .await;
                return Ok(CallToolResult::structured(json!({
                    "error": format!(
                        "Write failed at step {} of {steps}; the target file was left unchanged",
                        index + 1
                    ),
                    "step": reply,
                })));
            }
        }
        Ok(CallToolResult::structured(json!({
            "status": "written",
            "path": params.path,
            "bytes": bytes,
            "encoding": params.encoding,
            "replaced": exists,
        })))
    }

    /// Permanently delete a single file.
    #[tool(
        name = "delete_file",
        description = "Permanently delete a single file, scanning first and refusing protected paths and directories. Shows the resolved path and metadata in the confirmation prompt."
    )]
    async fn delete_file(
        &self,
        Parameters(params): Parameters<DeleteFileParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        // DR-6: лексический отказ до любой сети.
        let decision = decide_delete_path(&params.path);
        if !decision.allow {
            return Ok(CallToolResult::structured(
                json!({ "error": decision.reason }),
            ));
        }
        let safe = ps::escape(&params.path);

        // Скан хостом: раскрывает полный путь (8.3, reparse) и не даёт удалить
        // каталог через delete_file.
        let scan_command = format!(
            "$item = Get-Item -LiteralPath '{safe}' -Force -ErrorAction Stop; \
             [PSCustomObject]@{{ FullName=$item.FullName; IsDirectory=[bool]$item.PSIsContainer; \
             SizeBytes=if($item.PSIsContainer){{$null}}else{{$item.Length}}; \
             Modified=$item.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') }} \
             | ConvertTo-Json -Compress"
        );
        let pre = self
            .run_value(&identity, &params.session_id, &scan_command, "delete_file")
            .await;
        let Some(stdout) = Self::successful_stdout(&pre) else {
            return Ok(CallToolResult::structured(json!({
                "error": pre
                    .get("stderr")
                    .and_then(serde_json::Value::as_str)
                    .or_else(|| pre.get("error").and_then(serde_json::Value::as_str))
                    .unwrap_or("Delete pre-check failed"),
                "scan": pre,
            })));
        };
        let scan = match FileScan::from_json(&stdout) {
            Ok(scan) => scan,
            Err(error) => {
                return Ok(CallToolResult::structured(json!({
                    "error": format!("{error} Refusing to delete."),
                    "scan": stdout,
                })));
            }
        };
        let scan_decision = decide_file_delete(&scan, &params.path);
        if !scan_decision.allow {
            return Ok(CallToolResult::structured(json!({
                "error": scan_decision.reason,
                "scan": stdout,
            })));
        }

        require_confirmation!(
            &self,
            &ctx,
            "DELETE FILE",
            &format!(
                "Path: {}\nResolved: {}\nMetadata: {}\n\nThis cannot be undone.",
                params.path, scan.full_name, stdout
            )
        );
        let command = format!(
            "Remove-Item -LiteralPath '{safe}' -Force -ErrorAction Stop; \
             if (Test-Path -LiteralPath '{safe}') {{ Write-Output 'WARNING: file still exists' }} \
             else {{ Write-Output 'File deleted successfully' }}"
        );
        Ok(self
            .run(&identity, &params.session_id, &command, "delete_file")
            .await)
    }

    /// Recursively delete a directory.
    #[tool(
        name = "delete_directory",
        description = "Recursively delete a directory and all contents. Scans first and refuses drive roots, system directories and reparse points (junction/symlink), and when the item count exceeds max_items."
    )]
    async fn delete_directory(
        &self,
        Parameters(params): Parameters<DeleteDirectoryParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        // DR-6: лексический отказ до любой сети.
        let decision = decide_delete_path(&params.path);
        if !decision.allow {
            return Ok(CallToolResult::structured(
                json!({ "error": decision.reason }),
            ));
        }
        let cap = params.max_items.clamp(1, 50_000);
        let safe = ps::escape(&params.path);

        // ADR-0005 §5: предварительный скан хостом — единственный способ
        // увидеть реальный FullName (8.3-имена) и признак reparse point.
        let scan_command = format!(
            "$item = Get-Item -LiteralPath '{safe}' -Force -ErrorAction Stop; \
             if (-not $item.PSIsContainer) {{ throw 'Path is a file — use delete_file instead' }}; \
             $isReparse = [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint); \
             $files = @(Get-ChildItem -LiteralPath '{safe}' -Recurse -File -Force -ErrorAction SilentlyContinue | Select-Object -First {limit}); \
             $dirs = @(Get-ChildItem -LiteralPath '{safe}' -Recurse -Directory -Force -ErrorAction SilentlyContinue | Select-Object -First {limit}); \
             $nestedReparse = [bool](@($dirs | Where-Object {{ [bool]($_.Attributes -band [IO.FileAttributes]::ReparsePoint) }}).Count -gt 0); \
             [PSCustomObject]@{{ FullName=$item.FullName; IsReparsePoint=$isReparse; NestedReparsePoint=$nestedReparse; \
             FileCount=$files.Count; DirCount=$dirs.Count; TotalItems=($files.Count + $dirs.Count) }} \
             | ConvertTo-Json -Compress",
            limit = cap + 1
        );
        let pre = self
            .run_value(
                &identity,
                &params.session_id,
                &scan_command,
                "delete_directory",
            )
            .await;
        let Some(stdout) = Self::successful_stdout(&pre) else {
            return Ok(CallToolResult::structured(json!({
                "error": pre
                    .get("stderr")
                    .and_then(serde_json::Value::as_str)
                    .or_else(|| pre.get("error").and_then(serde_json::Value::as_str))
                    .unwrap_or("Delete pre-check failed"),
                "scan": pre,
            })));
        };
        let scan = match DeleteScan::from_json(&stdout) {
            Ok(scan) => scan,
            Err(error) => {
                return Ok(CallToolResult::structured(json!({
                    "error": format!("{error} Refusing to delete."),
                    "scan": stdout,
                })));
            }
        };
        let scan_decision = decide_delete_scan(&scan, &params.path, cap);
        if !scan_decision.allow {
            return Ok(CallToolResult::structured(json!({
                "error": scan_decision.reason,
                "scan": stdout,
            })));
        }

        require_confirmation!(
            &self,
            &ctx,
            "DELETE DIRECTORY (recursive)",
            &format!(
                "Path: {}\nResolved: {}\nItems: {} files + {} dirs\n\nThis deletes ALL its contents and cannot be undone.",
                params.path, scan.full_name, scan.file_count, scan.dir_count
            )
        );
        // TOCTOU: между сканом и удалением дерево могло измениться, поэтому
        // команда удаления сама повторяет защитные проверки и отказывает,
        // если путь стал точкой повторной обработки или в поддереве появилась
        // такая точка. Только после этого вызывается Remove-Item.
        let command = format!(
            "$item = Get-Item -LiteralPath '{safe}' -Force -ErrorAction Stop; \
             if ([bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {{ throw 'Refusing to delete: path is a reparse point (junction/symlink)' }}; \
             $nested = @(Get-ChildItem -LiteralPath '{safe}' -Recurse -Directory -Force -ErrorAction SilentlyContinue \
             | Where-Object {{ [bool]($_.Attributes -band [IO.FileAttributes]::ReparsePoint) }}); \
             if ($nested.Count -gt 0) {{ throw \"Refusing to delete: subtree contains $($nested.Count) reparse point(s)\" }}; \
             Remove-Item -LiteralPath '{safe}' -Recurse -Force -ErrorAction Stop; \
             if (Test-Path -LiteralPath '{safe}') {{ Write-Output 'WARNING: directory still exists' }} \
             else {{ Write-Output 'Directory deleted successfully' }}"
        );
        Ok(self
            .run(&identity, &params.session_id, &command, "delete_directory")
            .await)
    }
}

fn service_state_command(name: &str) -> String {
    let safe = ps::escape(name);
    format!(
        "Get-Service -Name '{safe}' -ErrorAction Stop \
         | Select-Object Name, Status, StartType | ConvertTo-Json -Compress"
    )
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for WinrigServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "Remote Windows administration over WinRM/NTLM. Call connect first. In HTTP mode the \
             request carries X-AD-User (and optionally X-AD-Password) with the shared secret, or a \
             profile token; in stdio mode the identity comes from the profile. Mutating tools \
             require explicit confirmation and refuse to run when the client has no elicitation.",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{
        RegistryConfig, RemoteOutput, SessionTarget, TransportError, WinRmTransport,
    };
    use std::sync::Mutex;

    /// Фиктивный транспорт для проверок слоя сервера.
    struct FakeTransport {
        calls: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl WinRmTransport for FakeTransport {
        async fn run_powershell(
            &self,
            _target: &SessionTarget,
            script: &str,
        ) -> Result<RemoteOutput, TransportError> {
            self.calls.lock().expect("lock").push(script.to_owned());
            Ok(RemoteOutput {
                stdout: b"HOST1|Windows|10.0|2026-01-01 00:00:00".to_vec(),
                stderr: Vec::new(),
                exit_code: 0,
            })
        }
    }

    fn config() -> AppConfig {
        crate::config::load_config_from(&|name| {
            (name == "WINRIG_AUTH_TOKEN").then(|| "token".to_owned())
        })
        .expect("config")
    }

    fn server() -> WinrigServer {
        let transport = Arc::new(FakeTransport {
            calls: Mutex::new(Vec::new()),
        });
        let registry = Arc::new(SessionRegistry::new(transport, RegistryConfig::default()));
        WinrigServer::new(registry, Arc::new(config()))
    }

    #[test]
    fn policy_refuses_protected_delete_before_transport() {
        // Проверяем чистую политику, которую использует инструмент (DR-6).
        assert!(!decide_delete_path("C:\\Windows").allow);
        assert!(decide_delete_path("C:\\App\\logs").allow);
    }

    fn server_with(env: &[(&str, &str)]) -> WinrigServer {
        let overrides: Vec<(String, String)> = env
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        // `Env` не несёт времени жизни, поэтому замыкание обязано владеть
        // данными: ссылка на локальный вектор здесь не живёт достаточно долго.
        let lookup: Box<crate::config::Env> = Box::new(move |name: &str| {
            if name == "WINRIG_AUTH_TOKEN" {
                return Some("token".to_owned());
            }
            overrides
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        });
        let config = crate::config::load_config_from(lookup.as_ref()).expect("config");
        let transport = Arc::new(FakeTransport {
            calls: Mutex::new(Vec::new()),
        });
        let registry = Arc::new(SessionRegistry::new(transport, RegistryConfig::default()));
        WinrigServer::new(registry, Arc::new(config))
    }

    /// TR-FS-01: выключенный инструмент не объявляется. Иначе агент строит
    /// план вокруг возможности, в которой ему откажут.
    #[test]
    fn write_file_is_absent_until_the_operator_enables_it() {
        let off = server_with(&[]);
        let names: Vec<String> = off
            .tool_router
            .list_all()
            .iter()
            .map(|tool| tool.name.to_string())
            .collect();
        assert!(
            !names.iter().any(|name| name == "write_file"),
            "write_file must not be advertised while disabled"
        );
        assert_eq!(names.len(), 37, "expected 37 tools without write_file");

        let on = server_with(&[("WINRIG_ALLOW_FILE_WRITE", "true")]);
        let names: Vec<String> = on
            .tool_router
            .list_all()
            .iter()
            .map(|tool| tool.name.to_string())
            .collect();
        assert!(names.iter().any(|name| name == "write_file"));
        assert_eq!(names.len(), 38, "expected 38 tools with write_file");
    }

    /// TR-FS-01: снятый маршрут не только скрыт из списка, но и не вызывается.
    #[test]
    fn disabled_write_file_has_no_route() {
        assert!(!server_with(&[]).tool_router.has_route("write_file"));
        assert!(
            server_with(&[("WINRIG_ALLOW_FILE_WRITE", "true")])
                .tool_router
                .has_route("write_file")
        );
    }

    /// TR-FS-05: имя временного файла не повторяется между вызовами, иначе
    /// два параллельных вызова в один путь делят его на двоих.
    #[test]
    fn temporary_suffix_differs_between_calls() {
        let first = random_suffix();
        let second = random_suffix();
        assert_ne!(first, second);
        assert_eq!(first.len(), 16, "8 bytes as hex");
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()), "{first}");
    }

    /// DR-4: тело файла едет в команде как base64, и в аудит оно попасть не
    /// должно. Редактируется именно то, что в команде и лежит.
    #[test]
    fn base64_payload_is_extracted_for_redaction() {
        let command = ps::write_chunk("C:\\Temp\\p", "c2VjcmV0", true);
        assert_eq!(base64_payloads(&command), vec!["c2VjcmV0".to_owned()]);
        // Команда без полезной нагрузки не даёт ложных секретов: пустая строка
        // редактировала бы весь вывод.
        assert!(base64_payloads(&ps::write_precheck("C:\\a")).is_empty());
        assert!(base64_payloads(&ps::write_chunk("C:\\Temp\\p", "", true)).is_empty());
    }

    /// TR-FS-02: запись по защищённому пути отвергается политикой до сети.
    #[test]
    fn policy_refuses_protected_write_before_transport() {
        assert!(!decide_write_path("C:\\Windows\\System32\\config").allow);
        assert!(decide_write_path("C:\\App\\config.json").allow);
    }

    #[test]
    fn tool_router_lists_registered_tools() {
        let router = WinrigServer::tool_router();
        let tools = router.list_all();
        assert!(tools.iter().any(|tool| tool.name == "connect"));
        assert!(tools.iter().any(|tool| tool.name == "get_system_info"));
        assert!(tools.iter().any(|tool| tool.name == "delete_directory"));
        // Точное число: «не меньше 30» не поймает ни потерю одного, ни
        // дубликат. Здесь объявленные инструменты целиком; сколько из них
        // увидит агент, решает конфигурация (TR-FS-01), и это проверяет
        // `write_file_is_absent_until_the_operator_enables_it`.
        assert_eq!(tools.len(), 38, "expected 38 declared tools");
        let mut names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 38, "tool names must be unique");
    }

    #[test]
    fn known_mutating_tools_are_present() {
        // DR-5: список модифицирующих инструментов фиксирован; рост множества
        // меняет обещание README и должен быть осознанным.
        let router = WinrigServer::tool_router();
        let tools = router.list_all();
        let mut names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
        names.sort_unstable();
        for expected in [
            "delete_directory",
            "delete_file",
            "flush_dns",
            "kill_process",
            "restart_service",
            "set_registry",
            "start_service",
            "stop_service",
        ] {
            assert!(
                names.binary_search(&expected).is_ok(),
                "mutating tool {expected} is missing"
            );
        }
    }

    #[test]
    fn server_constructs_with_registry_and_config() {
        let server = server();
        assert_eq!(server.config.mcpo_port, 8005);
    }
}
