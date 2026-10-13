//! MCP server: tools bound to the session registry.
//!
//! Identity comes from the headers of the current request (DR-2,
//! [`crate::identity`]). Mutating tools require confirmation through elicitation
//! and do not run without it (DR-5, fail-closed).

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
    DeleteScan, FileScan, PolicyDecision, WriteScan, decide_delete_path, decide_delete_scan,
    decide_file_delete, decide_host, decide_port, decide_tls, decide_write_path, decide_write_scan,
};
use crate::ps;
use crate::session::{SessionRegistry, UserIdentity};

#[derive(Clone)]
pub struct WinrigServer {
    registry: Arc<SessionRegistry>,
    config: Arc<AppConfig>,
    /// Profile identity for stdio, which has no HTTP request (ADR-0009).
    local_identity: Option<Arc<crate::identity::ProfileIdentity>>,
    tool_router: ToolRouter<Self>,
}

impl std::fmt::Debug for WinrigServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WinrigServer").finish_non_exhaustive()
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ConfirmResponse {
    #[schemars(description = "The value `true` runs the operation.")]
    confirm: bool,
}

rmcp::elicit_safe!(ConfirmResponse);

impl WinrigServer {
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

    /// Disabled tools are removed from the router, not hidden (TR-FS-01,
    /// ADR-0013 §2).
    ///
    /// A removed route does not appear in `tools/list` and cannot be called:
    /// the agent must not see a capability it lacks and build a plan on it.
    fn router_for(config: &AppConfig) -> ToolRouter<Self> {
        let mut router = Self::tool_router();
        if !config.allow_file_write {
            router.remove_route("write_file");
        }
        router
    }

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

    /// # Errors
    ///
    /// [`rmcp::model::ErrorData`] with `INVALID_PARAMS` when none is available.
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

    /// Policy refusals are recorded for observability (TR-OBS-03, ADR-0015 §14).
    fn audit_refusal(&self, identity: &RequestIdentity, tool: &str, decision: &PolicyDecision) {
        self.registry
            .audit_refusal(&identity.username, tool, decision.code, &decision.reason);
    }

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

    /// `run_ps` always adds the session password; the values passed here come
    /// from the tool arguments (for example a registry value), so they do not
    /// reach the audit in cleartext (DR-4).
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

    /// `None` means the command did not run or the host returned an error — the
    /// caller must refuse (fail-closed).
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

    /// Read-only, and it runs before the confirmation: if it fails, the prompt
    /// still shows, just without the state block.
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

    /// An empty PID or a missing process yields an honest string, not an empty
    /// one: the prompt must show the target even when it no longer exists.
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

    /// `Ok(())` means the user agreed explicitly. `Err(result)` means the
    /// operation does not run: refusal, cancellation, timeout, or no
    /// confirmation channel (DR-5, fail-closed); `result` is a ready tool
    /// reply. The arguments are sanitized so a value cannot forge the dialog
    /// structure.
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

fn random_suffix() -> String {
    let mut bytes = [0u8; 8];
    rand::fill(&mut bytes);
    bytes.iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// The written file body reaches the command only as `FromBase64String('...')`,
/// so a list of one or two items covers the whole secret in the command (DR-4).
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

/// Returns a ready tool reply when confirmation is not obtained.
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
// Tool parameters
// ---------------------------------------------------------------------------

// User-facing text lives in explicit attributes, so doc comments never reach `tools/list`.

#[derive(Debug, Deserialize, JsonSchema)]
struct ConnectParams {
    #[schemars(
        description = "Hostname or IP address of the Windows host, for example 'web-server-01'."
    )]
    host: String,
    #[schemars(description = "WinRM port. The default is 5985 for HTTP and 5986 for HTTPS.")]
    #[serde(default)]
    port: Option<i64>,
    #[schemars(
        description = "Use the HTTPS transport. The tool derives the value from the port when it is omitted."
    )]
    #[serde(default)]
    use_ssl: Option<bool>,
    #[schemars(description = "Validate the TLS certificate of the host on HTTPS.")]
    #[serde(default = "default_true")]
    verify_cert: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SessionIdParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ListDirectoryParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(
        description = "Absolute path of the directory to list, for example 'C:\\\\Users' or 'D:\\\\Logs'."
    )]
    path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct FindFilesParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "Root directory where the recursive search starts.")]
    path: String,
    #[schemars(description = "Filename wildcard to match, for example '*.log'.")]
    pattern: String,
    #[schemars(description = "Maximum recursion depth. The default is 5 and the maximum is 10.")]
    #[serde(default = "default_depth")]
    max_depth: i64,
    #[schemars(description = "Include the size of each file in the output.")]
    #[serde(default = "default_true")]
    include_size: bool,
}

fn default_depth() -> i64 {
    5
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ReadFileParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "Absolute path of the file to read.")]
    path: String,
    #[schemars(
        description = "First line to return in the range mode. The line numbers start at 1."
    )]
    #[serde(default = "default_one")]
    start_line: i64,
    #[schemars(
        description = "Last line in the range mode. In the tail mode it is the number of lines from the end."
    )]
    #[serde(default = "default_200")]
    end_line: i64,
    #[schemars(description = "Read the last N lines instead of a range.")]
    #[serde(default)]
    tail: bool,
    #[schemars(description = "File encoding. The default is UTF8.")]
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
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(
        description = "Path of one file, or of the narrowest directory to search recursively."
    )]
    path: String,
    #[schemars(
        description = "Distinctive literal text to find. The tool does not accept a regex or wildcards."
    )]
    pattern: String,
    #[schemars(description = "Filename wildcard for a directory search.")]
    #[serde(default = "default_star")]
    file_filter: String,
    #[schemars(description = "Maximum number of matching lines to return. The maximum is 100.")]
    #[serde(default = "default_50")]
    max_results: i64,
    #[schemars(
        description = "Number of lines to show before and after each match. The maximum is 10."
    )]
    #[serde(default)]
    context_lines: i64,
    #[schemars(
        description = "Search only files that changed within this number of hours. The value 0 means all files."
    )]
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
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "Absolute path of the first file (the reference).")]
    path_a: String,
    #[schemars(description = "Absolute path of the second file (the difference).")]
    path_b: String,
    #[schemars(description = "Maximum number of differing lines to show. The maximum is 200.")]
    #[serde(default = "default_50")]
    max_diffs: i64,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct EventLogParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "Event log to read: System (default), Application or Security.")]
    #[serde(default = "default_system")]
    log_name: String,
    #[schemars(
        description = "Severity threshold. The tool includes this level and all higher levels: Critical, Error, Warning, Info."
    )]
    #[serde(default = "default_error_level")]
    level: String,
    #[schemars(description = "Number of hours back to search. The maximum is 720.")]
    #[serde(default = "default_24")]
    hours_back: i64,
    #[schemars(description = "Filter on the provider name. Wildcards are allowed.")]
    #[serde(default)]
    source: String,
    #[schemars(description = "Maximum number of events to return. The maximum is 100.")]
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
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "A wildcard on the Name or the DisplayName.")]
    #[serde(default)]
    name_filter: String,
    #[schemars(description = "Filter on the state: Running, Stopped or All.")]
    #[serde(default = "default_all")]
    status_filter: String,
    #[schemars(description = "Return a deep JSON inspection of each service.")]
    #[serde(default)]
    detail: bool,
}

fn default_all() -> String {
    "All".to_owned()
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ListProcessesParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "A wildcard on the process name.")]
    #[serde(default)]
    name_filter: String,
    #[schemars(description = "Sort in descending order by CPU or Memory.")]
    #[serde(default = "default_memory")]
    sort_by: String,
    #[schemars(description = "Number of processes to show. The maximum is 100.")]
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
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(
        description = "Number of seconds between samples. The parameter is kept for compatibility. The maximum is 10."
    )]
    #[serde(default = "default_two")]
    interval_sec: i64,
    #[schemars(
        description = "Wildcard for the per-process statistics. An empty value omits that section."
    )]
    #[serde(default)]
    process_filter: String,
}

fn default_two() -> i64 {
    2
}

#[derive(Debug, Deserialize, JsonSchema)]
struct RegistryReadParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(
        description = "Registry path with the 'HKLM:\\\\' prefix. The tool also accepts the HKEY_LOCAL_MACHINE form."
    )]
    key: String,
    #[schemars(
        description = "Name of one value to read. An empty value dumps all the values under the key."
    )]
    #[serde(default)]
    value_name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct CertificatesParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "Location of the certificate store: LocalMachine or CurrentUser.")]
    #[serde(default = "default_localmachine")]
    store: String,
    #[schemars(
        description = "Show only the certificates that expire within this number of days. The value 0 shows all."
    )]
    #[serde(default)]
    days_until_expiry: i64,
}

fn default_localmachine() -> String {
    "LocalMachine".to_owned()
}

#[derive(Debug, Deserialize, JsonSchema)]
struct TestNetworkParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "Hostname or IP address to test the connectivity to.")]
    target: String,
    #[schemars(description = "TCP port to test. The value 0 (default) sends an ICMP ping.")]
    #[serde(default)]
    port: i64,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct EnvParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "A wildcard on the variable name.")]
    #[serde(default)]
    name_filter: String,
    #[schemars(description = "Scope of the variables: Machine, User or Process.")]
    #[serde(default = "default_machine")]
    scope: String,
}

fn default_machine() -> String {
    "Machine".to_owned()
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ScheduledTasksParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "A wildcard on the task name.")]
    #[serde(default)]
    name_filter: String,
    #[schemars(description = "Include the disabled tasks.")]
    #[serde(default)]
    include_disabled: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct UserGroupsParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "User to look up. An empty value lists all the local groups.")]
    #[serde(default)]
    username: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct TcpConnectionsParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(
        description = "Filter on the state: Established (default), Listen, TimeWait, CloseWait or All."
    )]
    #[serde(default = "default_established")]
    state_filter: String,
    #[schemars(
        description = "Show only the connections that use this port. The value 0 means all the ports."
    )]
    #[serde(default)]
    port_filter: i64,
}

fn default_established() -> String {
    "Established".to_owned()
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DnsCacheParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "A wildcard on the record name.")]
    #[serde(default)]
    name_filter: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct InstalledSoftwareParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "A wildcard on the software name.")]
    #[serde(default)]
    name_filter: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ResolveDnsParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "Hostname or FQDN to resolve.")]
    name: String,
    #[schemars(
        description = "Type of the record: A (default), AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT."
    )]
    #[serde(default = "default_a")]
    record_type: String,
    #[schemars(
        description = "DNS server to query. An empty value uses the default of the system."
    )]
    #[serde(default)]
    dns_server: String,
}

fn default_a() -> String {
    "A".to_owned()
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ServiceNameParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "Exact name of the service, not the display name.")]
    name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct KillProcessParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "Process ID to kill.")]
    pid: i64,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SetRegistryParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "Registry path, for example 'HKLM:\\\\SOFTWARE\\\\MyApp'.")]
    key: String,
    #[schemars(description = "Name of the registry value to set.")]
    value_name: String,
    #[schemars(description = "Data to write, as a string.")]
    value_data: String,
    #[schemars(
        description = "Type of the value: String, DWord, QWord, ExpandString, MultiString, Binary."
    )]
    #[serde(default = "default_string")]
    value_type: String,
}

fn default_string() -> String {
    "String".to_owned()
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DeleteFileParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "Absolute path of the file to delete.")]
    path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct WriteFileParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "Absolute path of the file to write on the host.")]
    path: String,
    #[schemars(
        description = "Full contents to write. The tool replaces the file and does not append to it."
    )]
    content: String,
    #[schemars(
        description = "Replace the file when it already exists. Without this flag the tool refuses the call, so a new file cannot destroy an existing file by accident."
    )]
    #[serde(default)]
    overwrite: bool,
    #[schemars(description = "Encoding of the written file. The default is UTF-8 without a BOM.")]
    #[serde(default = "default_write_encoding")]
    encoding: String,
}

fn default_write_encoding() -> String {
    "utf8".to_owned()
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DeleteDirectoryParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "Absolute path of the directory to delete recursively.")]
    path: String,
    #[schemars(description = "Safety limit. The tool refuses the call if more items exist.")]
    #[serde(default = "default_5000")]
    max_items: i64,
}

fn default_5000() -> i64 {
    5000
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

#[tool_router]
impl WinrigServer {
    #[tool(
        name = "connect",
        description = "Open a WinRM session to a Windows host. The call returns a session_id. This is the required first step before any other tool. The server takes the AD password from the X-AD-Password request header and caches it in memory only."
    )]
    async fn connect(
        &self,
        Parameters(params): Parameters<ConnectParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        // Policy and transport see the same host string.
        let host = params.host.trim();
        for decision in [
            decide_host(host, &self.config.allowed_hosts),
            decide_port(params.port),
            decide_tls(params.verify_cert, self.config.allow_insecure_tls),
        ] {
            if !decision.allow {
                self.audit_refusal(&identity, "connect", &decision);
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
                host,
                port,
                params.use_ssl,
                params.verify_cert,
            )
            .await;
        Ok(CallToolResult::structured(reply))
    }

    #[tool(
        name = "disconnect",
        description = "Close an active WinRM session and release it. The server does not clean up sessions automatically. Always disconnect when the work is done."
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

    #[tool(
        name = "list_sessions",
        description = "List the active WinRM sessions with host, connection time, last used time and command count."
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

    #[tool(
        name = "list_directory",
        description = "List the files and directories at a path as tabular text (Mode, LastWriteTime, Length, Name)."
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

    #[tool(
        name = "find_files",
        description = "Find the files that match a wildcard pattern, recursively. The tool returns a maximum of 100 results and matches files only."
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

    #[tool(
        name = "read_file",
        description = "Read the contents of a file as numbered lines, with a maximum of 500 lines for each call. The range mode reads start_line through end_line. The tail mode reads the last N lines."
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

    #[tool(
        name = "search_file_content",
        description = "Search for literal text inside files, in the manner of grep. Pass a file path to search one file. Pass a directory to search it recursively."
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

    #[tool(
        name = "file_info",
        description = "Return JSON metadata for one file or one directory: size, timestamps and attributes."
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

    #[tool(
        name = "compare_files",
        description = "Compare two files line by line, in the manner of the diff tool. The result shows each differing line and the file that contains it."
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

    #[tool(
        name = "get_event_log",
        description = "Read the Windows Event Log. Use it for crashes, service failures, authentication errors and disk warnings."
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

    #[tool(
        name = "get_services",
        description = "List the Windows services. The summary mode returns tabular text with Name, Status, StartType and DisplayName. The detail mode returns JSON for each service."
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

    #[tool(
        name = "list_processes",
        description = "List the running processes as tabular text with PID, name, CPU seconds, memory MB, handle count and start time."
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

    #[tool(
        name = "get_system_info",
        description = "Return a system overview as JSON in one call: OS version, uptime, last boot, total and free RAM, CPU count, domain and timezone."
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

    #[tool(
        name = "get_disk_space",
        description = "Return the disk space of all fixed drives as tabular text: DeviceID, Total_GB, Free_GB and Used_Pct."
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

    #[tool(
        name = "get_perf_snapshot",
        description = "Capture a performance snapshot as JSON. The output does not depend on the locale. It holds CPU, memory, disk I/O and network data, and optionally per-process statistics."
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

    #[tool(
        name = "get_registry",
        description = "Read a registry key or one value and return JSON. This tool is read-only."
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

    #[tool(
        name = "get_certificates",
        description = "List the certificates from the Personal (My) store, sorted by the days until expiry. The output shows Subject, Expires, DaysLeft and Thumbprint."
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

    #[tool(
        name = "get_network_config",
        description = "Return the network configuration of each NIC as tabular text: interface name, status, IPv4, gateway and DNS servers."
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

    #[tool(
        name = "test_network",
        description = "Test the connectivity from the perspective of the host. With port=0 the tool sends three ICMP pings. With port>0 it runs a TCP test."
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

    #[tool(
        name = "get_environment_variables",
        description = "Return the environment variables of the chosen scope as tabular text. Each row has a name and a value."
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

    #[tool(
        name = "get_scheduled_tasks",
        description = "List the Windows scheduled tasks as tabular text with name, state, last run time, last result and next run time."
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

    #[tool(
        name = "get_local_users",
        description = "List the local user accounts as tabular text with name, enabled status, last logon and description."
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

    #[tool(
        name = "get_user_groups",
        description = "Show the local group memberships. With no username the tool lists all the local groups and their members. With a username it shows the local groups of that user."
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

    #[tool(
        name = "get_security_context",
        description = "Show the security context of the current WinRM session as JSON: identity, group memberships, privileges and integrity level."
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

    #[tool(
        name = "get_permissions",
        description = "Return the access control list (ACL) of a file or a directory as tabular text: identity, Allow/Deny type, rights and inheritance."
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

    #[tool(
        name = "get_tcp_connections",
        description = "List the active TCP connections as tabular text with local and remote addresses, ports, state and owning process."
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

    #[tool(
        name = "get_dns_cache",
        description = "Read the local DNS client cache as tabular text: record name, type, TTL and resolved data."
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

    #[tool(
        name = "get_installed_software",
        description = "List the installed software as tabular text with name, version, publisher and install date. The tool reads both the 64-bit and the 32-bit uninstall keys."
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

    #[tool(
        name = "resolve_dns_name",
        description = "Resolve a DNS name from the perspective of the host as tabular text. The output shows the full resolution chain, including CNAMEs."
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

    // ---- Mutating operations: they require confirmation (DR-5) ----

    #[tool(
        name = "flush_dns",
        description = "Clear the local DNS client cache on the host. This modifying operation prompts for confirmation."
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

    #[tool(
        name = "restart_service",
        description = "Restart a Windows service. This modifying operation prompts for confirmation. The result shows the state before and after the restart."
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

    #[tool(
        name = "stop_service",
        description = "Stop a running Windows service. This modifying operation prompts for confirmation. The result shows the state before and after the stop."
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

    #[tool(
        name = "start_service",
        description = "Start a stopped Windows service. This modifying operation prompts for confirmation. The result shows the state before and after the start."
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

    #[tool(
        name = "kill_process",
        description = "Terminate a process by PID. The confirmation prompt shows the details of the process."
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
        // Show exactly what will be terminated: a PID without a name is a
        // blind confirmation.
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

    #[tool(
        name = "set_registry",
        description = "Set a registry value and create it if it is absent. The confirmation prompt shows the old value and the new value."
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
        // Show the current value before the write: without the old value the
        // operator cannot see what changes.
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
        // The value is treated as a secret: it may hold a password, and the
        // audit must not reveal it (DR-4).
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

    #[tool(
        name = "write_file",
        description = "Write a file on the host and replace it as a whole. The tool refuses protected paths. It refuses an existing file unless overwrite is set. The content travels in chunks of about 2 KB, because the WinRS command line is limited. Use this tool for configuration files and scripts, not for large payloads. To run a script that is too long for one command, write it here and then execute it by path."
    )]
    async fn write_file(
        &self,
        Parameters(params): Parameters<WriteFileParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        // DR-6: lexical refusal before any network access.
        let decision = decide_write_path(&params.path);
        if !decision.allow {
            self.audit_refusal(&identity, "write_file", &decision);
            return Ok(CallToolResult::structured(
                json!({ "error": decision.reason }),
            ));
        }
        // The plan is built entirely before the network: the size limit and an
        // unknown encoding refuse without leaving anything on the host
        // (TR-FS-04).
        // Unique per call: two parallel calls to one path would otherwise share
        // the temporary file, mix their chunks, and the first rename would take
        // the file from under the second call. The suffix is random, not a pid
        // with a counter: two winrig instances on different machines can get
        // the same pid and write to one host.
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

        // Host-side scan: the path as .NET and PowerShell resolve it, the
        // target's existence, and the host's protected roots (TR-FS-03,
        // TR-FS-06). It does not close the race, but it tells creation from
        // overwrite in the prompt.
        let probe = self
            .run_value(
                &identity,
                &params.session_id,
                &ps::write_scan(&params.path),
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
        let scan = match WriteScan::from_json(&probe_stdout) {
            Ok(scan) => scan,
            Err(error) => {
                return Ok(CallToolResult::structured(json!({
                    "error": format!("{error} Refusing to write."),
                    "scan": probe_stdout,
                })));
            }
        };
        let scan_decision = decide_write_scan(&scan, &params.path, params.overwrite);
        if !scan_decision.allow {
            self.audit_refusal(&identity, "write_file", &scan_decision);
            return Ok(CallToolResult::structured(json!({
                "error": scan_decision.reason,
                "scan": probe_stdout,
            })));
        }
        let exists = scan.exists;

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
                "Path: {}\nResolved: {}\nBytes: {bytes}\nEncoding: {}\nExisting file: {}\n\n\
                 The file is replaced as a whole.",
                params.path,
                scan.full_name,
                params.encoding,
                if exists { "yes" } else { "no" }
            )
        );

        // Chunks and the rename run as one sequence: a failure in the middle
        // removes the temporary file and the target stays unchanged (TR-FS-05).
        // DR-4: the content travels in the command as base64 and may be a
        // secret. `redact` searches for a substring, so we redact exactly what
        // the command carries — the base64 string itself. Cleartext never
        // reaches it.
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

    #[tool(
        name = "delete_file",
        description = "Delete one file permanently. The tool scans first and refuses protected paths and directories. The confirmation prompt shows the resolved path and the metadata."
    )]
    async fn delete_file(
        &self,
        Parameters(params): Parameters<DeleteFileParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        // DR-6: lexical refusal before any network access.
        let decision = decide_delete_path(&params.path);
        if !decision.allow {
            self.audit_refusal(&identity, "delete_file", &decision);
            return Ok(CallToolResult::structured(
                json!({ "error": decision.reason }),
            ));
        }
        let safe = ps::escape(&params.path);

        // Host-side scan: it reveals the full path (8.3, reparse) and prevents
        // deleting a directory through delete_file.
        let scan_command = ps::delete_file_scan(&params.path);
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
            self.audit_refusal(&identity, "delete_file", &scan_decision);
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

    #[tool(
        name = "delete_directory",
        description = "Delete a directory and all its contents, recursively. The tool scans first. It refuses drive roots, system directories and reparse points (junction or symlink). It also refuses a directory with more items than max_items."
    )]
    async fn delete_directory(
        &self,
        Parameters(params): Parameters<DeleteDirectoryParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        // DR-6: lexical refusal before any network access.
        let decision = decide_delete_path(&params.path);
        if !decision.allow {
            self.audit_refusal(&identity, "delete_directory", &decision);
            return Ok(CallToolResult::structured(
                json!({ "error": decision.reason }),
            ));
        }
        let cap = params.max_items.clamp(1, 50_000);
        let safe = ps::escape(&params.path);

        // ADR-0005 §5: the host-side pre-scan is the only way to see the real
        // FullName (8.3 names) and the reparse point flag.
        let scan_command = ps::delete_directory_scan(&params.path, cap + 1);
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
            self.audit_refusal(&identity, "delete_directory", &scan_decision);
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
        // TOCTOU: the tree can change between the scan and the delete, so the
        // delete command repeats the safety checks and refuses if the path
        // became a reparse point or the subtree gained one. Only then does it
        // call Remove-Item.
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
        assert!(!decide_delete_path("C:\\Windows").allow);
        assert!(decide_delete_path("C:\\App\\logs").allow);
    }

    fn server_with(env: &[(&str, &str)]) -> WinrigServer {
        let overrides: Vec<(String, String)> = env
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        // `Env` carries no lifetime, so the closure must own the data: a
        // reference to a local vector does not live long enough here.
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

    /// TR-FS-01: a disabled tool is not advertised. Otherwise the agent builds
    /// a plan around a capability it will be refused.
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

    /// TR-FS-01: a removed route is not only hidden from the list but also uncallable.
    #[test]
    fn disabled_write_file_has_no_route() {
        assert!(!server_with(&[]).tool_router.has_route("write_file"));
        assert!(
            server_with(&[("WINRIG_ALLOW_FILE_WRITE", "true")])
                .tool_router
                .has_route("write_file")
        );
    }

    /// TR-FS-05: the temporary file name does not repeat between calls, or two
    /// parallel calls to one path would share it.
    #[test]
    fn temporary_suffix_differs_between_calls() {
        let first = random_suffix();
        let second = random_suffix();
        assert_ne!(first, second);
        assert_eq!(first.len(), 16, "8 bytes as hex");
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()), "{first}");
    }

    /// DR-4: the file body travels in the command as base64 and must not reach
    /// the audit. Exactly what the command carries is redacted.
    #[test]
    fn base64_payload_is_extracted_for_redaction() {
        let command = ps::write_chunk("C:\\Temp\\p", "c2VjcmV0", true);
        assert_eq!(base64_payloads(&command), vec!["c2VjcmV0".to_owned()]);
        // A command with no payload yields no false secrets: an empty string
        // would redact the whole output.
        assert!(base64_payloads(&ps::write_scan("C:\\a")).is_empty());
        assert!(base64_payloads(&ps::write_chunk("C:\\Temp\\p", "", true)).is_empty());
    }

    /// TR-FS-02: a write to a protected path is refused by the policy before the network.
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
        // An exact count: "at least 30" would catch neither a lost tool nor a
        // duplicate. These are all declared tools; the configuration decides
        // how many the agent sees (TR-FS-01), and
        // `write_file_is_absent_until_the_operator_enables_it` checks that.
        assert_eq!(tools.len(), 38, "expected 38 declared tools");
        let mut names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 38, "tool names must be unique");
    }

    #[test]
    fn known_mutating_tools_are_present() {
        // DR-5: the set of mutating tools is fixed; growing it changes the
        // README promise and must be deliberate.
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

    /// Writes the full `tools/list` payload to the path in `WINRIG_DUMP_TOOLS`
    /// with every tool enabled. It captures the user-facing API before and after
    /// a change so the two payloads can be compared byte for byte; the test does
    /// nothing when the variable is unset (the common run).
    #[test]
    fn dump_tools_when_requested() {
        let Ok(path) = std::env::var("WINRIG_DUMP_TOOLS") else {
            return;
        };
        let server = server_with(&[("WINRIG_ALLOW_FILE_WRITE", "true")]);
        let value =
            serde_json::to_value(server.tool_router.list_all()).expect("serialize tool list");
        let text = serde_json::to_string_pretty(&value).expect("pretty print tool list");
        std::fs::write(&path, format!("{text}\n")).expect("write tool dump");
    }
}
