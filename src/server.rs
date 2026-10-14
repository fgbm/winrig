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

use crate::config::{AppConfig, ConfirmFallback};
use crate::executor::{sanitize_body_value, sanitize_path_value, sanitize_prompt_value};
use crate::identity::RequestIdentity;
use crate::policy::{
    DeleteScan, FileScan, PolicyDecision, WriteScan, decide_command, decide_command_length,
    decide_delete_path, decide_delete_scan, decide_file_delete, decide_host, decide_port,
    decide_script_size, decide_service_target, decide_tls, decide_write_path, decide_write_scan,
};
use crate::ps;
use crate::session::{ScriptRun, SessionRegistry, UserIdentity};

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

/// The header and the body of the dialog that an operator answers before a
/// modifying operation runs (TR-SEC-16..19).
///
/// The header names the tool, the host of the session and the user of the request
/// (DR-2). Each field is sanitized and capped on its own, so a value cannot forge
/// a line or the dialog structure (TR-SEC-19).
struct Confirmation {
    tool: String,
    action: String,
    host: String,
    user: String,
    /// The id that the audit of an absent confirmation records.
    session: String,
    fields: Vec<(String, String)>,
    /// A command or a script, shown in full (TR-SEC-22).
    body: Option<(String, String)>,
    effect: String,
}

impl Confirmation {
    fn new(tool: &str, action: &str, host: &str, user: &str) -> Self {
        Self {
            tool: tool.to_owned(),
            action: action.to_owned(),
            host: host.to_owned(),
            user: user.to_owned(),
            session: String::new(),
            fields: Vec::new(),
            body: None,
            effect: String::new(),
        }
    }

    /// Adds one target or operation line as `label: value`.
    fn field(mut self, label: &str, value: &str) -> Self {
        self.fields.push((label.to_owned(), value.to_owned()));
        self
    }

    /// Adds the full text of a command or a script: the operator confirms what will
    /// run, so the 200-character cap of TR-SEC-19 does not apply. Each line is
    /// rendered with a fixed prefix, so a line cannot forge a header line
    /// (TR-SEC-22, Q-31).
    fn body(mut self, label: &str, value: &str) -> Self {
        self.body = Some((label.to_owned(), sanitize_body_value(value)));
        self
    }

    /// Adds a path-like field: a long value is cut in the middle, so its file name
    /// stays visible (TR-SEC-19).
    fn path(mut self, label: &str, value: &str) -> Self {
        self.fields
            .push((label.to_owned(), sanitize_path_value(value)));
        self
    }

    /// Adds the plain line that states the effect and whether the operator can
    /// undo it (TR-SEC-16).
    fn effect(mut self, text: &str) -> Self {
        self.effect = text.to_owned();
        self
    }

    fn render(&self) -> String {
        let mut message = format!("Confirm {}?\n\n", sanitize_prompt_value(&self.action));
        message.push_str(&format!("Tool: {}\n", sanitize_prompt_value(&self.tool)));
        message.push_str(&format!("Host: {}\n", sanitize_prompt_value(&self.host)));
        message.push_str(&format!("User: {}", sanitize_prompt_value(&self.user)));
        for (label, value) in &self.fields {
            message.push_str(&format!("\n{label}: {}", sanitize_prompt_value(value)));
        }
        if let Some((label, value)) = &self.body {
            message.push_str(&format!("\n{label}:"));
            for line in value.split('\n') {
                message.push_str(&format!("\n  | {line}"));
            }
        }
        if !self.effect.is_empty() {
            message.push_str(&format!("\n\n{}", sanitize_prompt_value(&self.effect)));
        }
        message
    }
}

/// The plain effect line of each modifying tool (TR-SEC-16, TR-SEC-20). Each one
/// states what the operation does and whether the operator can undo it.
const EFFECT_FLUSH_DNS: &str = "This clears the whole DNS client cache. You cannot undo it.";
const EFFECT_RESTART_SERVICE: &str = "This restarts the service. To undo it, stop the service.";
const EFFECT_STOP_SERVICE: &str = "This stops the service. To undo it, start the service.";
const EFFECT_STOP_SERVICE_DISABLE: &str = "This sets the start type to Disabled, then stops the \
                                            service. To undo it, set the start type again and \
                                            start the service.";
const EFFECT_START_SERVICE: &str = "This starts the service. To undo it, stop the service.";
const EFFECT_KILL_PROCESS: &str = "This terminates the process by PID. The child processes \
                                   continue to run. You cannot undo it.";
const EFFECT_SET_REGISTRY: &str =
    "This sets the registry value. To undo it, restore the previous value.";
const EFFECT_WRITE_NEW: &str = "This creates the file. To undo it, delete the file.";
const EFFECT_WRITE_REPLACE: &str =
    "This replaces the whole file. You cannot undo it; the previous content is lost.";
const EFFECT_DELETE_FILE: &str = "This deletes one file permanently. You cannot undo it.";
const EFFECT_DELETE_DIRECTORY: &str = "This deletes the directory and all its contents, \
                                       recursively. The host checks the reparse points again after \
                                       the confirmation. You cannot undo it.";
const EFFECT_SET_START_TYPE: &str = "This changes the start type. The service stays in its \
                                     current state; the change applies at the next start. To undo \
                                     it, set the start type again.";
const EFFECT_RUN_COMMAND: &str =
    "This runs an arbitrary PowerShell command on the host. You cannot undo it.";
const EFFECT_RUN_SCRIPT: &str = "This uploads and runs an arbitrary PowerShell script, then tries to delete the file. You cannot undo it.";

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
        if !config.allow_command_exec {
            router.remove_route("run_command");
        }
        if !config.allow_script_exec {
            router.remove_route("run_script");
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

    /// Records the refusal before any host call (TR-OBS-03, ADR-0015 §14).
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

    /// Reads the current status for the prompt, as a plain word.
    ///
    /// Read-only, and it runs before the confirmation. A failed read gives
    /// `unknown` with a short reason class, never the raw JSON (TR-SEC-17). The
    /// start type comes from [`ps::get_service_config`], which knows
    /// `AutomaticDelayed`.
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
        let Some(stdout) = Self::successful_stdout(&reply) else {
            return unknown_word("unavailable");
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(stdout.trim()) else {
            return unknown_word("unreadable");
        };
        plain_word(value.get("Status"))
    }

    /// Read-only, and it runs before the confirmation: it gives the current value of
    /// one field of [`ps::get_service_config`] for the prompt. A missing or unreadable
    /// answer is an honest string, not an empty one.
    async fn service_field(
        &self,
        identity: &RequestIdentity,
        session_id: &str,
        name: &str,
        field: &str,
    ) -> Result<String, String> {
        let command = ps::get_service_config(name)?;
        let reply = self
            .run_value(identity, session_id, &command, "get_service_config")
            .await;
        let Some(stdout) = Self::successful_stdout(&reply) else {
            return Ok(unknown_word("unavailable"));
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(stdout.trim()) else {
            return Ok(unknown_word("unreadable"));
        };
        Ok(plain_word(value.get(field)))
    }

    /// The name, the executable path and the start time of the process. The command
    /// line is never fetched, so it can carry no secret to the prompt or the audit
    /// (DR-4). A missing process yields an honest object, not an empty one
    /// (TR-SEC-17).
    async fn process_details(
        &self,
        identity: &RequestIdentity,
        session_id: &str,
        pid: i64,
    ) -> serde_json::Value {
        let command = ps::process_details(pid);
        let reply = self
            .run_value(identity, session_id, &command, "list_processes")
            .await;
        Self::successful_stdout(&reply)
            .and_then(|stdout| serde_json::from_str::<serde_json::Value>(stdout.trim()).ok())
            .unwrap_or_else(|| json!({ "Name": "process not found" }))
    }

    /// The user agreed explicitly, the channel is absent and the operator chose to
    /// proceed, or the operation does not run with a ready tool reply (DR-5).
    async fn confirm(
        ctx: &RequestContext<RoleServer>,
        confirmation: Confirmation,
        timeout: Duration,
        fallback: ConfirmFallback,
    ) -> ConfirmationOutcome {
        let action = sanitize_prompt_value(&confirmation.action);
        let message = confirmation.render();
        match ctx
            .peer
            .elicit_with_timeout::<ConfirmResponse>(message, Some(timeout))
            .await
        {
            Ok(Some(response)) if response.confirm => ConfirmationOutcome::Confirmed,
            Ok(Some(_)) | Ok(None) => ConfirmationOutcome::Refused(cancelled(&action)),
            Err(ElicitationError::UserDeclined | ElicitationError::UserCancelled) => {
                ConfirmationOutcome::Refused(cancelled(&action))
            }
            Err(ElicitationError::Service(rmcp::service::ServiceError::Timeout { .. })) => {
                ConfirmationOutcome::Refused(CallToolResult::structured(json!({
                    "error": format!(
                        "Confirmation for {action} timed out after {}s. The operation did not run.",
                        timeout.as_secs()
                    ),
                    "status": "timeout",
                })))
            }
            // TR-SEC-11: only the absent channel can be bypassed, and only by the
            // operator's explicit setting. "Nobody to ask" is not "the user said no".
            // A client that declared elicitation but only in URL mode is refused:
            // it has a channel, the server just cannot use it for a form.
            Err(ElicitationError::CapabilityNotSupported) => {
                let declared = ctx
                    .peer
                    .peer_info()
                    .is_some_and(|info| info.capabilities.elicitation.is_some());
                if fallback == ConfirmFallback::Proceed && !declared {
                    ConfirmationOutcome::Unsupported
                } else {
                    ConfirmationOutcome::Refused(CallToolResult::structured(json!({
                        "error": format!(
                            "The server cannot ask for confirmation. It did not run {action}: the \
                             client has no usable elicitation channel. See the confirmation section \
                             of the documentation."
                        ),
                    })))
                }
            }
            Err(error) => ConfirmationOutcome::Refused(CallToolResult::structured(json!({
                "error": format!(
                    "The server cannot ask for confirmation. It did not run {action}: {error}"
                ),
            }))),
        }
    }

    /// Builds the header of the prompt that an operator answers: the tool name,
    /// the host of the session and the user of the request (TR-SEC-16, DR-2).
    fn confirmation(
        &self,
        identity: &RequestIdentity,
        session_id: &str,
        tool: &str,
        action: &str,
    ) -> Confirmation {
        let host = self
            .registry
            .session_host(&identity.username, session_id)
            .unwrap_or_else(|| "(unknown)".to_owned());
        let mut confirmation = Confirmation::new(tool, action, &host, &identity.username);
        confirmation.session = session_id.to_owned();
        confirmation
    }

    /// The refusal that `run_ps` gives for an unknown session, before any prompt:
    /// the operator is not asked about an operation that cannot run (DR-5).
    fn missing_session(
        &self,
        identity: &RequestIdentity,
        session_id: &str,
    ) -> Option<CallToolResult> {
        self.registry
            .session_host(&identity.username, session_id)
            .is_none()
            .then(|| {
                CallToolResult::structured(json!({
                    "error": format!("Session not found: {session_id}. Use connect first.")
                }))
            })
    }
}

/// The most seconds `stop_service` waits with `wait_seconds`. The wait is bounded, so
/// a call cannot hold the session open without an end.
const MAX_STOP_WAIT_SECONDS: i64 = 600;

fn random_suffix() -> String {
    let mut bytes = [0u8; 8];
    rand::fill(&mut bytes);
    bytes.iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Checks the staging path the host reported: one line, absolute, and exactly the
/// file name the tool asked for (ADR-0017 §31).
///
/// The host resolves `$env:TEMP`, so the value is untrusted. A path with a line
/// break, a relative path or another file name is refused before the confirmation
/// and before any command carries it.
fn validated_temp_path(raw: &str, suffix: &str) -> Option<String> {
    let path = raw.trim();
    if path.is_empty() || path.contains(['\n', '\r']) {
        return None;
    }
    let bytes = path.as_bytes();
    let absolute = path.starts_with("\\\\")
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && (bytes[2] == b'\\' || bytes[2] == b'/'));
    if !absolute {
        return None;
    }
    let name = path.rsplit(['\\', '/']).next().unwrap_or_default();
    (name == format!("winrig-{suffix}.ps1")).then(|| path.to_owned())
}

fn cancelled(action: &str) -> CallToolResult {
    CallToolResult::structured(json!({
        "status": "cancelled",
        "message": format!("The operator cancelled {action}"),
    }))
}

/// The result of one confirmation attempt (TR-SEC-11).
enum ConfirmationOutcome {
    /// Explicit operator agreement.
    Confirmed,
    /// The client declared no channel and the operator set
    /// `WINRIG_CONFIRM_FALLBACK=proceed`; the audit marks the run.
    Unsupported,
    /// The operation does not run; the value is a ready tool reply.
    Refused(CallToolResult),
}

/// Runs the operation on an explicit agreement. An absent channel refuses by
/// default, or runs through the permanent operator agreement, which the audit
/// marks (TR-SEC-11, DR-5).
macro_rules! require_confirmation {
    ($self:expr, $ctx:expr, $confirmation:expr) => {{
        let confirmation = $confirmation;
        let tool = confirmation.tool.clone();
        let user = confirmation.user.clone();
        let host = confirmation.host.clone();
        let session = confirmation.session.clone();
        match WinrigServer::confirm(
            $ctx,
            confirmation,
            std::time::Duration::from_secs($self.config.confirm_timeout_seconds),
            $self.config.confirm_fallback,
        )
        .await
        {
            ConfirmationOutcome::Confirmed => {}
            ConfirmationOutcome::Unsupported => {
                $self
                    .registry
                    .audit_confirmation_unsupported(&user, &tool, &session, &host);
            }
            ConfirmationOutcome::Refused(result) => return Ok(result),
        }
    }};
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
    #[schemars(
        description = "In the tail mode, drop the lines that contain this literal text. The match is case-insensitive and uses no wildcards."
    )]
    #[serde(default)]
    exclude: String,
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
    #[schemars(
        description = "Return the last matches instead of the first. The directory search orders the files by their last write time, oldest first. Use it to read the end of a large log."
    )]
    #[serde(default)]
    from_end: bool,
    #[schemars(
        description = "Return only the number of matching lines for each file. It ignores max_results, context_lines and from_end."
    )]
    #[serde(default)]
    count_only: bool,
    #[schemars(
        description = "Lower time bound of the line timestamp, in the host local time: YYYY-MM-DD HH:MM:SS. A line without a timestamp does not match."
    )]
    #[serde(default)]
    since: String,
    #[schemars(
        description = "Upper time bound of the line timestamp, in the host local time: YYYY-MM-DD HH:MM:SS."
    )]
    #[serde(default)]
    until: String,
    #[schemars(
        description = "The .NET custom format of the timestamp at the start of a line. The default is yyyy-MM-dd HH:mm:ss."
    )]
    #[serde(default)]
    timestamp_format: String,
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
    #[schemars(
        description = "Event log channel to read: System (default), Application, Security or any channel that list_event_logs returns."
    )]
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
struct ListEventLogsParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "Wildcard on the channel name. An empty value lists every channel.")]
    #[serde(default)]
    filter: String,
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
    #[schemars(description = "Also return the names of the child keys.")]
    #[serde(default)]
    subkeys: bool,
    #[schemars(
        description = "Levels of child keys to return. The default is 1 and the range is 1 to 5. Used only when subkeys is true."
    )]
    #[serde(default = "default_one")]
    depth: i64,
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
        description = "Filter on the state: Established (default), Listen, TimeWait, CloseWait, FinWait1, FinWait2, SynReceived, Bound or All."
    )]
    #[serde(default = "default_established")]
    state_filter: String,
    #[schemars(
        description = "Show only the connections that use this port. The value 0 means all the ports."
    )]
    #[serde(default)]
    port_filter: i64,
    #[schemars(
        description = "Show only the connections of this owning process ID. The value 0 means all the processes."
    )]
    #[serde(default)]
    pid: i64,
    #[schemars(
        description = "A wildcard on the owning process name. An empty value means all the processes."
    )]
    #[serde(default)]
    process: String,
    #[schemars(
        description = "Group the rows by process, local port, local address and remote address. The result is JSON with a count for each group and a truncation flag."
    )]
    #[serde(default)]
    summary: bool,
}

fn default_established() -> String {
    "Established".to_owned()
}

#[derive(Debug, Deserialize, JsonSchema)]
struct OpenHandlesParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(
        description = "Absolute path of a file, or of a directory. For a directory the tool checks the files under it."
    )]
    path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct PrintJobsParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "Exact name of the printer, not the share name.")]
    printer: String,
    #[schemars(
        description = "Return the document name and the owner of each job. The default is false, and the tool hides the personal data."
    )]
    #[serde(default)]
    include_personal_data: bool,
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
struct SetServiceStartTypeParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "Exact name of the service, not the display name.")]
    name: String,
    #[schemars(description = "Start type: Automatic, AutomaticDelayed, Manual or Disabled.")]
    start_type: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct StopServiceParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "Exact name of the service, not the display name.")]
    name: String,
    #[schemars(
        description = "Set the start type to Disabled before the stop, so a recovery action cannot start the service again. Default false."
    )]
    #[serde(default)]
    disable: bool,
    #[schemars(
        description = "Seconds to wait after the stop before the tool checks whether the service started again. Default 15."
    )]
    #[serde(default = "default_wait_seconds")]
    wait_seconds: i64,
}

fn default_wait_seconds() -> i64 {
    15
}

#[derive(Debug, Deserialize, JsonSchema)]
struct KillProcessParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    pid: i64,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SetRegistryParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "Registry path, for example 'HKLM:\\\\SOFTWARE\\\\MyApp'.")]
    key: String,
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
struct RunCommandParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(
        description = "PowerShell command to run on the host. The confirmation shows the full text. The encoded wrapper must fit one WinRS command line, so the command holds at most 979 UTF-16 units; a longer script goes through write_file and then runs by path."
    )]
    command: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct RunScriptParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(
        description = "PowerShell script to run on the host. The confirmation shows the whole script. The script obeys WINRIG_MAX_WRITE_BYTES and may be longer than one WinRS command line. The prefix list WINRIG_ALLOWED_COMMANDS does not filter a script."
    )]
    script: String,
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
        description = "Read the contents of a file as numbered lines, with a maximum of 500 lines for each call. The range mode reads start_line through end_line. The tail mode reads the last N lines. In the tail mode, exclude drops the lines that contain a literal text."
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
            &params.exclude,
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
        description = "Search for literal text inside files, in the manner of grep. Pass a file path to search one file. Pass a directory to search it recursively. The tool streams the file. Set from_end to return the last matches, and count_only to return the number of matches for each file. Set since, until and timestamp_format to filter the lines by the timestamp at the start. The from_end and time filters read each file to its end. Use since to narrow the range."
    )]
    async fn search_file_content(
        &self,
        Parameters(params): Parameters<SearchFileContentParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        let options = ps::SearchOptions {
            from_end: params.from_end,
            count_only: params.count_only,
            since: &params.since,
            until: &params.until,
            timestamp_format: &params.timestamp_format,
        };
        let command = match ps::search_file_content(
            &params.path,
            &params.pattern,
            &params.file_filter,
            params.max_results,
            params.context_lines,
            params.modified_after_hours,
            &options,
        ) {
            Ok(command) => command,
            Err(error) => return Ok(CallToolResult::structured(json!({ "error": error }))),
        };
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &command,
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
        name = "list_event_logs",
        description = "List the Windows event log channels with the record count and the enabled state. The record count is null for a channel without a log file. A query without a filter returns a truncated set. Use it to find an operational channel for get_event_log."
    )]
    async fn list_event_logs(
        &self,
        Parameters(params): Parameters<ListEventLogsParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &ps::list_event_logs(&params.filter),
                "list_event_logs",
            )
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
        name = "get_service_config",
        description = "Return one service in JSON: the start type (Automatic, AutomaticDelayed, Manual or Disabled), the account, the binary path and the recovery (failure) actions, each with its action, delay in milliseconds and the reset period in seconds. Read-only. Use it before a start-type change or to see why a stopped service returned."
    )]
    async fn get_service_config(
        &self,
        Parameters(params): Parameters<ServiceNameParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        let command = match ps::get_service_config(&params.name) {
            Ok(command) => command,
            Err(error) => return Ok(CallToolResult::structured(json!({ "error": error }))),
        };
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &command,
                "get_service_config",
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
        description = "Read a registry key or one value and return JSON. With subkeys true, the result also holds the child key names relative to the key. This tool is read-only."
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
                &ps::get_registry(
                    &params.key,
                    &params.value_name,
                    params.subkeys,
                    params.depth,
                ),
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
        description = "List the active TCP connections with local and remote addresses, ports, state and owning process. Filter by state, port, PID or process name. The default output is a text table; the summary mode returns JSON with a count for each group."
    )]
    async fn get_tcp_connections(
        &self,
        Parameters(params): Parameters<TcpConnectionsParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        // The wildcard is bounded before any host call: a long pattern would not
        // fit the WinRS command line (TR-REL-13).
        let process_chars = params.process.chars().count();
        if process_chars > ps::TCP_PROCESS_FILTER_MAX_CHARS {
            return Ok(CallToolResult::structured(json!({
                "error": format!(
                    "process is {process_chars} characters; the limit is {}",
                    ps::TCP_PROCESS_FILTER_MAX_CHARS
                )
            })));
        }
        let command = match ps::get_tcp_connections(
            &params.state_filter,
            params.port_filter,
            params.pid,
            &params.process,
            params.summary,
        ) {
            Ok(command) => command,
            Err(error) => return Ok(CallToolResult::structured(json!({ "error": error }))),
        };
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &command,
                "get_tcp_connections",
            )
            .await)
    }

    #[tool(
        name = "get_open_handles",
        description = "Return the processes that hold a file open, with the PID, the process name and the start time. Pass a file path, or a directory path to check each file under it (up to 200 files): a handle on the directory itself, such as a process working directory, is not visible. A directory with a deep tree can take a long time. The tool uses the Restart Manager, so the host needs no Sysinternals handle.exe. The Restart Manager reports the applications and services that hold the resource, so a process with only a low-level handle can be absent. The result reports files_checked and skipped. Read-only."
    )]
    async fn get_open_handles(
        &self,
        Parameters(params): Parameters<OpenHandlesParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        let command = match ps::get_open_handles(&params.path) {
            Ok(command) => command,
            Err(error) => return Ok(CallToolResult::structured(json!({ "error": error }))),
        };
        Ok(self
            .run(&identity, &params.session_id, &command, "get_open_handles")
            .await)
    }

    #[tool(
        name = "get_printers",
        description = "List the printers on the host with the share name, the driver, the port, the port host and number, the state as the PrinterStatus name and the job count. The result is cut to fit the response size; truncated shows a cut. Read-only."
    )]
    async fn get_printers(
        &self,
        Parameters(params): Parameters<SessionIdParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &ps::get_printers(),
                "get_printers",
            )
            .await)
    }

    #[tool(
        name = "get_print_jobs",
        description = "List the print jobs of one printer with the job id, the state, the size and the submit time. The document name and the owner are personal data and stay hidden unless include_personal_data is true. The result is cut to fit the response size; truncated shows a cut. Read-only."
    )]
    async fn get_print_jobs(
        &self,
        Parameters(params): Parameters<PrintJobsParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        let command = match ps::get_print_jobs(&params.printer, params.include_personal_data) {
            Ok(command) => command,
            Err(error) => return Ok(CallToolResult::structured(json!({ "error": error }))),
        };
        Ok(self
            .run(&identity, &params.session_id, &command, "get_print_jobs")
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
        if let Some(result) = self.missing_session(&identity, &params.session_id) {
            return Ok(result);
        }
        require_confirmation!(
            &self,
            &ctx,
            self.confirmation(
                &identity,
                &params.session_id,
                "flush_dns",
                "FLUSH DNS CACHE"
            )
            .effect(EFFECT_FLUSH_DNS)
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
        description = "Restart a Windows service. This modifying operation prompts for confirmation. The result shows the state before and after the restart. The tool refuses a service that is critical for the remote session."
    )]
    async fn restart_service(
        &self,
        Parameters(params): Parameters<ServiceNameParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        let decision = decide_service_target(&params.name);
        if !decision.allow {
            self.audit_refusal(&identity, "restart_service", &decision);
            return Ok(CallToolResult::structured(
                json!({ "error": decision.reason }),
            ));
        }
        let command = match ps::restart_service(&params.name) {
            Ok(command) => command,
            Err(error) => return Ok(CallToolResult::structured(json!({ "error": error }))),
        };
        if let Some(result) = self.missing_session(&identity, &params.session_id) {
            return Ok(result);
        }
        let before = self
            .service_state(&identity, &params.session_id, &params.name)
            .await;
        require_confirmation!(
            &self,
            &ctx,
            self.confirmation(
                &identity,
                &params.session_id,
                "restart_service",
                "RESTART SERVICE"
            )
            .field("Service", &params.name)
            .field("State before", &before)
            .field("Intended state", "Running")
            .effect(EFFECT_RESTART_SERVICE)
        );
        Ok(self
            .run(&identity, &params.session_id, &command, "restart_service")
            .await)
    }

    #[tool(
        name = "stop_service",
        description = "Stop a running Windows service and verify that it stays stopped. This modifying operation prompts for confirmation. After the stop the tool waits wait_seconds (default 15) and reads the state and the System events 7031, 7034 and 7036 for the service; if the service runs again, the tool returns an error that names the recovery restart. With disable=true the tool sets the start type to Disabled before the stop, so a recovery action cannot start the service again."
    )]
    async fn stop_service(
        &self,
        Parameters(params): Parameters<StopServiceParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        // Fail-closed before any host call: a protected service, and a name with a
        // wildcard, are refused (TR-SEC-15, AC-SEC15-3).
        let decision = decide_service_target(&params.name);
        if !decision.allow {
            self.audit_refusal(&identity, "stop_service", &decision);
            return Ok(CallToolResult::structured(
                json!({ "error": decision.reason }),
            ));
        }
        if !(0..=MAX_STOP_WAIT_SECONDS).contains(&params.wait_seconds) {
            return Ok(CallToolResult::structured(json!({
                "error": format!(
                    "wait_seconds is {}; the range is 0 to {MAX_STOP_WAIT_SECONDS}",
                    params.wait_seconds
                ),
            })));
        }
        if let Some(result) = self.missing_session(&identity, &params.session_id) {
            return Ok(result);
        }
        let before = self
            .service_state(&identity, &params.session_id, &params.name)
            .await;
        let start_type = match self
            .service_field(&identity, &params.session_id, &params.name, "start_type")
            .await
        {
            Ok(value) => value,
            Err(error) => return Ok(CallToolResult::structured(json!({ "error": error }))),
        };
        let command = match ps::stop_service_verified(
            &params.name,
            params.disable,
            params.wait_seconds,
            &start_type,
        ) {
            Ok(command) => command,
            Err(error) => return Ok(CallToolResult::structured(json!({ "error": error }))),
        };
        let mut confirmation = self
            .confirmation(
                &identity,
                &params.session_id,
                "stop_service",
                "STOP SERVICE",
            )
            .field("Service", &params.name)
            .field("State before", &before)
            .field("Current start type", &start_type)
            .field("Intended state", "Stopped");
        confirmation = if params.disable {
            confirmation
                .field("New start type", "Disabled")
                .effect(EFFECT_STOP_SERVICE_DISABLE)
        } else {
            confirmation.effect(EFFECT_STOP_SERVICE)
        };
        require_confirmation!(&self, &ctx, confirmation);
        let reply = self
            .run_value(&identity, &params.session_id, &command, "stop_service")
            .await;
        Ok(self.stop_service_outcome(&params.name, params.wait_seconds, reply))
    }

    /// A stop that failed, or a service that runs again, is a refusal, not a success
    /// (TR-REL-18, AC-REL18-1, finding 6). The half-done state (`start_type_changed`,
    /// `previous_start_type`, `stop_error`) travels in the error. An unreadable answer
    /// passes through.
    fn stop_service_outcome(
        &self,
        name: &str,
        wait_seconds: i64,
        reply: serde_json::Value,
    ) -> CallToolResult {
        let Some(value) = Self::successful_stdout(&reply)
            .and_then(|stdout| serde_json::from_str::<serde_json::Value>(stdout.trim()).ok())
        else {
            return CallToolResult::structured(reply);
        };
        if let Some(stop_error) = value
            .get("stop_error")
            .and_then(serde_json::Value::as_str)
            .filter(|text| !text.is_empty())
        {
            let dependents: Vec<String> = value
                .get("dependents")
                .and_then(serde_json::Value::as_array)
                .map(|list| {
                    list.iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            let named = if dependents.is_empty() {
                String::new()
            } else {
                format!(" Dependent services: {}.", dependents.join(", "))
            };
            return CallToolResult::structured(json!({
                "error": format!(
                    "The stop of {name} failed: {stop_error}{named} Stop the dependent service \
                     first."
                ),
                "start_type_changed": value.get("start_type_changed"),
                "previous_start_type": value.get("previous_start_type"),
                "dependents": value.get("dependents"),
                "result": value,
            }));
        }
        if value
            .get("running_again")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            return CallToolResult::structured(json!({
                "error": format!(
                    "The service {name} runs again {wait_seconds} s after the stop. A recovery action \
                     (restart the service) started it. Set the start type to Disabled, or call \
                     stop_service with disable=true, to keep it stopped."
                ),
                "result": value,
            }));
        }
        CallToolResult::structured(reply)
    }

    #[tool(
        name = "set_service_start_type",
        description = "Set the start type of a Windows service. This modifying operation prompts for confirmation and shows the current and the new start type. The values are Automatic, AutomaticDelayed, Manual and Disabled. The tool refuses a service that is critical for the remote session."
    )]
    async fn set_service_start_type(
        &self,
        Parameters(params): Parameters<SetServiceStartTypeParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        // Fail-closed before any host call (TR-SEC-15, AC-SEC15-3).
        let decision = decide_service_target(&params.name);
        if !decision.allow {
            self.audit_refusal(&identity, "set_service_start_type", &decision);
            return Ok(CallToolResult::structured(
                json!({ "error": decision.reason }),
            ));
        }
        let Some((label, sc_value)) = ps::start_type(&params.start_type) else {
            return Ok(CallToolResult::structured(json!({
                "error": format!(
                    "Invalid start_type '{}'. Valid values: Automatic, AutomaticDelayed, Manual, Disabled",
                    params.start_type
                ),
            })));
        };
        let command = match ps::set_service_start_type(&params.name, label, sc_value) {
            Ok(command) => command,
            Err(error) => return Ok(CallToolResult::structured(json!({ "error": error }))),
        };
        if let Some(result) = self.missing_session(&identity, &params.session_id) {
            return Ok(result);
        }
        let current = match self
            .service_field(&identity, &params.session_id, &params.name, "start_type")
            .await
        {
            Ok(value) => value,
            Err(error) => return Ok(CallToolResult::structured(json!({ "error": error }))),
        };
        require_confirmation!(
            &self,
            &ctx,
            self.confirmation(
                &identity,
                &params.session_id,
                "set_service_start_type",
                "SET SERVICE START TYPE"
            )
            .field("Service", &params.name)
            .field("Current start type", &current)
            .field("New start type", label)
            .effect(EFFECT_SET_START_TYPE)
        );
        Ok(self
            .run(
                &identity,
                &params.session_id,
                &command,
                "set_service_start_type",
            )
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
        if let Some(result) = self.missing_session(&identity, &params.session_id) {
            return Ok(result);
        }
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
            self.confirmation(
                &identity,
                &params.session_id,
                "start_service",
                "START SERVICE"
            )
            .field("Service", &params.name)
            .field("State before", &before)
            .field("Intended state", "Running")
            .effect(EFFECT_START_SERVICE)
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
        if let Some(result) = self.missing_session(&identity, &params.session_id) {
            return Ok(result);
        }
        let command = format!(
            "Stop-Process -Id {pid} -Force -ErrorAction Stop; \
             Write-Output 'Process {pid} terminated'; Start-Sleep -Milliseconds 500; \
             $still = Get-Process -Id {pid} -ErrorAction SilentlyContinue; \
             if ($still) {{ Write-Output 'WARNING: process still running' }} \
             else {{ Write-Output 'Confirmed: process no longer exists' }}"
        );
        // Show exactly what will be terminated: a PID without a name is a blind
        // confirmation (TR-SEC-17). The command line stays out of the prompt and
        // the audit (DR-4).
        let details = self
            .process_details(&identity, &params.session_id, pid)
            .await;
        let process_field = |key: &str| plain_word(details.get(key));
        require_confirmation!(
            &self,
            &ctx,
            self.confirmation(
                &identity,
                &params.session_id,
                "kill_process",
                "TERMINATE PROCESS"
            )
            .field("PID", &pid.to_string())
            .field("Name", &process_field("Name"))
            .field("Executable path", &process_field("ExecutablePath"))
            .field("Started", &process_field("Started"))
            .effect(EFFECT_KILL_PROCESS)
        );
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
                        "Invalid value_type '{other}'. Valid values: String, DWord, QWord, ExpandString, MultiString, Binary"
                    ),
                })));
            }
        };
        let mut key = params.key.trim().to_owned();
        if key.to_uppercase().starts_with("HKEY_") {
            key = format!("Registry::{key}");
        }
        if let Some(result) = self.missing_session(&identity, &params.session_id) {
            return Ok(result);
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
        // DR-4: the old value can be a secret, so the pre-read returns only its
        // existence and its type, never its data.
        let read_command = ps::registry_value_presence(&key, &params.value_name);
        let before_reply = self
            .run_value(&identity, &params.session_id, &read_command, "get_registry")
            .await;
        let before = Self::successful_stdout(&before_reply)
            .and_then(|stdout| serde_json::from_str::<serde_json::Value>(stdout.trim()).ok())
            .map_or_else(|| "unknown".to_owned(), |value| old_value_label(&value));
        require_confirmation!(
            &self,
            &ctx,
            self.confirmation(
                &identity,
                &params.session_id,
                "set_registry",
                "SET REGISTRY VALUE"
            )
            .path("Key", &key)
            .field("Value", &params.value_name)
            .field("Type", ps_type)
            .field("Old value", &before)
            // DR-4, TR-SEC-18: the new value may be a secret, so the prompt
            // shows the marker only.
            .field("New value", "hidden")
            .effect(EFFECT_SET_REGISTRY)
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
        description = "Write a file on the host and replace it as a whole. The tool refuses protected paths. It refuses an existing file unless overwrite is set. The content travels in chunks of about 1.5 KB, because the WinRS command line is limited. The tool refuses a path so long that its commands would not fit that line: about 760 characters for UTF-8 and about 460 characters for the other encodings, for a path with no quote character. Use this tool for configuration files and scripts, not for large payloads. To run a script that is too long for one command, write it here and then execute it by path."
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
        if let Some(result) = self.missing_session(&identity, &params.session_id) {
            return Ok(result);
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
                    "error": format!("{error} The tool refuses to write."),
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
            self.confirmation(
                &identity,
                &params.session_id,
                "write_file",
                if exists {
                    "OVERWRITE FILE"
                } else {
                    "WRITE FILE"
                }
            )
            .path("Path", &params.path)
            .path("Resolved", &scan.full_name)
            .field("Bytes", &bytes.to_string())
            .field("Encoding", &params.encoding)
            .field("Existing file", if exists { "yes" } else { "no" })
            // DR-4, TR-SEC-18: the content may be a secret, so the prompt shows
            // the marker only. The size is a property of the call, not the value.
            .field("Content", "hidden")
            .effect(if exists {
                EFFECT_WRITE_REPLACE
            } else {
                EFFECT_WRITE_NEW
            })
        );

        // Chunks and the rename run as one sequence: a failure in the middle
        // removes the temporary file and the target stays unchanged (TR-FS-05).
        // DR-4: the content travels in the command as base64 and may be a
        // secret. `redact` searches for a substring, so we redact exactly what
        // the command carries — the base64 string itself. Cleartext never
        // reaches it.
        let steps = plan.len();
        for (index, command) in plan.iter().enumerate() {
            let secrets = ps::base64_payloads(command);
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
                        "The write failed at step {} of {steps}. The tool left the target file unchanged.",
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
        name = "run_command",
        description = "Run an arbitrary PowerShell command on the host. This modifying operation prompts for confirmation and shows the full command text. The server refuses a command outside a non-empty WINRIG_ALLOWED_COMMANDS before the call. The encoded wrapper must fit one WinRS command line, so the command holds at most 979 UTF-16 units. For a longer script, write it with write_file and then run it by path. The status code is the exit code of the last native command when it is set, even if the script handled the failure."
    )]
    async fn run_command(
        &self,
        Parameters(params): Parameters<RunCommandParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        // TR-EXE-02: the allowlist refusal is before any network access. The
        // reason never echoes the command, so a secret in it stays out of the
        // audit (DR-4).
        let decision = decide_command(&params.command, &self.config.allowed_commands);
        if !decision.allow {
            self.audit_refusal(&identity, "run_command", &decision);
            return Ok(CallToolResult::structured(
                json!({ "error": decision.reason }),
            ));
        }
        // TR-EXE-04: the length refusal is a policy refusal too, so it reaches the
        // audit before the network and names the limit in UTF-16 units.
        let length = decide_command_length(&params.command, ps::max_command_chars());
        if !length.allow {
            self.audit_refusal(&identity, "run_command", &length);
            return Ok(CallToolResult::structured(
                json!({ "error": length.reason }),
            ));
        }
        if let Some(result) = self.missing_session(&identity, &params.session_id) {
            return Ok(result);
        }
        // The encoded wrapper is built before the prompt: a command that cannot
        // fit one WinRS command line is refused without asking the operator to
        // confirm an operation that cannot run (TR-EXE-04).
        let command = match ps::run_command(&params.command) {
            Ok(command) => command,
            Err(error) => return Ok(CallToolResult::structured(json!({ "error": error }))),
        };
        require_confirmation!(
            &self,
            &ctx,
            self.confirmation(&identity, &params.session_id, "run_command", "RUN COMMAND")
                // TR-EXE-04, TR-SEC-22: the full command text, without the cap.
                .body("Command", &params.command)
                .effect(EFFECT_RUN_COMMAND)
        );
        // DR-4, ADR-0013 §3: the audit redacts the session password and the
        // wrapper's base64, and records the rest of the command text as it is.
        let secrets = ps::base64_payloads(&command);
        Ok(CallToolResult::structured(
            self.registry
                .run_ps_displayed(
                    &identity.username,
                    &params.session_id,
                    &command,
                    &params.command,
                    "run_command",
                    &secrets,
                    &[],
                )
                .await,
        ))
    }

    #[tool(
        name = "run_script",
        description = "Run a PowerShell script that is longer than one WinRS command line. The tool writes the script into a temporary .ps1 in the session temp directory, reads the file and runs its text as a script block, then tries to delete the file. The script has no $PSScriptRoot and no $PSCommandPath, and param() receives no arguments. This modifying operation prompts for one confirmation that shows the whole script and its SHA-256. The server declares the tool only with WINRIG_ALLOW_SCRIPT_EXEC; the prefix list WINRIG_ALLOWED_COMMANDS does not filter a script. The script obeys WINRIG_MAX_WRITE_BYTES. The tool can fail if the script produces no output for 60 seconds. The status code is the exit code of the last native command when it is set, even if the script handled the failure."
    )]
    async fn run_script(
        &self,
        Parameters(params): Parameters<RunScriptParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        if params.script.trim().is_empty() {
            return Ok(CallToolResult::structured(
                json!({ "error": "the script is empty" }),
            ));
        }
        // TR-EXE-06, AC-EXE-07: the size limit is a policy refusal before any host
        // call, so it reaches the audit and names the limit.
        let size = decide_script_size(params.script.len(), self.config.max_write_bytes);
        if !size.allow {
            self.audit_refusal(&identity, "run_script", &size);
            return Ok(CallToolResult::structured(json!({ "error": size.reason })));
        }
        if let Some(result) = self.missing_session(&identity, &params.session_id) {
            return Ok(result);
        }
        // ADR-0017 §31: the staging file lives in the session temp directory with a
        // random name, so two parallel calls or two users do not collide. The host
        // resolves the directory; this read is not a write, so DR-5 is not touched.
        let suffix = random_suffix();
        let probed = self
            .run_value(
                &identity,
                &params.session_id,
                &ps::script_temp_path(&suffix),
                "run_script",
            )
            .await;
        let Some(raw) = Self::successful_stdout(&probed) else {
            return Ok(CallToolResult::structured(json!({
                "error": probed
                    .get("stderr")
                    .and_then(serde_json::Value::as_str)
                    .or_else(|| probed.get("error").and_then(serde_json::Value::as_str))
                    .unwrap_or("The host did not report its temp directory"),
                "probe": probed,
            })));
        };
        // The path comes from the host, so it is validated before it enters any
        // command: one line, absolute, and the file name that the tool asked for.
        let Some(temp_path) = validated_temp_path(&raw, &suffix) else {
            return Ok(CallToolResult::structured(json!({
                "error": "The host returned an unexpected staging path. The tool refused the run.",
                "temp_path": raw.trim(),
            })));
        };
        let hash = ps::script_sha256(&params.script);
        // The whole plan and the run command are built before the confirmation, so
        // a script that cannot run is refused instead of confirmed (AC-EXE-07).
        let plan = match ps::script_plan(&temp_path, &params.script, self.config.max_write_bytes) {
            Ok(plan) => plan,
            Err(error) => return Ok(CallToolResult::structured(json!({ "error": error }))),
        };
        let run = match ps::run_script_file(&temp_path, &hash) {
            Ok(command) => command,
            Err(error) => return Ok(CallToolResult::structured(json!({ "error": error }))),
        };
        let cleanup = ps::script_cleanup(&temp_path);

        // TR-EXE-07, DR-5: one confirmation covers the upload, the run and the
        // delete, and it shows the whole script and its SHA-256 (TR-SEC-22). The
        // staging file is not an operator target, so the write boundary does not
        // apply (ADR-0017 §32); the prompt names its path.
        require_confirmation!(
            &self,
            &ctx,
            self.confirmation(&identity, &params.session_id, "run_script", "RUN SCRIPT")
                .path("Temporary path", &temp_path)
                .field("Bytes", &params.script.len().to_string())
                .field("SHA-256", &hash)
                .field("Command allowlist", "does not filter a script")
                .body("Script", &params.script)
                .effect(EFFECT_RUN_SCRIPT)
        );
        // DR-4: the audit shows the script text and the confirmed hash, and the
        // chunk base64 is redacted; the staging file is removed on every outcome
        // (TR-EXE-06).
        Ok(CallToolResult::structured(
            self.registry
                .run_script(
                    &identity.username,
                    &params.session_id,
                    ScriptRun {
                        chunks: plan.as_slice(),
                        run: run.as_str(),
                        cleanup: cleanup.as_str(),
                        display: params.script.as_str(),
                        hash: &hash,
                    },
                    "run_script",
                )
                .await,
        ))
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
        if let Some(result) = self.missing_session(&identity, &params.session_id) {
            return Ok(result);
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
                    "error": format!("{error} The tool refuses to delete."),
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

        let (size, modified) = scan_metadata(&stdout);
        require_confirmation!(
            &self,
            &ctx,
            self.confirmation(&identity, &params.session_id, "delete_file", "DELETE FILE")
                .path("Path", &params.path)
                .path("Resolved", &scan.full_name)
                .field("Size", &size)
                .field("Modified", &modified)
                .effect(EFFECT_DELETE_FILE)
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
        if let Some(result) = self.missing_session(&identity, &params.session_id) {
            return Ok(result);
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
                    "error": format!("{error} The tool refuses to delete."),
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
            self.confirmation(
                &identity,
                &params.session_id,
                "delete_directory",
                "DELETE DIRECTORY (recursive)"
            )
            .path("Path", &params.path)
            .path("Resolved", &scan.full_name)
            .field(
                "Items",
                &format!("{} files + {} directories", scan.file_count, scan.dir_count)
            )
            .effect(EFFECT_DELETE_DIRECTORY)
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

/// The service state as a plain string, so the prompt shows a word (`Running`,
/// `Stopped`), not the JSON of an enum (TR-SEC-17). The start type is read
/// separately, because only `get_service_config` knows `AutomaticDelayed`.
fn service_state_command(name: &str) -> String {
    let safe = ps::escape(name);
    format!(
        "$s = Get-Service -Name '{safe}' -ErrorAction Stop | Select-Object -First 1; \
         [PSCustomObject]@{{ Status=[string]$s.Status }} | ConvertTo-Json -Compress"
    )
}

/// The plain string of a prompt field, or `unknown` when the host gave none.
fn plain_word(value: Option<&serde_json::Value>) -> String {
    value
        .and_then(serde_json::Value::as_str)
        .filter(|text| !text.is_empty())
        .unwrap_or("unknown")
        .to_owned()
}

/// `unknown` with a short reason class, never the raw JSON of a failed read.
fn unknown_word(reason: &str) -> String {
    format!("unknown ({reason})")
}

/// `present (hidden)` with the old value's type, `not present`, or `unknown`. The
/// data is never shown (DR-4, TR-SEC-18).
fn old_value_label(value: &serde_json::Value) -> String {
    match value.get("state").and_then(serde_json::Value::as_str) {
        Some("present") => match value.get("type").and_then(serde_json::Value::as_str) {
            Some(kind) if !kind.is_empty() => format!("present (hidden, {kind})"),
            _ => "present (hidden)".to_owned(),
        },
        Some("absent") => "not present".to_owned(),
        // An access-denied read is not "not present": the operator must not act on
        // a wrong assumption.
        _ => "unknown".to_owned(),
    }
}

/// The size and the modification time of a scanned file, in the invariant format
/// the scan emits (TR-SEC-17). A missing field gives `unknown`.
fn scan_metadata(stdout: &str) -> (String, String) {
    let Some(value) = serde_json::from_str::<serde_json::Value>(stdout.trim()).ok() else {
        return ("unknown".to_owned(), "unknown".to_owned());
    };
    let size = match value.get("SizeBytes").and_then(serde_json::Value::as_i64) {
        Some(bytes) => format!("{bytes} bytes"),
        None => "unknown".to_owned(),
    };
    (size, plain_word(value.get("Modified")))
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for WinrigServer {
    fn get_info(&self) -> ServerConfig {
        let confirmation = match self.config.confirm_fallback {
            ConfirmFallback::Refuse => {
                "Modifying tools require explicit confirmation and refuse to run when the client \
                 has no elicitation channel."
            }
            ConfirmFallback::Proceed => {
                "Modifying tools require explicit confirmation. WINRIG_CONFIRM_FALLBACK=proceed is \
                 set, so when the client declares no elicitation channel at all a modifying tool \
                 runs and the audit marks the absent confirmation. This lifts fail-closed for every \
                 modifying tool, deletion included. A client that declares elicitation only in URL \
                 mode is still refused. See the confirmation section of the documentation."
            }
        };
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            format!(
                "Remote Windows administration over WinRM/NTLM. Call connect first. In HTTP mode \
                 the request carries X-AD-User (and optionally X-AD-Password) with the shared \
                 secret, or a profile token. In stdio mode the identity comes from the profile. \
                 {confirmation}"
            ),
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

    /// DR-6: the tool applies this pure decision before any network call.
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
        assert_eq!(names.len(), 43, "expected 43 tools without write_file");

        let on = server_with(&[("WINRIG_ALLOW_FILE_WRITE", "true")]);
        let names: Vec<String> = on
            .tool_router
            .list_all()
            .iter()
            .map(|tool| tool.name.to_string())
            .collect();
        assert!(names.iter().any(|name| name == "write_file"));
        assert_eq!(names.len(), 44, "expected 44 tools with write_file");
    }

    /// TR-EXE-01, AC-EXE-01: a disabled `run_command` is not advertised and has
    /// no route. Enabling it adds exactly one tool.
    #[test]
    fn run_command_is_absent_until_the_operator_enables_it() {
        let off = server_with(&[]);
        let names: Vec<String> = off
            .tool_router
            .list_all()
            .iter()
            .map(|tool| tool.name.to_string())
            .collect();
        assert!(
            !names.iter().any(|name| name == "run_command"),
            "run_command must not be advertised while disabled"
        );
        assert_eq!(names.len(), 43, "expected 43 tools without run_command");
        assert!(!off.tool_router.has_route("run_command"));

        let on = server_with(&[("WINRIG_ALLOW_COMMAND_EXEC", "true")]);
        let names: Vec<String> = on
            .tool_router
            .list_all()
            .iter()
            .map(|tool| tool.name.to_string())
            .collect();
        assert!(names.iter().any(|name| name == "run_command"));
        assert_eq!(names.len(), 44, "expected 44 tools with run_command");
        assert!(on.tool_router.has_route("run_command"));
    }

    /// TR-EXE-05, AC-EXE-05: a disabled `run_script` is not advertised and has no
    /// route. Enabling it adds exactly one tool.
    #[test]
    fn run_script_is_absent_until_the_operator_enables_it() {
        let off = server_with(&[]);
        let names: Vec<String> = off
            .tool_router
            .list_all()
            .iter()
            .map(|tool| tool.name.to_string())
            .collect();
        assert!(
            !names.iter().any(|name| name == "run_script"),
            "run_script must not be advertised while disabled"
        );
        assert_eq!(names.len(), 43, "expected 43 tools without run_script");
        assert!(!off.tool_router.has_route("run_script"));

        let on = server_with(&[("WINRIG_ALLOW_SCRIPT_EXEC", "true")]);
        let names: Vec<String> = on
            .tool_router
            .list_all()
            .iter()
            .map(|tool| tool.name.to_string())
            .collect();
        assert!(names.iter().any(|name| name == "run_script"));
        assert_eq!(names.len(), 44, "expected 44 tools with run_script");
        assert!(on.tool_router.has_route("run_script"));
    }

    /// TR-EXE-06, AC-EXE-07: a script above the byte limit is refused before the
    /// network with the real size and the limit. The plan carries the same
    /// refusal.
    #[test]
    fn run_script_refuses_a_script_above_the_limit() {
        let limit = 64 * 1024;
        let over = "a".repeat(limit + 1);
        let decision = decide_script_size(over.len(), limit);
        assert!(!decision.allow);
        assert_eq!(decision.code, "SCRIPT_TOO_LONG");
        assert!(decision.reason.contains(&(limit + 1).to_string()));
        assert!(decision.reason.contains(&limit.to_string()));
        assert!(
            ps::script_plan("C:\\Temp\\winrig-a.ps1", &over, limit).is_err(),
            "the plan must refuse the over-long script"
        );
        assert!(ps::script_plan("C:\\Temp\\winrig-a.ps1", "Write-Output 1", limit).is_ok());
    }

    /// TR-EXE-02, AC-EXE-02: a command inside a non-empty allowlist reaches the
    /// transport; a command outside it is refused by the policy before the
    /// network. The confirmation branch is covered through the MCP harness in
    /// `tests/tool_calls.rs`, which builds a `RequestContext`.
    #[tokio::test]
    async fn allowed_command_reaches_the_transport() {
        let transport = Arc::new(FakeTransport {
            calls: Mutex::new(Vec::new()),
        });
        let registry = Arc::new(SessionRegistry::new(
            Arc::clone(&transport) as Arc<dyn WinRmTransport>,
            RegistryConfig::default(),
        ));
        let lookup: Box<crate::config::Env> = Box::new(|name: &str| match name {
            "WINRIG_AUTH_TOKEN" => Some("token".to_owned()),
            "WINRIG_ALLOWED_HOSTS" => Some("host1".to_owned()),
            "WINRIG_ALLOWED_COMMANDS" => Some("Get-Service".to_owned()),
            _ => None,
        });
        let config = crate::config::load_config_from(lookup.as_ref()).expect("config");
        let server = WinrigServer::new(registry, Arc::new(config));
        let identity = RequestIdentity {
            username: "contoso\\alice".to_owned(),
            password: Some("s3cret".to_owned().into()),
            source: crate::identity::IdentitySource::Headers,
        };
        let user = WinrigServer::user(&identity);
        server
            .registry
            .connect(&user, "host1", None, None, true)
            .await;

        // Inside the list: the wrapper reaches the host.
        let command = ps::run_command("Get-Service").expect("fits");
        server
            .run(&identity, "host1", &command, "run_command")
            .await;
        assert!(
            transport
                .calls
                .lock()
                .expect("lock")
                .iter()
                .any(|call| call.contains("[ScriptBlock]::Create")),
            "the allowed command never reached the host"
        );

        // Outside the list: the decision refuses, so the tool never calls the
        // host with it.
        assert!(!decide_command("whoami", &server.config.allowed_commands).allow);
        assert!(decide_command("Get-Service -Name Spooler", &server.config.allowed_commands).allow);
    }

    /// TR-SEC-22, AC-SEC22-1: the body of a command is shown in full, while a
    /// metadata field obeys the 200-character cap.
    #[test]
    fn metadata_fields_obey_the_prompt_cap() {
        let long = "a".repeat(500);
        let prompt = Confirmation::new("run_command", "RUN COMMAND", "host1", "contoso\\alice")
            .field("Session", &long)
            .body("Command", &long)
            .render();
        let session = prompt
            .lines()
            .find(|line| line.starts_with("Session: "))
            .expect("a session line");
        assert_eq!(
            session.trim_start_matches("Session: ").chars().count(),
            200,
            "a metadata field must obey the cap"
        );
        // The body renders on its own lines with the `  | ` prefix, so the long
        // command must not be cut.
        let command = prompt
            .lines()
            .find(|line| line.starts_with("  | "))
            .expect("a command body line");
        assert_eq!(
            command.trim_start_matches("  | ").chars().count(),
            500,
            "the body must stay in full"
        );
    }

    /// TR-SEC-22, AC-SEC22-1: a multi-line body renders line by line with a fixed
    /// prefix, so CRLF collapses to LF and an injected line cannot forge a header
    /// line or a field line.
    #[test]
    fn body_renders_line_by_line_without_forging_a_header() {
        let body = "Get-Service\r\nWrite-Output '#'\nTool: run_command";
        let prompt = Confirmation::new("run_command", "RUN COMMAND", "host1", "contoso\\alice")
            .field("Session", "host1")
            .body("Command", body)
            .render();
        let body_lines: Vec<&str> = prompt
            .lines()
            .skip_while(|line| *line != "Command:")
            .skip(1)
            .take_while(|line| line.starts_with("  | "))
            .collect();
        assert_eq!(body_lines.len(), 3, "{prompt}");
        assert_eq!(body_lines[0], "  | Get-Service", "{prompt}");
        assert_eq!(body_lines[1], "  | Write-Output '#'", "{prompt}");
        assert_eq!(body_lines[2], "  | Tool: run_command", "{prompt}");
        // The injected `Tool:` line carries the prefix, so the genuine header stays
        // the only line that reads as a header.
        assert_eq!(
            prompt
                .lines()
                .filter(|line| *line == "Tool: run_command")
                .count(),
            1,
            "{prompt}"
        );
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

    /// TR-EXE-06: the staging path the host reports is validated before it enters
    /// any command. A relative path, a line break or another file name is refused.
    #[test]
    fn staging_path_is_validated_against_the_requested_name() {
        assert_eq!(
            validated_temp_path("C:\\Windows\\Temp\\winrig-abc.ps1", "abc").as_deref(),
            Some("C:\\Windows\\Temp\\winrig-abc.ps1")
        );
        assert_eq!(
            validated_temp_path("\\\\host\\share\\winrig-abc.ps1", "abc").as_deref(),
            Some("\\\\host\\share\\winrig-abc.ps1")
        );
        // Another file, a relative path and a line break are all refused.
        assert!(validated_temp_path("C:\\Windows\\System32\\x.ps1", "abc").is_none());
        assert!(validated_temp_path("Temp\\winrig-abc.ps1", "abc").is_none());
        assert!(validated_temp_path("C:\\Temp\\winrig-abc.ps1\nX", "abc").is_none());
        assert!(validated_temp_path("C:\\Temp\\winrig-other.ps1", "abc").is_none());
        assert!(validated_temp_path("  ", "abc").is_none());
    }

    /// DR-4: the file body travels in the command as base64 and must not reach
    /// the audit. Exactly what the command carries is redacted.
    #[test]
    fn base64_payload_is_extracted_for_redaction() {
        let command = ps::write_chunk("C:\\Temp\\p", "c2VjcmV0", true);
        assert_eq!(ps::base64_payloads(&command), vec!["c2VjcmV0".to_owned()]);
        // A command with no payload yields no false secrets: an empty string
        // would redact the whole output.
        assert!(ps::base64_payloads(&ps::write_scan("C:\\a")).is_empty());
        assert!(ps::base64_payloads(&ps::write_chunk("C:\\Temp\\p", "", true)).is_empty());
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
        assert!(tools.iter().any(|tool| tool.name == "get_open_handles"));
        assert!(tools.iter().any(|tool| tool.name == "get_printers"));
        assert!(tools.iter().any(|tool| tool.name == "get_print_jobs"));
        assert!(tools.iter().any(|tool| tool.name == "get_service_config"));
        assert!(
            tools
                .iter()
                .any(|tool| tool.name == "set_service_start_type")
        );
        assert!(tools.iter().any(|tool| tool.name == "delete_directory"));
        assert!(tools.iter().any(|tool| tool.name == "run_command"));
        assert!(tools.iter().any(|tool| tool.name == "run_script"));
        // An exact count: "at least 30" would catch neither a lost tool nor a
        // duplicate. These are all declared tools; the configuration decides
        // how many the agent sees (TR-FS-01, TR-EXE-01, TR-EXE-05), and
        // `write_file_is_absent_until_the_operator_enables_it`,
        // `run_command_is_absent_until_the_operator_enables_it` and
        // `run_script_is_absent_until_the_operator_enables_it` check that.
        assert_eq!(tools.len(), 46, "expected 46 declared tools");
        let mut names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 46, "tool names must be unique");
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
            "run_command",
            "run_script",
            "set_registry",
            "set_service_start_type",
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

    /// TR-SEC-16, TR-SEC-20: every effect sentence fits the 200-character prompt
    /// cap, so no effect line is silently cut.
    #[test]
    fn every_effect_sentence_fits_the_prompt_cap() {
        for effect in [
            EFFECT_FLUSH_DNS,
            EFFECT_RESTART_SERVICE,
            EFFECT_STOP_SERVICE,
            EFFECT_STOP_SERVICE_DISABLE,
            EFFECT_START_SERVICE,
            EFFECT_KILL_PROCESS,
            EFFECT_SET_REGISTRY,
            EFFECT_WRITE_NEW,
            EFFECT_WRITE_REPLACE,
            EFFECT_DELETE_FILE,
            EFFECT_DELETE_DIRECTORY,
            EFFECT_SET_START_TYPE,
            EFFECT_RUN_COMMAND,
            EFFECT_RUN_SCRIPT,
        ] {
            assert!(!effect.is_empty(), "an effect line is empty");
            assert!(
                effect.chars().count() < 200,
                "the effect is too long: {effect}"
            );
        }
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
