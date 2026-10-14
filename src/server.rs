//! MCP server: tools bound to the session registry.
//!
//! Identity comes from the headers of the current request (DR-2,
//! [`crate::identity`]). Mutating tools require confirmation through elicitation
//! and do not run without it (DR-5, fail-closed).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
    DeleteScan, FileScan, PolicyDecision, SourceScan, TransferScan, WriteScan, decide_command,
    decide_command_length, decide_create_directory, decide_delete_file_path, decide_delete_path,
    decide_delete_scan, decide_file_delete, decide_file_op_source, decide_file_op_target,
    decide_host, decide_move_volume, decide_new_name, decide_path_relation, decide_port,
    decide_script_size, decide_service_target, decide_tls, decide_write_path, decide_write_scan,
    is_case_only_change, same_volume,
};
use crate::ps;
use crate::session::{AuditTransfer, ScriptRun, SessionRegistry, UserIdentity};
use sha2::{Digest, Sha256};

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
const EFFECT_COPY_FILE: &str = "This copies the file. To undo it, delete the copy.";
const EFFECT_COPY_DIRECTORY: &str =
    "This copies the directory and its whole content. To undo it, delete the copy.";
const EFFECT_MOVE: &str = "This moves the object. To undo it, move it back.";
const EFFECT_RENAME: &str =
    "This renames the object in its own directory. To undo it, rename it back.";
const EFFECT_CREATE_DIRECTORY: &str =
    "This creates the directory and its missing parents. To undo it, delete the new directory.";
const EFFECT_DOWNLOAD_FILE: &str = "This copies the file from the host into the local transfer \
                                    directory. You cannot undo it.";
const EFFECT_UPLOAD_NEW: &str = "This creates the file on the host from the local transfer file. \
                                 To undo it, delete the file.";
const EFFECT_UPLOAD_REPLACE: &str = "This replaces the whole file on the host with the local \
                                     transfer file. You cannot undo it; the previous content is lost.";

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
        if !config.allow_file_ops {
            router.remove_route("copy_file");
            router.remove_route("move_file");
            router.remove_route("rename_file");
            router.remove_route("create_directory");
        }
        if !config.allow_file_download {
            router.remove_route("download_file");
        }
        if !config.allow_file_upload {
            router.remove_route("upload_file");
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

    /// Runs a read-only pre-scan and returns its stdout, or a ready refusal. A scan
    /// that did not run or did not parse refuses the operation (fail-closed,
    /// ADR-0005 §5): an unreadable answer is never "safe by default".
    async fn pre_scan(
        &self,
        identity: &RequestIdentity,
        session_id: &str,
        command: &str,
        tool: &str,
    ) -> Result<String, CallToolResult> {
        let reply = self.run_value(identity, session_id, command, tool).await;
        Self::successful_stdout(&reply).ok_or_else(|| {
            CallToolResult::structured(json!({
                "error": reply
                    .get("stderr")
                    .and_then(serde_json::Value::as_str)
                    .or_else(|| reply.get("error").and_then(serde_json::Value::as_str))
                    .unwrap_or("The pre-scan did not return a result."),
                "scan": reply,
            }))
        })
    }

    /// A scan or host answer that did not parse refuses the operation (fail-closed).
    fn parse_refusal<T>(
        result: Result<T, String>,
        verb: &str,
        raw: &str,
    ) -> Result<T, CallToolResult> {
        result.map_err(|error| {
            CallToolResult::structured(json!({
                "error": format!("{error} The tool refuses to {verb}."),
                "scan": raw,
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
        let _state = confirm_state!($self, $ctx, $confirmation);
    }};
}

/// The same as [`require_confirmation`] but it yields the confirmation state
/// (`confirmed` or `unsupported`) for the audit record of the tool (ADR-0017 §38).
macro_rules! confirm_state {
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
            ConfirmationOutcome::Confirmed => "confirmed",
            ConfirmationOutcome::Unsupported => {
                $self
                    .registry
                    .audit_confirmation_unsupported(&user, &tool, &session, &host);
                "unsupported"
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

#[derive(Debug, Deserialize, JsonSchema)]
struct CopyFileParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(
        description = "Absolute path of the file or the directory to copy. A path under a system directory is allowed for a copy."
    )]
    source: String,
    #[schemars(
        description = "Absolute path of the destination. The tool refuses an existing target unless overwrite is set, and it never replaces an existing directory."
    )]
    target: String,
    #[schemars(description = "Replace an existing file target. The default is false.")]
    #[serde(default)]
    overwrite: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct MoveFileParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "Absolute path of the file or the directory to move.")]
    source: String,
    #[schemars(
        description = "Absolute path of the destination. On one volume the host renames the object. Across volumes the tool copies a file and then deletes the source; it refuses a cross-volume directory move."
    )]
    target: String,
    #[schemars(description = "Replace an existing file target. The default is false.")]
    #[serde(default)]
    overwrite: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct RenameFileParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "Absolute path of the file or the directory to rename.")]
    path: String,
    #[schemars(
        description = "New name of the last path component. Pass one file name, not a path: a separator, a reserved device name and a trailing dot or space are refused."
    )]
    new_name: String,
    #[schemars(description = "Replace an existing file of the new name. The default is false.")]
    #[serde(default)]
    overwrite: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct CreateDirectoryParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(
        description = "Absolute path of the directory to create. The tool also creates each missing parent."
    )]
    path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DownloadFileParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(description = "Absolute path of the file to read on the host.")]
    remote_path: String,
    #[schemars(
        description = "Local file name in the transfer directory. Pass one plain file name, not a path."
    )]
    name: String,
    #[schemars(
        description = "Replace the local file when it already exists. The default is false."
    )]
    #[serde(default)]
    overwrite: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct UploadFileParams {
    #[schemars(description = "Session ID that connect returns.")]
    session_id: String,
    #[schemars(
        description = "Local file name in the transfer directory. Pass one plain file name, not a path."
    )]
    name: String,
    #[schemars(description = "Absolute path of the file to write on the host.")]
    remote_path: String,
    #[schemars(description = "Replace the file on the host when it exists. The default is false.")]
    #[serde(default)]
    overwrite: bool,
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
            "if (-not (Test-Path -LiteralPath '{safe_key}')) {{ New-Item -LiteralPath '{safe_key}' -Force | Out-Null }}; \
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
        description = "Write a file on the host and replace it as a whole. The tool refuses a device volume path, an 8.3 name, a symbolic link or a junction, and an existing directory. An operator allowlist entry in WINRIG_WRITE_ALLOW_PATHS can permit a protected path; the confirmation then warns for a system directory, a volume root or a share root. It refuses an existing file unless overwrite is set. The content travels in chunks of about 1.5 KB, because the WinRS command line is limited. The tool refuses a path so long that its commands would not fit that line: about 530 characters for UTF-8 and about 470 characters for the other encodings, for a path with no quote character. Use this tool for configuration files and scripts, not for large payloads. To run a script that is too long for one command, write it here and then execute it by path."
    )]
    async fn write_file(
        &self,
        Parameters(params): Parameters<WriteFileParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        // DR-6: lexical refusal before any network access. ADR-0017 §9: an
        // operator allowlist entry that covers the path lifts the refusal.
        let decision = decide_write_path(&params.path, &self.config.write_allow_paths);
        if !decision.allow {
            self.audit_refusal(&identity, "write_file", &decision);
            return Ok(CallToolResult::structured(
                json!({ "error": decision.reason }),
            ));
        }
        if let Some(result) = self.missing_session(&identity, &params.session_id) {
            return Ok(result);
        }
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
        let scan_decision = decide_write_scan(
            &scan,
            &params.path,
            params.overwrite,
            &self.config.write_allow_paths,
        );
        if !scan_decision.allow {
            self.audit_refusal(&identity, "write_file", &scan_decision);
            return Ok(CallToolResult::structured(json!({
                "error": scan_decision.reason,
                "scan": probe_stdout,
            })));
        }
        let exists = scan.exists;
        // The chunks and the replacement reach the host as .NET calls, so they use
        // the .NET-resolved path, not the raw request text (ADR-0017 §18).
        // Unique per call: two parallel calls to one path would otherwise share the
        // temporary file and the first rename would take it from the second call. The
        // suffix is random, not a pid with a counter: two winrig instances can get the
        // same pid.
        let target_path = scan.dotnet_full_name.clone();
        let temp_path = format!("{target_path}.winrig-{}.part", random_suffix());
        // The plan is built before the confirmation: the size limit and an unknown
        // encoding refuse without leaving anything on the host (TR-FS-04).
        let plan = match ps::write_plan(
            &target_path,
            &temp_path,
            &params.content,
            &params.encoding,
            self.config.max_write_bytes,
        ) {
            Ok(plan) => plan,
            Err(error) => return Ok(CallToolResult::structured(json!({ "error": error }))),
        };

        let bytes = params.content.len();
        let mut confirmation = self
            .confirmation(
                &identity,
                &params.session_id,
                "write_file",
                if exists {
                    "OVERWRITE FILE"
                } else {
                    "WRITE FILE"
                },
            )
            .path("Path", &params.path)
            .path("Resolved", &scan.full_name)
            .field("Bytes", &bytes.to_string())
            .field("Encoding", &params.encoding)
            .field("Existing file", if exists { "yes" } else { "no" })
            // DR-4, TR-SEC-18: the content may be a secret, so the prompt shows
            // the marker only. The size is a property of the call, not the value.
            .field("Content", "hidden");
        // ADR-0017 §36: a protected target the allowlist permits warns each time.
        if let Some(class) = scan_decision.class {
            confirmation = confirmation.field("Warning", class);
        }
        require_confirmation!(
            &self,
            &ctx,
            confirmation.effect(if exists {
                EFFECT_WRITE_REPLACE
            } else {
                EFFECT_WRITE_NEW
            })
        );

        // ADR-0017 §39: the audit names the entry that permitted a protected path,
        // once the operator confirmed the write.
        if let Some(entry) = &scan_decision.matched {
            self.registry.audit_write_allow(
                &identity.username,
                "write_file",
                &scan.full_name,
                entry,
            );
        }

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
        description = "Delete one file permanently. The tool scans first and refuses a protected path, an 8.3 name, a directory, and a symbolic link or a junction. An operator allowlist entry in WINRIG_WRITE_ALLOW_PATHS can permit a protected path; the confirmation then warns for a system directory, a volume root or a share root. The confirmation prompt shows the resolved path and the metadata."
    )]
    async fn delete_file(
        &self,
        Parameters(params): Parameters<DeleteFileParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        // DR-6: lexical refusal before any network access. ADR-0017 §9: an
        // operator allowlist entry that covers the path lifts the refusal.
        let decision = decide_delete_file_path(&params.path, &self.config.write_allow_paths);
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
        let scan_decision = decide_file_delete(&scan, &params.path, &self.config.write_allow_paths);
        if !scan_decision.allow {
            self.audit_refusal(&identity, "delete_file", &scan_decision);
            return Ok(CallToolResult::structured(json!({
                "error": scan_decision.reason,
                "scan": stdout,
            })));
        }
        let (size, modified) = scan_metadata(&stdout);
        let mut confirmation = self
            .confirmation(&identity, &params.session_id, "delete_file", "DELETE FILE")
            .path("Path", &params.path)
            .path("Resolved", &scan.full_name)
            .field("Size", &size)
            .field("Modified", &modified);
        // ADR-0017 §36: a protected target the allowlist permits warns each time.
        if let Some(class) = scan_decision.class {
            confirmation = confirmation.field("Warning", class);
        }
        require_confirmation!(&self, &ctx, confirmation.effect(EFFECT_DELETE_FILE));
        // ADR-0017 §39: the audit names the entry that permitted a protected path,
        // once the operator confirmed the delete.
        if let Some(entry) = &scan_decision.matched {
            self.registry.audit_write_allow(
                &identity.username,
                "delete_file",
                &scan.full_name,
                entry,
            );
        }
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

    #[tool(
        name = "copy_file",
        description = "Copy a file or a directory on the host. A directory copy is recursive, and the confirmation shows the file, directory and byte counts. The tool refuses an existing target unless overwrite is set, and it never replaces an existing directory. The source may be under a protected root, because a copy only reads it; the target obeys the write allowlist WINRIG_WRITE_ALLOW_PATHS and warns for a system directory or a volume root. The copy refuses a source tree that holds a symbolic link or a junction, which a recursive copy would follow. The tool reaches the host with the [IO.File] and [IO.Directory] classes, so a wildcard in a path cannot expand. A partial copy is an error, never a success. The tool can fail if the copy produces no output for 60 seconds. The server declares the tool only with WINRIG_ALLOW_FILE_OPS."
    )]
    async fn copy_file(
        &self,
        Parameters(params): Parameters<CopyFileParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        // ADR-0017 §12: the lexical refusal runs before any scan, so a protected
        // target costs no host call.
        let lexical = decide_write_path(&params.target, &self.config.write_allow_paths);
        if !lexical.allow {
            self.audit_refusal(&identity, "copy_file", &lexical);
            return Ok(CallToolResult::structured(
                json!({ "error": lexical.reason }),
            ));
        }
        if let Some(result) = self.missing_session(&identity, &params.session_id) {
            return Ok(result);
        }
        // The source is read-only, so a protected source is allowed (ADR-0017 §16);
        // the scan refuses a link root and a directory tree that holds a link
        // (ADR-0017 §17). The target obeys the write boundary (§15).
        let raw = match self
            .pre_scan(
                &identity,
                &params.session_id,
                &ps::copy_source_scan(&params.source),
                "copy_file",
            )
            .await
        {
            Ok(raw) => raw,
            Err(result) => return Ok(result),
        };
        let source = match Self::parse_refusal(SourceScan::from_json(&raw), "copy", &raw) {
            Ok(scan) => scan,
            Err(result) => return Ok(result),
        };
        let source_decision = decide_file_op_source(
            &source,
            &params.source,
            false,
            source.is_directory,
            &self.config.write_allow_paths,
        );
        if !source_decision.allow {
            self.audit_refusal(&identity, "copy_file", &source_decision);
            return Ok(CallToolResult::structured(json!({
                "error": source_decision.reason,
                "scan": raw,
            })));
        }
        let relation = decide_path_relation(&params.source, &params.target, source.is_directory);
        if !relation.allow {
            self.audit_refusal(&identity, "copy_file", &relation);
            return Ok(CallToolResult::structured(json!({
                "error": relation.reason,
            })));
        }
        let raw_target = match self
            .pre_scan(
                &identity,
                &params.session_id,
                &ps::write_scan(&params.target),
                "copy_file",
            )
            .await
        {
            Ok(raw) => raw,
            Err(result) => return Ok(result),
        };
        let target =
            match Self::parse_refusal(WriteScan::from_json(&raw_target), "copy", &raw_target) {
                Ok(scan) => scan,
                Err(result) => return Ok(result),
            };
        let target_decision = decide_file_op_target(
            &target,
            &params.target,
            source.is_directory,
            params.overwrite,
            "copy to",
            &self.config.write_allow_paths,
        );
        if !target_decision.allow {
            self.audit_refusal(&identity, "copy_file", &target_decision);
            return Ok(CallToolResult::structured(json!({
                "error": target_decision.reason,
                "scan": raw_target,
            })));
        }
        // A path too long for one WinRS command line refuses before the prompt. The
        // resolved paths reach the command, so the .NET calls act on the real path.
        let command = match ps::copy_command(
            &source.full_name,
            &target.dotnet_full_name,
            params.overwrite,
            source.is_directory,
        ) {
            Ok(command) => command,
            Err(error) => return Ok(CallToolResult::structured(json!({ "error": error }))),
        };
        let action = if source.is_directory {
            "COPY DIRECTORY"
        } else {
            "COPY FILE"
        };
        let mut confirmation = self
            .confirmation(&identity, &params.session_id, "copy_file", action)
            .path("Source", &params.source)
            .path("Resolved source", &source.full_name)
            .path("Target", &params.target)
            .path("Resolved target", &target.full_name)
            .field("Overwrite", if params.overwrite { "yes" } else { "no" });
        for (label, value) in source_size_fields(&source) {
            confirmation = confirmation.field(label, &value);
        }
        if let Some(class) = target_decision.class {
            confirmation = confirmation.field("Warning", class);
        }
        require_confirmation!(
            &self,
            &ctx,
            confirmation.effect(if source.is_directory {
                EFFECT_COPY_DIRECTORY
            } else {
                EFFECT_COPY_FILE
            })
        );
        if let Some(entry) = &target_decision.matched {
            self.registry.audit_write_allow(
                &identity.username,
                "copy_file",
                &target.full_name,
                entry,
            );
        }
        Ok(file_op_reply(
            &self
                .run_value(&identity, &params.session_id, &command, "copy_file")
                .await,
        ))
    }

    #[tool(
        name = "move_file",
        description = "Move a file or a directory on the host. By path, on one volume the host renames the object; across volumes the tool copies a file, verifies the size and then deletes the source. A mount point or a junction in a parent can turn a by-path rename into a copy, which the run-time check refuses for a directory. The tool refuses a cross-volume move of a directory, because the implied recursive delete falls under DR-6; copy the directory and delete the source in two calls. The confirmation shows the resolved source and target, the mode, the implied delete and the overwrite state. The tool refuses an existing target unless overwrite is set, and it never replaces an existing directory. The source obeys the write allowlist, because the move removes it. The tool reaches the host with the [IO.File] and [IO.Directory] classes, so a wildcard in a path cannot expand. A partial move is an error, never a success. The tool can fail if the move produces no output for 60 seconds. The server declares the tool only with WINRIG_ALLOW_FILE_OPS."
    )]
    async fn move_file(
        &self,
        Parameters(params): Parameters<MoveFileParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        // ADR-0017 §12: the lexical refusals run before any scan, so a protected
        // target or source costs no host call.
        for (path, decision) in [
            (
                &params.target,
                decide_write_path(&params.target, &self.config.write_allow_paths),
            ),
            (
                &params.source,
                decide_write_path(&params.source, &self.config.write_allow_paths),
            ),
        ] {
            if !decision.allow {
                self.audit_refusal(&identity, "move_file", &decision);
                return Ok(CallToolResult::structured(json!({
                    "error": decision.reason,
                    "path": path,
                })));
            }
        }
        if let Some(result) = self.missing_session(&identity, &params.session_id) {
            return Ok(result);
        }
        let raw = match self
            .pre_scan(
                &identity,
                &params.session_id,
                &ps::copy_source_scan(&params.source),
                "move_file",
            )
            .await
        {
            Ok(raw) => raw,
            Err(result) => return Ok(result),
        };
        let source = match Self::parse_refusal(SourceScan::from_json(&raw), "move", &raw) {
            Ok(scan) => scan,
            Err(result) => return Ok(result),
        };
        // The move removes the source, so it obeys the write boundary and its
        // allowlist (ADR-0017 §16, §18); a nested link does not block a rename.
        let source_decision = decide_file_op_source(
            &source,
            &params.source,
            true,
            false,
            &self.config.write_allow_paths,
        );
        if !source_decision.allow {
            self.audit_refusal(&identity, "move_file", &source_decision);
            return Ok(CallToolResult::structured(json!({
                "error": source_decision.reason,
                "scan": raw,
            })));
        }
        // A change of case only names the same object, so the relation check and the
        // target overwrite check do not apply; the move needs two steps (TR-FS-10).
        let case_only = is_case_only_change(&params.source, &params.target);
        if !case_only {
            let relation =
                decide_path_relation(&params.source, &params.target, source.is_directory);
            if !relation.allow {
                self.audit_refusal(&identity, "move_file", &relation);
                return Ok(CallToolResult::structured(json!({
                    "error": relation.reason,
                })));
            }
        }
        let raw_target = match self
            .pre_scan(
                &identity,
                &params.session_id,
                &ps::write_scan(&params.target),
                "move_file",
            )
            .await
        {
            Ok(raw) => raw,
            Err(result) => return Ok(result),
        };
        let target =
            match Self::parse_refusal(WriteScan::from_json(&raw_target), "move", &raw_target) {
                Ok(scan) => scan,
                Err(result) => return Ok(result),
            };
        let target_decision = if case_only {
            None
        } else {
            let decision = decide_file_op_target(
                &target,
                &params.target,
                source.is_directory,
                params.overwrite,
                "move to",
                &self.config.write_allow_paths,
            );
            if !decision.allow {
                self.audit_refusal(&identity, "move_file", &decision);
                return Ok(CallToolResult::structured(json!({
                    "error": decision.reason,
                    "scan": raw_target,
                })));
            }
            Some(decision)
        };
        if !case_only {
            let volume_decision =
                decide_move_volume(&source.full_name, &target.full_name, source.is_directory);
            if !volume_decision.allow {
                self.audit_refusal(&identity, "move_file", &volume_decision);
                return Ok(CallToolResult::structured(json!({
                    "error": volume_decision.reason,
                })));
            }
        }
        let same = same_volume(&source.full_name, &target.full_name);
        let command = if case_only {
            ps::move_case_command(
                &source.full_name,
                &target.dotnet_full_name,
                source.is_directory,
                params.overwrite,
            )
        } else if same {
            ps::move_rename_command(
                &source.full_name,
                &target.dotnet_full_name,
                source.is_directory,
                params.overwrite,
            )
        } else {
            ps::move_copy_delete_command(
                &source.full_name,
                &target.dotnet_full_name,
                params.overwrite,
            )
        };
        let command = match command {
            Ok(command) => command,
            Err(error) => return Ok(CallToolResult::structured(json!({ "error": error }))),
        };
        let action = if source.is_directory {
            "MOVE DIRECTORY"
        } else {
            "MOVE FILE"
        };
        let mode = if same {
            "one volume (by path): rename"
        } else {
            "across volumes (by path): copy then delete the source"
        };
        let mut confirmation = self
            .confirmation(&identity, &params.session_id, "move_file", action)
            .path("Source", &params.source)
            .path("Resolved source", &source.full_name)
            .path("Target", &params.target)
            .path("Resolved target", &target.full_name)
            .field("Mode", mode)
            .field("Overwrite", if params.overwrite { "yes" } else { "no" });
        for (label, value) in source_size_fields(&source) {
            confirmation = confirmation.field(label, &value);
        }
        // ADR-0017 §36: a protected target or a protected source (the move removes it)
        // carries the warning line.
        if let Some(class) = target_decision.as_ref().and_then(|decision| decision.class) {
            confirmation = confirmation.field("Warning", class);
        }
        if let Some(class) = source_decision.class {
            confirmation = confirmation.field("Warning (source)", class);
        }
        require_confirmation!(&self, &ctx, confirmation.effect(EFFECT_MOVE));
        // ADR-0017 §39: the audit names the entry that permitted each protected
        // path, the removed source and the written target.
        for (path, entry) in [
            (&source.full_name, &source_decision.matched),
            (
                &target.full_name,
                &target_decision
                    .as_ref()
                    .and_then(|decision| decision.matched.clone()),
            ),
        ] {
            if let Some(entry) = entry {
                self.registry
                    .audit_write_allow(&identity.username, "move_file", path, entry);
            }
        }
        Ok(file_op_reply(
            &self
                .run_value(&identity, &params.session_id, &command, "move_file")
                .await,
        ))
    }

    #[tool(
        name = "rename_file",
        description = "Rename a file or a directory in its own directory. Pass one new name, not a path: a separator, a reserved device name (CON, NUL, COM1, ...) and a trailing dot or space are refused. The rename stays on one volume. The confirmation shows the resolved path, the resolved destination and the new name. The tool refuses a target that already exists unless overwrite is set, and it never replaces an existing directory; an existing file is replaced with the atomic [IO.File]::Replace. The path obeys the write allowlist. The tool reaches the host with the [IO.File] and [IO.Directory] classes, so a wildcard in a path cannot expand. The server declares the tool only with WINRIG_ALLOW_FILE_OPS."
    )]
    async fn rename_file(
        &self,
        Parameters(params): Parameters<RenameFileParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        // TR-FS-10: the new name is one file name, checked before any host call.
        let name_decision = decide_new_name(&params.new_name);
        if !name_decision.allow {
            self.audit_refusal(&identity, "rename_file", &name_decision);
            return Ok(CallToolResult::structured(
                json!({ "error": name_decision.reason }),
            ));
        }
        // ADR-0017 §12: the lexical refusals run before any scan, so a protected path
        // costs no host call. The destination is the parent of the requested path
        // plus the new name.
        let Some(requested_target) = rename_target(&params.path, &params.new_name) else {
            return Ok(CallToolResult::structured(json!({
                "error": "the path has no parent directory; pass an absolute path",
            })));
        };
        for (path, decision) in [
            (
                &params.path,
                decide_write_path(&params.path, &self.config.write_allow_paths),
            ),
            (
                &requested_target,
                decide_write_path(&requested_target, &self.config.write_allow_paths),
            ),
        ] {
            if !decision.allow {
                self.audit_refusal(&identity, "rename_file", &decision);
                return Ok(CallToolResult::structured(json!({
                    "error": decision.reason,
                    "path": path,
                })));
            }
        }
        if let Some(result) = self.missing_session(&identity, &params.session_id) {
            return Ok(result);
        }
        let raw = match self
            .pre_scan(
                &identity,
                &params.session_id,
                &ps::copy_source_scan(&params.path),
                "rename_file",
            )
            .await
        {
            Ok(raw) => raw,
            Err(result) => return Ok(result),
        };
        let source = match Self::parse_refusal(SourceScan::from_json(&raw), "rename", &raw) {
            Ok(scan) => scan,
            Err(result) => return Ok(result),
        };
        let source_decision = decide_file_op_source(
            &source,
            &params.path,
            true,
            false,
            &self.config.write_allow_paths,
        );
        if !source_decision.allow {
            self.audit_refusal(&identity, "rename_file", &source_decision);
            return Ok(CallToolResult::structured(json!({
                "error": source_decision.reason,
                "scan": raw,
            })));
        }
        let Some(target_path) = rename_target(&source.full_name, &params.new_name) else {
            return Ok(CallToolResult::structured(json!({
                "error": "the path has no parent directory; pass an absolute path",
            })));
        };
        // A change of case only names the same object; the two-step command handles it
        // and the relation and target overwrite checks do not apply (TR-FS-10).
        let case_only = is_case_only_change(&source.full_name, &target_path);
        if !case_only {
            let relation =
                decide_path_relation(&source.full_name, &target_path, source.is_directory);
            if !relation.allow {
                self.audit_refusal(&identity, "rename_file", &relation);
                return Ok(CallToolResult::structured(json!({
                    "error": relation.reason,
                })));
            }
        }
        let raw_target = match self
            .pre_scan(
                &identity,
                &params.session_id,
                &ps::write_scan(&target_path),
                "rename_file",
            )
            .await
        {
            Ok(raw) => raw,
            Err(result) => return Ok(result),
        };
        let target =
            match Self::parse_refusal(WriteScan::from_json(&raw_target), "rename", &raw_target) {
                Ok(scan) => scan,
                Err(result) => return Ok(result),
            };
        let target_decision = if case_only {
            None
        } else {
            let decision = decide_file_op_target(
                &target,
                &target_path,
                source.is_directory,
                params.overwrite,
                "rename",
                &self.config.write_allow_paths,
            );
            if !decision.allow {
                self.audit_refusal(&identity, "rename_file", &decision);
                return Ok(CallToolResult::structured(json!({
                    "error": decision.reason,
                    "scan": raw_target,
                })));
            }
            Some(decision)
        };
        let command = match if case_only {
            ps::move_case_command(
                &source.full_name,
                &target_path,
                source.is_directory,
                params.overwrite,
            )
        } else {
            ps::rename_command(
                &source.full_name,
                &target_path,
                source.is_directory,
                params.overwrite,
            )
        } {
            Ok(command) => command,
            Err(error) => return Ok(CallToolResult::structured(json!({ "error": error }))),
        };
        let mut confirmation = self
            .confirmation(&identity, &params.session_id, "rename_file", "RENAME")
            .path("Path", &params.path)
            .path("Resolved", &source.full_name)
            .path("Resolved destination", &target_path)
            .field("New name", &params.new_name)
            .field("Overwrite", if params.overwrite { "yes" } else { "no" });
        if let Some(class) = target_decision.as_ref().and_then(|decision| decision.class) {
            confirmation = confirmation.field("Warning", class);
        }
        if let Some(class) = source_decision.class {
            confirmation = confirmation.field("Warning (source)", class);
        }
        require_confirmation!(&self, &ctx, confirmation.effect(EFFECT_RENAME));
        for (path, entry) in [
            (&source.full_name, &source_decision.matched),
            (
                &target.full_name,
                &target_decision
                    .as_ref()
                    .and_then(|decision| decision.matched.clone()),
            ),
        ] {
            if let Some(entry) = entry {
                self.registry
                    .audit_write_allow(&identity.username, "rename_file", path, entry);
            }
        }
        Ok(file_op_reply(
            &self
                .run_value(&identity, &params.session_id, &command, "rename_file")
                .await,
        ))
    }

    #[tool(
        name = "create_directory",
        description = "Create a directory and each missing parent on the host. Every created level lies inside the write boundary, and the target obeys the write allowlist WINRIG_WRITE_ALLOW_PATHS. The confirmation shows the resolved path and the number of created levels. The tool refuses a target that already exists and creates only a missing directory. The tool reaches the host with the [IO.Directory] class, so a wildcard in a path cannot expand. The server declares the tool only with WINRIG_ALLOW_FILE_OPS."
    )]
    async fn create_directory(
        &self,
        Parameters(params): Parameters<CreateDirectoryParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        // ADR-0017 §12: the lexical refusal runs before any scan, so a protected
        // target costs no host call.
        let lexical = decide_write_path(&params.path, &self.config.write_allow_paths);
        if !lexical.allow {
            self.audit_refusal(&identity, "create_directory", &lexical);
            return Ok(CallToolResult::structured(
                json!({ "error": lexical.reason }),
            ));
        }
        if let Some(result) = self.missing_session(&identity, &params.session_id) {
            return Ok(result);
        }
        let raw = match self
            .pre_scan(
                &identity,
                &params.session_id,
                &ps::create_directory_scan(&params.path),
                "create_directory",
            )
            .await
        {
            Ok(raw) => raw,
            Err(result) => return Ok(result),
        };
        let target =
            match Self::parse_refusal(WriteScan::from_json(&raw), "create a directory at", &raw) {
                Ok(scan) => scan,
                Err(result) => return Ok(result),
            };
        // TR-FS-11: an existing target is refused, and the final path and the
        // shallowest absent level both pass the write boundary, so every created
        // level lies inside it.
        let top = top_missing(&raw);
        let target_decision = decide_create_directory(
            &target,
            &params.path,
            top.as_deref(),
            &self.config.write_allow_paths,
        );
        if !target_decision.allow {
            self.audit_refusal(&identity, "create_directory", &target_decision);
            return Ok(CallToolResult::structured(json!({
                "error": target_decision.reason,
                "scan": raw,
            })));
        }
        let command = match ps::create_directory_command(&target.dotnet_full_name) {
            Ok(command) => command,
            Err(error) => return Ok(CallToolResult::structured(json!({ "error": error }))),
        };
        let levels = missing_levels(&raw);
        let mut confirmation = self
            .confirmation(
                &identity,
                &params.session_id,
                "create_directory",
                "CREATE DIRECTORY",
            )
            .path("Path", &params.path)
            .path("Resolved", &target.full_name)
            .field("Created levels", &created_levels_label(levels));
        if let Some(top) = &top {
            confirmation = confirmation.path("Top level", top);
        }
        if let Some(class) = target_decision.class {
            confirmation = confirmation.field("Warning", class);
        }
        require_confirmation!(&self, &ctx, confirmation.effect(EFFECT_CREATE_DIRECTORY));
        if let Some(entry) = &target_decision.matched {
            self.registry.audit_write_allow(
                &identity.username,
                "create_directory",
                &target.full_name,
                entry,
            );
        }
        Ok(file_op_reply(
            &self
                .run_value(&identity, &params.session_id, &command, "create_directory")
                .await,
        ))
    }

    #[tool(
        name = "download_file",
        description = "Copy a file from the host into the local transfer directory. The tool reads the file on the host in windows through a raw channel, so the reply truncation does not apply, and it never returns the content inline: the reply carries the name, the size and the SHA-256. It hashes the bytes while it reads them, confirms the whole length with a separate host pass and refuses a mismatch. The confirmation shows the resolved remote path, the size, the modification time and the local destination. WINRIG_MAX_TRANSFER_BYTES refuses a larger file after the size scan and before any read (256 MiB by default). The local endpoint is WINRIG_TRANSFER_DIR, with one subdirectory per user in HTTP mode. The server declares the tool only with WINRIG_ALLOW_FILE_DOWNLOAD."
    )]
    async fn download_file(
        &self,
        Parameters(params): Parameters<DownloadFileParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        // TR-XFER-01: the local name is validated before any host call.
        let name_decision = crate::policy::decide_transfer_name(&params.name);
        if !name_decision.allow {
            self.audit_refusal(&identity, "download_file", &name_decision);
            return Ok(CallToolResult::structured(
                json!({ "error": name_decision.reason }),
            ));
        }
        // TR-XFER-02: a relative remote path is refused before the network.
        let path_decision = crate::policy::decide_transfer_remote_path(&params.remote_path);
        if !path_decision.allow {
            self.audit_refusal(&identity, "download_file", &path_decision);
            return Ok(CallToolResult::structured(
                json!({ "error": path_decision.reason }),
            ));
        }
        let root = match transfer_root(&self.config) {
            Ok(root) => root,
            Err(error) => return Ok(CallToolResult::structured(json!({ "error": error }))),
        };
        if let Some(result) = self.missing_session(&identity, &params.session_id) {
            return Ok(result);
        }
        // The host pre-scan is read-only: the resolved path, the kind, the length of
        // the opened stream and the modification time (TR-XFER-02). It runs before
        // the confirmation and reads no content.
        let raw = match self
            .pre_scan(
                &identity,
                &params.session_id,
                &ps::download_scan(&params.remote_path),
                "download_file",
            )
            .await
        {
            Ok(raw) => raw,
            Err(result) => return Ok(result),
        };
        let scan = match Self::parse_refusal(TransferScan::from_json(&raw), "download", &raw) {
            Ok(scan) => scan,
            Err(result) => return Ok(result),
        };
        let source_decision = crate::policy::decide_download_source(&scan, &params.remote_path);
        if !source_decision.allow {
            self.audit_refusal(&identity, "download_file", &source_decision);
            return Ok(CallToolResult::structured(json!({
                "error": source_decision.reason,
                "scan": raw,
            })));
        }
        // TR-XFER-05: the size limit is checked on the scanned length before the
        // confirmation and before any read.
        let size_decision =
            crate::policy::decide_transfer_size(scan.size_bytes, self.config.max_transfer_bytes);
        if !size_decision.allow {
            self.audit_refusal(&identity, "download_file", &size_decision);
            return Ok(CallToolResult::structured(
                json!({ "error": size_decision.reason }),
            ));
        }
        // DR-3: HTTP mode isolates each user in a subdirectory; stdio uses the root.
        let isolated = self.local_identity.is_none();
        let dir = transfer_user_dir(&root, &identity.username, isolated);
        let local_path = dir.join(&params.name);
        // TR-XFER-01: the directory is checked without creating it; the creation
        // happens after the confirmation.
        if let Err(error) = precheck_transfer_dir(&root, &dir, isolated) {
            return Ok(CallToolResult::structured(json!({ "error": error })));
        }
        let (exists, is_symlink) = local_target_state(&local_path);
        let target_decision =
            crate::policy::decide_transfer_target(exists, is_symlink, params.overwrite);
        if !target_decision.allow {
            self.audit_refusal(&identity, "download_file", &target_decision);
            return Ok(CallToolResult::structured(
                json!({ "error": target_decision.reason }),
            ));
        }
        let mut confirmation = self
            .confirmation(
                &identity,
                &params.session_id,
                "download_file",
                "DOWNLOAD FILE",
            )
            .path("Remote path", &params.remote_path)
            .path("Resolved remote", &scan.full_name)
            .field("Size", &format!("{} bytes", scan.size_bytes))
            // TR-XFER-02: the prompt shows the modification time; the hash is known
            // only after the read.
            .field(
                "Last write",
                scan.last_write_utc.as_deref().unwrap_or("unknown"),
            )
            .path("Local destination", &local_path.to_string_lossy())
            .field("Overwrite", if params.overwrite { "yes" } else { "no" });
        // ADR-0017 §28: a download under a protected or a system path warns.
        if let Some(class) = source_decision.class {
            confirmation = confirmation.field("Warning", class);
        }
        let confirmation_state =
            confirm_state!(&self, &ctx, confirmation.effect(EFFECT_DOWNLOAD_FILE));
        self.perform_download(
            &identity,
            &params.session_id,
            &scan,
            &local_path,
            &root,
            isolated,
            params.overwrite,
            confirmation_state,
        )
        .await
    }

    /// Copies the host file window by window, hashes it while reading, confirms the
    /// whole length with a separate host pass and places the file (TR-XFER-02,
    /// ADR-0017 §24). Runs after the confirmation.
    #[allow(clippy::too_many_arguments)]
    async fn perform_download(
        &self,
        identity: &RequestIdentity,
        session_id: &str,
        scan: &TransferScan,
        local_path: &Path,
        root: &Path,
        isolated: bool,
        overwrite: bool,
        confirmation: &str,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let host = self
            .registry
            .session_host(&identity.username, session_id)
            .unwrap_or_else(|| "(unknown)".to_owned());
        let resolved_local = local_path.to_string_lossy().into_owned();
        let dir = match local_path.parent() {
            Some(dir) => dir.to_path_buf(),
            None => {
                return Ok(CallToolResult::structured(
                    json!({ "error": "the local destination has no parent directory" }),
                ));
            }
        };
        // TR-XFER-01: the directories are created only here, after the confirmation.
        if let Err(error) = ensure_transfer_dir(root, &dir, isolated) {
            self.audit_failed(
                &identity.username,
                &host,
                scan,
                &resolved_local,
                confirmation,
                "",
                "",
            );
            return Ok(CallToolResult::structured(json!({ "error": error })));
        }
        // TR-XFER-01: a stale half-written temp from an interrupted run does not
        // accumulate; only entries older than one hour are removed.
        clean_stale_parts(&dir);
        let temp = dir.join(format!(".winrig-{}.part", random_suffix()));
        let file = match open_transfer_temp(&temp) {
            Ok(file) => file,
            Err(error) => {
                let message = format!("cannot create {}: {error}", temp.display());
                self.audit_failed(
                    &identity.username,
                    &host,
                    scan,
                    &resolved_local,
                    confirmation,
                    "",
                    "",
                );
                return Ok(CallToolResult::structured(json!({ "error": message })));
            }
        };
        // The root and the user directory must be owned by this process; the probe
        // file proves ownership, because it is created by the current effective user.
        if let Err(error) = probe_dirs_owned_by_us(root, &dir, &temp) {
            let _ = fs::remove_file(&temp);
            self.audit_failed(
                &identity.username,
                &host,
                scan,
                &resolved_local,
                confirmation,
                "",
                "",
            );
            return Ok(CallToolResult::structured(json!({ "error": error })));
        }
        // The guard owns the open file and the temp: it closes the file, removes the
        // partial file and records a `cancelled` entry if the future is dropped before
        // the file is placed (a client disconnect).
        let mut guard = TransferGuard {
            registry: self.registry.as_ref(),
            username: &identity.username,
            host: &host,
            remote_path: &scan.full_name,
            local_path: &resolved_local,
            size: scan.size_bytes,
            confirmation,
            temp: temp.clone(),
            file: Some(file),
            armed: true,
        };
        let outcome = self
            .copy_and_hash(&identity.username, session_id, scan, guard.file_mut())
            .await;
        match outcome {
            Ok(digests) => {
                if let Err(error) = guard.file_mut().sync_all() {
                    let message = format!("cannot flush {}: {error}", temp.display());
                    guard.close_file();
                    let _ = fs::remove_file(&temp);
                    guard.disarm();
                    self.audit_failed(
                        &identity.username,
                        &host,
                        scan,
                        &resolved_local,
                        confirmation,
                        &digests.host_hash,
                        &digests.local_hash,
                    );
                    return Ok(CallToolResult::structured(json!({ "error": message })));
                }
                guard.close_file();
                if let Err(error) = replace_transfer_file(&temp, local_path, overwrite) {
                    let _ = fs::remove_file(&temp);
                    guard.disarm();
                    self.audit_failed(
                        &identity.username,
                        &host,
                        scan,
                        &resolved_local,
                        confirmation,
                        &digests.host_hash,
                        &digests.local_hash,
                    );
                    return Ok(CallToolResult::structured(json!({ "error": error })));
                }
                guard.disarm();
                self.registry.audit_transfer(AuditTransfer {
                    username: &identity.username,
                    tool: "download_file",
                    host: &host,
                    remote_path: &scan.full_name,
                    local_path: &resolved_local,
                    size: scan.size_bytes,
                    host_hash: &digests.host_hash,
                    local_hash: &digests.local_hash,
                    confirmation,
                    status: "downloaded",
                });
                Ok(CallToolResult::structured(json!({
                    "status": "downloaded",
                    "name": local_path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default(),
                    "size": scan.size_bytes,
                    "sha256": digests.local_hash,
                    "path": resolved_local,
                })))
            }
            Err(failure) => {
                guard.close_file();
                let _ = fs::remove_file(&temp);
                guard.disarm();
                self.audit_failed(
                    &identity.username,
                    &host,
                    scan,
                    &resolved_local,
                    confirmation,
                    &failure.host_hash,
                    &failure.local_hash,
                );
                Ok(CallToolResult::structured(
                    json!({ "error": failure.message }),
                ))
            }
        }
    }

    /// Reads the file window by window, hashes the bytes as they arrive and then
    /// confirms the whole length with a separate host hash pass (TR-XFER-02).
    ///
    /// Every read and the host hash pass are bounded to the length the scan reported,
    /// so an append-only log still yields a stable prefix. A mismatch or a short file
    /// is a "the source changed during the transfer" failure.
    async fn copy_and_hash(
        &self,
        username: &str,
        session_id: &str,
        scan: &TransferScan,
        file: &mut fs::File,
    ) -> Result<TransferDigests, TransferFailure> {
        let mut hasher = Sha256::new();
        let total = scan.size_bytes.max(0);
        let mut offset = 0i64;
        while offset < total {
            let window_len = ps::TRANSFER_WINDOW_BYTES.min(total - offset);
            let command = ps::download_chunk(&scan.full_name, offset, window_len);
            let reply = self
                .registry
                .run_transfer_command(username, session_id, "download_file", &command, None)
                .await;
            let Some(stdout) = Self::successful_stdout(&reply) else {
                return Err(TransferFailure::partial(
                    format!(
                        "The download failed at offset {offset}: {}",
                        reply_error(&reply)
                    ),
                    &hasher,
                ));
            };
            let mut produced = 0i64;
            for line in stdout.lines() {
                // The base64 of one line may carry separator whitespace; drop it.
                let cleaned: String = line.chars().filter(|c| !c.is_ascii_whitespace()).collect();
                if cleaned.is_empty() {
                    continue;
                }
                let decoded = match decode_base64(&cleaned) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        return Err(TransferFailure::partial(
                            format!(
                                "The host returned an unreadable line at offset {offset}: {error}"
                            ),
                            &hasher,
                        ));
                    }
                };
                // Any non-empty line is accepted as long as its payload does not
                // exceed the window that remains; a short read in the middle (a
                // network share may return less than asked) only moves the window
                // total. Only the total is checked.
                let remaining = window_len - produced;
                if decoded.len() as i64 > remaining {
                    return Err(TransferFailure::partial(
                        format!(
                            "The source changed during the transfer: {remaining} bytes remain at \
                             offset {}, and a line carried {}.",
                            offset + produced,
                            decoded.len()
                        ),
                        &hasher,
                    ));
                }
                hasher.update(&decoded);
                if let Err(error) = file.write_all(&decoded) {
                    return Err(TransferFailure::partial(
                        format!("cannot write the local file: {error}"),
                        &hasher,
                    ));
                }
                produced += decoded.len() as i64;
            }
            if produced != window_len {
                return Err(TransferFailure::partial(
                    format!(
                        "The source changed during the transfer: expected {window_len} bytes at \
                         offset {offset}, got {produced}."
                    ),
                    &hasher,
                ));
            }
            offset += window_len;
        }
        let local_hash = hex_sha256(&hasher.finalize());
        // The host hashes exactly [0, total), so an append-only log still matches.
        let command = ps::download_hash(&scan.full_name, total);
        let reply = self
            .registry
            .run_transfer_command(username, session_id, "download_file", &command, None)
            .await;
        if reply.get("status_code").and_then(serde_json::Value::as_i64)
            == Some(i64::from(ps::HASH_SHORT_EXIT))
        {
            return Err(TransferFailure {
                message: "The source changed during the transfer.".to_owned(),
                host_hash: String::new(),
                local_hash,
            });
        }
        let Some(stdout) = Self::successful_stdout(&reply) else {
            return Err(TransferFailure {
                message: format!("The host hash pass failed: {}", reply_error(&reply)),
                host_hash: String::new(),
                local_hash,
            });
        };
        let Some(host_hash) = parse_host_hash(&stdout) else {
            return Err(TransferFailure {
                message: "The host hash pass returned no digest.".to_owned(),
                host_hash: String::new(),
                local_hash,
            });
        };
        if !host_hash.eq_ignore_ascii_case(&local_hash) {
            return Err(TransferFailure {
                message: "The source changed during the transfer.".to_owned(),
                host_hash,
                local_hash,
            });
        }
        Ok(TransferDigests {
            host_hash,
            local_hash,
        })
    }

    /// Records a failed transfer with the paths, the size and whatever hashes are
    /// known (TR-XFER-02, ADR-0017 §38).
    #[allow(clippy::too_many_arguments)]
    fn audit_failed(
        &self,
        username: &str,
        host: &str,
        scan: &TransferScan,
        local_path: &str,
        confirmation: &str,
        host_hash: &str,
        local_hash: &str,
    ) {
        self.registry.audit_transfer(AuditTransfer {
            username,
            tool: "download_file",
            host,
            remote_path: &scan.full_name,
            local_path,
            size: scan.size_bytes,
            host_hash,
            local_hash,
            confirmation,
            status: "failed",
        });
    }

    #[tool(
        name = "upload_file",
        description = "Copy a file from the local transfer directory to the host. Pass one plain file name from WINRIG_TRANSFER_DIR, which has one subdirectory per user in HTTP mode. The tool hashes the local file and shows the resolved remote path, the size and the SHA-256 in one confirmation. It then sends the bytes in windows of 4 MiB through the standard input of a host command into a temporary file next to the target. The host hashes the temporary file, and the tool replaces the target only when the digest equals the confirmed one. A change of the local file after the confirmation fails the upload and leaves the target unchanged. WINRIG_MAX_TRANSFER_BYTES refuses a larger file before the read (256 MiB by default). The tool refuses a device volume path, an 8.3 name, a symbolic link or a junction, and an existing directory. An operator allowlist entry in WINRIG_WRITE_ALLOW_PATHS can permit a protected path; the confirmation then warns. It refuses an existing file unless overwrite is set. The server declares the tool only with WINRIG_ALLOW_FILE_UPLOAD."
    )]
    async fn upload_file(
        &self,
        Parameters(params): Parameters<UploadFileParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let identity = self.identity(&ctx)?;
        // TR-XFER-01: the local name is validated before any host call.
        let name_decision = crate::policy::decide_transfer_name(&params.name);
        if !name_decision.allow {
            self.audit_refusal(&identity, "upload_file", &name_decision);
            return Ok(CallToolResult::structured(
                json!({ "error": name_decision.reason }),
            ));
        }
        // TR-XFER-04: a relative remote path is refused before the network.
        let path_decision = crate::policy::decide_transfer_remote_path(&params.remote_path);
        if !path_decision.allow {
            self.audit_refusal(&identity, "upload_file", &path_decision);
            return Ok(CallToolResult::structured(
                json!({ "error": path_decision.reason }),
            ));
        }
        // DR-6, ADR-0017 §9: the lexical refusal comes before any network access.
        let decision = decide_write_path(&params.remote_path, &self.config.write_allow_paths);
        if !decision.allow {
            self.audit_refusal(&identity, "upload_file", &decision);
            return Ok(CallToolResult::structured(
                json!({ "error": decision.reason }),
            ));
        }
        let root = match transfer_root(&self.config) {
            Ok(root) => root,
            Err(error) => return Ok(CallToolResult::structured(json!({ "error": error }))),
        };
        // DR-3: HTTP mode reads only from the subdirectory of the request user.
        let isolated = self.local_identity.is_none();
        let dir = transfer_user_dir(&root, &identity.username, isolated);
        let local_path = dir.join(&params.name);
        if let Err(error) = precheck_transfer_dir(&root, &dir, isolated) {
            return Ok(CallToolResult::structured(json!({ "error": error })));
        }
        let (file, size) =
            match open_upload_source_blocking(&root, &dir, &local_path, isolated).await {
                Ok(opened) => opened,
                Err(error) => return Ok(CallToolResult::structured(json!({ "error": error }))),
            };
        // TR-XFER-05: the limit is checked on the size of the opened file, before the
        // read and before any host call.
        let size_decision =
            crate::policy::decide_transfer_size(size, self.config.max_transfer_bytes);
        if !size_decision.allow {
            self.audit_refusal(&identity, "upload_file", &size_decision);
            return Ok(CallToolResult::structured(
                json!({ "error": size_decision.reason }),
            ));
        }
        if let Some(result) = self.missing_session(&identity, &params.session_id) {
            return Ok(result);
        }
        // The host scan resolves the path as .NET and PowerShell do and reports the
        // existing target, the link type and the host roots (TR-FS-03, TR-FS-06).
        let raw = match self
            .pre_scan(
                &identity,
                &params.session_id,
                &ps::write_scan(&params.remote_path),
                "upload_file",
            )
            .await
        {
            Ok(raw) => raw,
            Err(result) => return Ok(result),
        };
        let scan = match Self::parse_refusal(WriteScan::from_json(&raw), "write", &raw) {
            Ok(scan) => scan,
            Err(result) => return Ok(result),
        };
        let scan_decision = decide_write_scan(
            &scan,
            &params.remote_path,
            params.overwrite,
            &self.config.write_allow_paths,
        );
        if !scan_decision.allow {
            self.audit_refusal(&identity, "upload_file", &scan_decision);
            return Ok(CallToolResult::structured(json!({
                "error": scan_decision.reason,
                "scan": raw,
            })));
        }
        // The hash pass reads the file once; the prompt shows its digest, and the
        // upload writes only bytes that hash to it (TR-XFER-04).
        let sha256 = match tokio::task::spawn_blocking(move || hash_local_file(file, size)).await {
            Ok(Ok(hash)) => hash,
            Ok(Err(error)) => return Ok(CallToolResult::structured(json!({ "error": error }))),
            Err(error) => {
                return Ok(CallToolResult::structured(
                    json!({ "error": format!("the hash of the local file did not finish: {error}") }),
                ));
            }
        };
        // The commands write to the .NET-resolved path (ADR-0017 §18). The temp name
        // is random, so two calls to one target never share a temp file.
        let target_path = scan.dotnet_full_name.clone();
        let temp_path = format!("{target_path}.winrig-{}.part", random_suffix());
        // Every command is built before the confirmation: a path too long for one
        // WinRS command line refuses without leaving anything on the host.
        for built in [
            ps::upload_chunk(&temp_path, 0, 0),
            ps::upload_commit(&temp_path, &target_path, size, &sha256, params.overwrite),
            ps::upload_remove_temp(&temp_path),
        ] {
            if let Err(error) = built {
                return Ok(CallToolResult::structured(json!({ "error": error })));
            }
        }
        let mut confirmation = self
            .confirmation(
                &identity,
                &params.session_id,
                "upload_file",
                if scan.exists {
                    "UPLOAD AND OVERWRITE FILE"
                } else {
                    "UPLOAD FILE"
                },
            )
            .path("Local source", &local_path.to_string_lossy())
            .path("Remote path", &params.remote_path)
            .path("Resolved remote", &scan.full_name)
            .field("Size", &format!("{size} bytes"))
            .field("SHA-256", &sha256)
            .field("Overwrite", if params.overwrite { "yes" } else { "no" })
            .field("Existing file", if scan.exists { "yes" } else { "no" });
        // ADR-0017 §36: a protected target that the allowlist permits warns each time.
        if let Some(class) = scan_decision.class {
            confirmation = confirmation.field("Warning", class);
        }
        let confirmation_state = confirm_state!(
            &self,
            &ctx,
            confirmation.effect(if scan.exists {
                EFFECT_UPLOAD_REPLACE
            } else {
                EFFECT_UPLOAD_NEW
            })
        );
        // ADR-0017 §39: the audit names the entry that permitted a protected path.
        if let Some(entry) = &scan_decision.matched {
            self.registry.audit_write_allow(
                &identity.username,
                "upload_file",
                &scan.full_name,
                entry,
            );
        }
        self.perform_upload(
            &identity,
            &params.session_id,
            &UploadPlan {
                local_path: &local_path,
                root: &root,
                dir: &dir,
                isolated,
                remote_path: &scan.full_name,
                target_path: &target_path,
                temp_path: &temp_path,
                size,
                sha256: &sha256,
                overwrite: params.overwrite,
                existed: scan.exists,
            },
            confirmation_state,
        )
        .await
    }

    /// Sends the local file window by window into the host temp file, then lets the
    /// host hash and place it (TR-XFER-04, ADR-0017 §26). Runs after the
    /// confirmation.
    ///
    /// The server reads the file again and hashes the bytes as it sends them. The
    /// digest must equal the confirmed one before the host places anything, and the
    /// host checks the same digest on its side. A failure or a cancel removes the
    /// host temp file.
    async fn perform_upload(
        &self,
        identity: &RequestIdentity,
        session_id: &str,
        plan: &UploadPlan<'_>,
        confirmation: &str,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let host = self
            .registry
            .session_host(&identity.username, session_id)
            .unwrap_or_else(|| "(unknown)".to_owned());
        let resolved_local = plan.local_path.to_string_lossy().into_owned();
        let audit = |status: &str, host_hash: &str, local_hash: &str| {
            self.registry.audit_transfer(AuditTransfer {
                username: &identity.username,
                tool: "upload_file",
                host: &host,
                remote_path: plan.remote_path,
                local_path: &resolved_local,
                size: plan.size,
                host_hash,
                local_hash,
                confirmation,
                status,
            });
        };
        let mut guard = UploadGuard {
            registry: Arc::clone(&self.registry),
            username: identity.username.clone(),
            session_id: session_id.to_owned(),
            host: host.clone(),
            remote_path: plan.remote_path.to_owned(),
            local_path: resolved_local.clone(),
            size: plan.size,
            confirmation: confirmation.to_owned(),
            temp_path: plan.temp_path.to_owned(),
            state: UploadState::default(),
            armed: true,
        };
        match self
            .send_and_place(&identity.username, session_id, plan, &guard.state)
            .await
        {
            Ok(digests) => {
                guard.armed = false;
                audit("uploaded", &digests.host_hash, &digests.local_hash);
                Ok(CallToolResult::structured(json!({
                    "status": "uploaded",
                    "name": plan.local_path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default(),
                    "remote_path": plan.remote_path,
                    "size": plan.size,
                    "sha256": digests.local_hash,
                    "replaced": plan.existed,
                })))
            }
            Err(failure) => {
                let removed = remove_host_temp(
                    &self.registry,
                    &identity.username,
                    session_id,
                    plan.temp_path,
                )
                .await;
                let unknown = guard.state.unknown.load(Ordering::SeqCst);
                guard.armed = false;
                audit(
                    if unknown { "unknown" } else { "failed" },
                    &failure.host_hash,
                    &failure.local_hash,
                );
                let message = if removed {
                    failure.message
                } else {
                    format!(
                        "{} The temporary file {} may remain on the host.",
                        failure.message, plan.temp_path
                    )
                };
                Ok(CallToolResult::structured(json!({ "error": message })))
            }
        }
    }

    /// Reads the local file once, sends each window to the host and asks the host to
    /// hash and place the temp file (TR-XFER-04).
    ///
    /// The local digest is compared with the confirmed one before the placement
    /// command runs, so a file that changed after the confirmation never reaches the
    /// target. `state` tells the cancel guard when the placement is in flight and when
    /// its result is unknown.
    async fn send_and_place(
        &self,
        username: &str,
        session_id: &str,
        plan: &UploadPlan<'_>,
        state: &UploadState,
    ) -> Result<TransferDigests, TransferFailure> {
        let local_failure = |message: String| TransferFailure {
            message,
            host_hash: String::new(),
            local_hash: String::new(),
        };
        let mut hasher = Sha256::new();
        let (mut file, size) =
            open_upload_source_blocking(plan.root, plan.dir, plan.local_path, plan.isolated)
                .await
                .map_err(local_failure)?;
        if size != plan.size {
            return Err(local_failure(format!(
                "{LOCAL_FILE_CHANGED} The size is now {size} bytes."
            )));
        }
        let window =
            usize::try_from(ps::UPLOAD_WINDOW_BYTES.min(plan.size.max(1))).unwrap_or(usize::MAX);
        let mut buffer = vec![0u8; window];
        let mut offset = 0i64;
        loop {
            let length = ps::UPLOAD_WINDOW_BYTES.min(plan.size - offset);
            let length_bytes = usize::try_from(length).unwrap_or(0);
            (file, buffer, hasher) = read_window(file, buffer, length_bytes, hasher)
                .await
                .map_err(local_failure)?;
            let bytes = &buffer[..length_bytes];
            let command = ps::upload_chunk(plan.temp_path, offset, length)
                .map_err(|message| TransferFailure::partial(message, &hasher))?;
            let reply = self
                .registry
                .run_transfer_command(username, session_id, "upload_file", &command, Some(bytes))
                .await;
            let expected = offset + length;
            let Some(stdout) = Self::successful_stdout(&reply) else {
                return Err(TransferFailure::partial(
                    format!(
                        "The upload failed at offset {offset}: {}",
                        reply_error(&reply)
                    ),
                    &hasher,
                ));
            };
            let reported = stdout
                .lines()
                .map(str::trim)
                .rfind(|line| !line.is_empty())
                .and_then(|line| line.parse::<i64>().ok());
            if reported != Some(expected) {
                return Err(TransferFailure::partial(
                    format!(
                        "The host temp file has {} bytes after the window at offset {offset}; \
                         expected {expected}.",
                        reported
                            .map_or_else(|| "an unknown number of".to_owned(), |n| n.to_string())
                    ),
                    &hasher,
                ));
            }
            offset = expected;
            if offset >= plan.size {
                break;
            }
        }
        if !at_end_of_file(file).await.map_err(local_failure)? {
            return Err(TransferFailure::partial(
                LOCAL_FILE_CHANGED.to_owned(),
                &hasher,
            ));
        }
        let local_hash = hex_sha256(&hasher.finalize());
        let failure = |message: &str, host_hash: &str| TransferFailure {
            message: message.to_owned(),
            host_hash: host_hash.to_owned(),
            local_hash: local_hash.clone(),
        };
        if !local_hash.eq_ignore_ascii_case(plan.sha256) {
            return Err(failure(
                &format!("{LOCAL_FILE_CHANGED} The tool did not place the file."),
                "",
            ));
        }
        let command = ps::upload_commit(
            plan.temp_path,
            plan.target_path,
            plan.size,
            plan.sha256,
            plan.overwrite,
        )
        .map_err(|message| failure(&message, ""))?;
        // From here a cancel or a lost answer may come after the replace: the target
        // is not known to be unchanged.
        state.placing.store(true, Ordering::SeqCst);
        let reply = self
            .registry
            .run_transfer_command(username, session_id, "upload_file", &command, None)
            .await;
        let code = reply.get("status_code").and_then(serde_json::Value::as_i64);
        if code.is_none() {
            state.unknown.store(true, Ordering::SeqCst);
            return Err(failure(
                &format!(
                    "The host gave no answer to the placement: {}. The target may have been replaced; check the file on the host.",
                    reply_error(&reply)
                ),
                "",
            ));
        }
        let stdout = reply
            .get("stdout")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let host_hash = commit_digest(stdout).unwrap_or_default();
        if code == Some(i64::from(ps::HASH_SHORT_EXIT)) {
            return Err(failure(
                "The host temp file has a different length than the local file. The tool did not place it.",
                "",
            ));
        }
        if code == Some(i64::from(ps::UPLOAD_MISMATCH_EXIT)) {
            return Err(failure(
                "The host SHA-256 of the temp file differs from the confirmed one. The tool did not place it.",
                &host_hash,
            ));
        }
        let placed = code == Some(0)
            && reply.get("error").is_none()
            && stdout.lines().any(|line| line.trim() == "placed");
        if !placed {
            return Err(failure(
                &format!("The host did not place the file: {}", reply_error(&reply)),
                &host_hash,
            ));
        }
        if !host_hash.eq_ignore_ascii_case(&local_hash) {
            return Err(failure(
                "The host SHA-256 differs from the local one. The tool cannot trust the placed file.",
                &host_hash,
            ));
        }
        Ok(TransferDigests {
            host_hash,
            local_hash,
        })
    }
}

/// The local endpoint of the file transfer, from `WINRIG_TRANSFER_DIR`
/// (TR-XFER-01).
///
/// The server app sets the value before it builds the tool router, so a missing
/// value is a configuration error, not "the default".
fn transfer_root(config: &AppConfig) -> Result<PathBuf, String> {
    config
        .transfer_dir
        .as_ref()
        .map(PathBuf::from)
        .ok_or_else(|| {
            "WINRIG_TRANSFER_DIR is not set and no state directory is available; set the transfer \
             directory explicitly"
                .to_owned()
        })
}

/// The local directory of one user in the transfer root (TR-XFER-01, DR-3).
///
/// HTTP mode isolates each user in a subdirectory of a sanitized identity with a
/// hash suffix, so two identities never share a directory and their slugs cannot
/// collide. Stdio mode uses the root directly (ADR-0017 §21).
fn transfer_user_dir(root: &Path, username: &str, isolated: bool) -> PathBuf {
    if isolated {
        root.join(transfer_user_slug(username))
    } else {
        root.to_path_buf()
    }
}

/// A collision-free directory name for one identity (DR-3).
///
/// The identity is brought to its canonical form (lowercased), kept to its ASCII
/// alphanumerics and given a 128-bit hex suffix, so two identities never share a
/// directory and a name cannot collide.
fn transfer_user_slug(username: &str) -> String {
    let canonical = crate::identity::canonical_username(username);
    let mut slug = String::with_capacity(canonical.len() + 33);
    for c in canonical.chars().take(32) {
        if c.is_ascii_alphanumeric() {
            slug.push(c);
        } else {
            slug.push('_');
        }
    }
    if slug.is_empty() {
        slug.push('_');
    }
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(canonical.as_bytes());
    let mut hex = String::with_capacity(32);
    for byte in digest.iter().take(16) {
        use std::fmt::Write;
        let _ = write!(hex, "{byte:02x}");
    }
    format!("{slug}-{hex}")
}

/// Reports whether the destination file exists and whether it is a symbolic link
/// (TR-XFER-01).
///
/// `symlink_metadata` does not follow the link, so a dangling symbolic link counts
/// as existing and is refused.
fn local_target_state(path: &Path) -> (bool, bool) {
    let meta = fs::symlink_metadata(path).ok();
    let is_symlink = meta
        .as_ref()
        .is_some_and(|meta| meta.file_type().is_symlink());
    (meta.is_some() && !is_symlink, is_symlink)
}

/// Checks the transfer directory without creating it (TR-XFER-01, DR-8).
///
/// A path that exists must be a real directory that no other user can write. The
/// check runs before the confirmation; the creation runs after it.
fn precheck_transfer_dir(root: &Path, user_dir: &Path, isolated: bool) -> Result<(), String> {
    let dirs: &[&Path] = if isolated { &[root, user_dir] } else { &[root] };
    for dir in dirs {
        let Ok(meta) = fs::symlink_metadata(dir) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            return Err(format!(
                "WINRIG_TRANSFER_DIR path {} is a symbolic link; the tool refuses",
                dir.display()
            ));
        }
        if !meta.is_dir() {
            return Err(format!(
                "WINRIG_TRANSFER_DIR path {} is not a directory; the tool refuses",
                dir.display()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o022 != 0 {
                return Err(format!(
                    "WINRIG_TRANSFER_DIR directory {} is writable by group or other (mode {mode:o}); \
                     own it and set mode 0700",
                    dir.display()
                ));
            }
        }
    }
    Ok(())
}

/// Creates the transfer directories with the private modes after the confirmation
/// (TR-XFER-01).
fn ensure_transfer_dir(root: &Path, user_dir: &Path, isolated: bool) -> Result<(), String> {
    ensure_private_transfer_dir(root)?;
    if isolated && user_dir != root {
        ensure_private_transfer_dir(user_dir)?;
    }
    Ok(())
}

/// Creates one private directory, or re-applies `0700` to an existing real one.
///
/// A symbolic link at the path is refused, so the write cannot land outside the
/// transfer root.
fn ensure_private_transfer_dir(dir: &Path) -> Result<(), String> {
    if let Ok(meta) = fs::symlink_metadata(dir)
        && (meta.file_type().is_symlink() || !meta.is_dir())
    {
        return Err(format!(
            "WINRIG_TRANSFER_DIR path {} is not a real directory; the tool refuses",
            dir.display()
        ));
    }
    crate::private_fs::create_private_dir(dir)
        .map_err(|error| format!("cannot use {}: {error}", dir.display()))
}

/// Requires the transfer root and the user directory to be owned by this process
/// (TR-XFER-01).
///
/// The probe file is created by the current effective user, so its owner is the
/// effective uid; a directory that a different user owns could be swapped under the
/// tool. `chmod` is not used, because it needs libc and `unsafe_code` is forbidden.
#[cfg(unix)]
fn probe_dirs_owned_by_us(root: &Path, user_dir: &Path, probe: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let uid = fs::symlink_metadata(probe)
        .map_err(|error| format!("cannot probe {}: {error}", probe.display()))?
        .uid();
    for dir in [root, user_dir] {
        let meta = fs::symlink_metadata(dir)
            .map_err(|error| format!("cannot inspect {}: {error}", dir.display()))?;
        if meta.uid() != uid {
            return Err(format!(
                "WINRIG_TRANSFER_DIR directory {} is not owned by the current user; own it or change \
                 the variable",
                dir.display()
            ));
        }
    }
    Ok(())
}

/// Ownership by uid is a Unix concept; every other platform owns the file it just
/// created, and the portable checks of [`precheck_transfer_dir`] apply.
#[cfg(not(unix))]
fn probe_dirs_owned_by_us(_root: &Path, _user_dir: &Path, _probe: &Path) -> Result<(), String> {
    Ok(())
}

/// Age after which a leftover transfer temp file is removed (TR-XFER-01).
const STALE_PART_AGE: Duration = Duration::from_secs(3600);

/// Removes the `.winrig-*.part` files an interrupted run of a previous process left
/// in the user directory (TR-XFER-01). A recent one is kept: another call may still
/// be writing it.
fn clean_stale_parts(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let now = std::time::SystemTime::now();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !(name.starts_with(".winrig-") && name.ends_with(".part")) {
            continue;
        }
        let Ok(modified) = entry.metadata().and_then(|meta| meta.modified()) else {
            continue;
        };
        if now
            .duration_since(modified)
            .map(|age| age >= STALE_PART_AGE)
            .unwrap_or(false)
        {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// Opens the temporary transfer file with `create_new` and the `0600` mode.
///
/// `create_new` uses `O_EXCL`, which refuses an existing file and does not follow a
/// final symbolic link. `O_NOFOLLOW` is not set explicitly, because it needs libc
/// and `unsafe_code` is forbidden; `O_EXCL` gives the same guarantee for the final
/// component.
fn open_transfer_temp(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Places the assembled file at the target (TR-XFER-01).
///
/// Without `overwrite` a hard link refuses an existing target with `EEXIST`, so the
/// placement never replaces a file that appeared during the transfer. With `overwrite`
/// the rename is atomic. The directory is synced on Unix, so the placement survives a
/// crash.
fn replace_transfer_file(temp: &Path, target: &Path, overwrite: bool) -> Result<(), String> {
    if overwrite {
        fs::rename(temp, target)
            .map_err(|error| format!("cannot place {}: {error}", target.display()))?;
    } else {
        place_without_replacing(temp, target)?;
    }
    fsync_dir(target.parent());
    Ok(())
}

/// Places the temp without replacing an existing target (TR-XFER-01).
///
/// A hard link refuses an existing target with `EEXIST`. On a file system without
/// hard links (`Unsupported`, `PermissionDenied`) it falls back to a rename after a
/// `symlink_metadata` absence check. That check and the rename are not atomic, so a
/// narrow race can still replace a target that appeared just after the check; the
/// fallback is accepted because a file system that cannot link has no other way to
/// place the file. After a successful link the placement is complete: a temp that
/// cannot be removed only leaves a stale `.winrig-*.part`, which the next run cleans.
fn place_without_replacing(temp: &Path, target: &Path) -> Result<(), String> {
    match fs::hard_link(temp, target) {
        Ok(()) => {
            remove_temp_best_effort(temp);
            Ok(())
        }
        Err(error) if placement_uses_rename_fallback(error.kind()) => {
            if fs::symlink_metadata(target).is_ok() {
                return Err(format!(
                    "cannot place {}: the target already exists",
                    target.display()
                ));
            }
            fs::rename(temp, target)
                .map_err(|error| format!("cannot place {}: {error}", target.display()))
        }
        Err(error) => Err(format!("cannot place {}: {error}", target.display())),
    }
}

/// True for the `io::ErrorKind` values that mean a file system has no hard links:
/// `Unsupported` and `PermissionDenied` (TR-XFER-01).
fn placement_uses_rename_fallback(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::Unsupported | std::io::ErrorKind::PermissionDenied
    )
}

/// Removes the temp after a successful placement (TR-XFER-01).
///
/// A failure only leaves a stale `.winrig-*.part`, which the next run cleans, so it
/// never fails the finished transfer.
fn remove_temp_best_effort(temp: &Path) {
    if let Err(error) = fs::remove_file(temp) {
        tracing::warn!(
            path = %temp.display(),
            error = %error,
            "cannot remove the transfer temp file"
        );
    }
}

/// Flushes the directory entry of a placed file on Unix; other platforms have no
/// directory handle (TR-XFER-01).
fn fsync_dir(dir: Option<&Path>) {
    #[cfg(unix)]
    if let Some(dir) = dir
        && let Ok(handle) = std::fs::File::open(dir)
    {
        let _ = handle.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Decodes the base64 payload of one line (TR-XFER-02).
fn decode_base64(payload: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(payload)
        .map_err(|error| error.to_string())
}

/// Formats a digest as lowercase hexadecimal text (TR-XFER-02).
fn hex_sha256(digest: &[u8]) -> String {
    digest
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use std::fmt::Write;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Reads the lowercase hex digest from the output of the host hash pass, skipping
/// the `progress ...` lines (TR-XFER-02).
fn parse_host_hash(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .map(str::trim)
        .rfind(|line| !line.is_empty() && !line.starts_with("progress "))
        .filter(|line| line.len() == 64 && line.chars().all(|c| c.is_ascii_hexdigit()))
        .map(str::to_owned)
}

/// The host answer text of a failed transfer command (TR-XFER-02).
fn reply_error(reply: &serde_json::Value) -> String {
    reply
        .get("stderr")
        .and_then(serde_json::Value::as_str)
        .or_else(|| reply.get("error").and_then(serde_json::Value::as_str))
        .unwrap_or("the host returned no answer")
        .to_owned()
}

/// The two SHA-256 values of a finished transfer (TR-XFER-02).
struct TransferDigests {
    host_hash: String,
    local_hash: String,
}

/// Why a transfer failed, with the hash of each side where it is known (TR-XFER-02).
struct TransferFailure {
    message: String,
    host_hash: String,
    local_hash: String,
}

impl TransferFailure {
    /// A failure before the host hash pass, with the running local digest.
    fn partial(message: String, hasher: &Sha256) -> Self {
        Self {
            message,
            host_hash: String::new(),
            local_hash: hex_sha256(&hasher.clone().finalize()),
        }
    }
}

/// Owns the open partial file and the temp path, and records a `cancelled` audit
/// entry when the transfer future is dropped before the file is placed (TR-XFER-01,
/// ADR-0017 §38).
///
/// The file lives here so it is closed before the temp is removed: on Windows an open
/// handle would block the removal.
struct TransferGuard<'a> {
    registry: &'a SessionRegistry,
    username: &'a str,
    host: &'a str,
    remote_path: &'a str,
    local_path: &'a str,
    size: i64,
    confirmation: &'a str,
    temp: PathBuf,
    file: Option<fs::File>,
    armed: bool,
}

impl TransferGuard<'_> {
    /// The open partial file, for the read loop to write to.
    fn file_mut(&mut self) -> &mut fs::File {
        self.file.as_mut().expect("the partial file is open")
    }

    /// Closes the partial file, so a later rename or removal is not blocked by an
    /// open handle.
    fn close_file(&mut self) {
        self.file = None;
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TransferGuard<'_> {
    fn drop(&mut self) {
        // Close the file before the removal, whatever the exit path.
        self.file = None;
        if !self.armed {
            return;
        }
        let _ = fs::remove_file(&self.temp);
        self.registry.audit_transfer(AuditTransfer {
            username: self.username,
            tool: "download_file",
            host: self.host,
            remote_path: self.remote_path,
            local_path: self.local_path,
            size: self.size,
            host_hash: "",
            local_hash: "",
            confirmation: self.confirmation,
            status: "cancelled",
        });
    }
}

/// What a confirmed upload needs, fixed before the confirmation (TR-XFER-04).
struct UploadPlan<'a> {
    local_path: &'a Path,
    root: &'a Path,
    dir: &'a Path,
    isolated: bool,
    /// The path as the host resolved it, for the reply and the audit.
    remote_path: &'a str,
    /// The .NET-resolved path that the host commands write to.
    target_path: &'a str,
    temp_path: &'a str,
    size: i64,
    /// Digest from the prompt; the upload writes only bytes that hash to it.
    sha256: &'a str,
    overwrite: bool,
    existed: bool,
}

/// The reason of a failure that comes from a change of the local file.
const LOCAL_FILE_CHANGED: &str = "The local file changed while the tool read it.";

/// Where an upload stands, for the cancel guard (TR-XFER-04).
#[derive(Default)]
struct UploadState {
    /// The placement command was sent; the target may already be replaced.
    placing: AtomicBool,
    /// The placement ended without an answer from the host.
    unknown: AtomicBool,
}

/// Removes the host temp file and records the audit entry when the upload future is
/// dropped before it ends (TR-XFER-04, ADR-0017 §38).
///
/// The entry is `cancelled` while the target is untouched, and `unknown` once the
/// placement was in flight, because the replace may have happened. The removal runs
/// as a task, because `drop` cannot wait. The transport terminates a stalled host
/// command from its own task, so the removal retries on a schedule until the host
/// proves that the file is gone.
struct UploadGuard {
    registry: Arc<SessionRegistry>,
    username: String,
    session_id: String,
    host: String,
    remote_path: String,
    local_path: String,
    size: i64,
    confirmation: String,
    temp_path: String,
    state: UploadState,
    armed: bool,
}

/// Waits before each removal attempt of a cancelled upload.
const CANCEL_CLEANUP_DELAYS: [Duration; 3] = [
    Duration::from_secs(1),
    Duration::from_secs(3),
    Duration::from_secs(10),
];

impl Drop for UploadGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.registry.audit_transfer(AuditTransfer {
            username: &self.username,
            tool: "upload_file",
            host: &self.host,
            remote_path: &self.remote_path,
            local_path: &self.local_path,
            size: self.size,
            host_hash: "",
            local_hash: "",
            confirmation: &self.confirmation,
            status: if self.state.placing.load(Ordering::SeqCst) {
                "unknown"
            } else {
                "cancelled"
            },
        });
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let registry = Arc::clone(&self.registry);
        let username = self.username.clone();
        let session_id = self.session_id.clone();
        let temp_path = self.temp_path.clone();
        runtime.spawn(async move {
            for delay in CANCEL_CLEANUP_DELAYS {
                tokio::time::sleep(delay).await;
                if remove_host_temp(&registry, &username, &session_id, &temp_path).await {
                    break;
                }
            }
        });
    }
}

/// Deletes the host temp file of an upload; true only when the host proved that the
/// file is gone, by the exit code of the command (TR-XFER-04).
async fn remove_host_temp(
    registry: &SessionRegistry,
    username: &str,
    session_id: &str,
    temp_path: &str,
) -> bool {
    let Ok(command) = ps::upload_remove_temp(temp_path) else {
        return false;
    };
    let reply = registry
        .run_transfer_command(username, session_id, "upload_file", &command, None)
        .await;
    reply.get("error").is_none()
        && reply.get("status_code").and_then(serde_json::Value::as_i64) == Some(0)
}

/// Runs [`open_upload_source`] off the async workers (TR-XFER-04).
async fn open_upload_source_blocking(
    root: &Path,
    dir: &Path,
    path: &Path,
    isolated: bool,
) -> Result<(fs::File, i64), String> {
    let (root, dir, path) = (root.to_path_buf(), dir.to_path_buf(), path.to_path_buf());
    tokio::task::spawn_blocking(move || open_upload_source(&root, &dir, &path, isolated))
        .await
        .map_err(|error| format!("the local file check did not finish: {error}"))?
}

/// Fills `buffer` from the file and hashes it, off the async workers (TR-XFER-04).
///
/// A file that ends early changed after the size was confirmed.
async fn read_window(
    mut file: fs::File,
    mut buffer: Vec<u8>,
    length: usize,
    mut hasher: Sha256,
) -> Result<(fs::File, Vec<u8>, Sha256), String> {
    tokio::task::spawn_blocking(move || {
        use std::io::Read;
        file.read_exact(&mut buffer[..length]).map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                LOCAL_FILE_CHANGED.to_owned()
            } else {
                format!("cannot read the local file: {error}")
            }
        })?;
        hasher.update(&buffer[..length]);
        Ok((file, buffer, hasher))
    })
    .await
    .map_err(|error| format!("the local file read did not finish: {error}"))?
}

/// True when the file has no byte after the confirmed size (TR-XFER-04).
async fn at_end_of_file(mut file: fs::File) -> Result<bool, String> {
    tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let mut probe = [0u8; 1];
        file.read(&mut probe)
            .map(|read| read == 0)
            .map_err(|error| format!("cannot read the local file: {error}"))
    })
    .await
    .map_err(|error| format!("the local file read did not finish: {error}"))?
}

/// The SHA-256 line of the upload commit output (TR-XFER-04).
fn commit_digest(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .map(str::trim)
        .find(|line| line.len() == 64 && line.chars().all(|c| c.is_ascii_hexdigit()))
        .map(str::to_owned)
}

/// Opens a regular file of the transfer directory for an upload and returns it with
/// its size (TR-XFER-01, TR-XFER-04).
///
/// The path must not be a symbolic link, and the opened handle must be the same
/// regular file that `symlink_metadata` saw, so a swap between the two steps is
/// refused. On Unix the file and the directories must have one owner, no other user
/// may write the file, and it must have one hard link.
fn open_upload_source(
    root: &Path,
    dir: &Path,
    path: &Path,
    isolated: bool,
) -> Result<(fs::File, i64), String> {
    let before = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "the file {} does not exist; put it into the transfer directory first",
                path.display()
            ));
        }
        Err(error) => return Err(format!("cannot inspect {}: {error}", path.display())),
    };
    if before.file_type().is_symlink() {
        return Err(format!(
            "{} is a symbolic link; the tool refuses to read through it",
            path.display()
        ));
    }
    if !before.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    let file =
        fs::File::open(path).map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    let after = file
        .metadata()
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !after.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(format!(
                "{} changed while the tool opened it; the tool refuses",
                path.display()
            ));
        }
        // A second hard link could be rewritten from outside the transfer directory.
        if after.nlink() > 1 {
            return Err(format!(
                "{} has more than one hard link; the tool refuses",
                path.display()
            ));
        }
        let dirs: &[&Path] = if isolated { &[root, dir] } else { &[root] };
        check_source_owner(dirs, &after, path)?;
    }
    #[cfg(not(unix))]
    let _ = (root, dir, isolated);
    let size = i64::try_from(after.len())
        .map_err(|_| format!("{} is too large to transfer", path.display()))?;
    Ok((file, size))
}

/// Requires the file to have the owner of the transfer directories and no write
/// permission for group or other (TR-XFER-01).
#[cfg(unix)]
fn check_source_owner(dirs: &[&Path], meta: &std::fs::Metadata, path: &Path) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    for dir in dirs {
        let dir_meta = fs::symlink_metadata(dir)
            .map_err(|error| format!("cannot inspect {}: {error}", dir.display()))?;
        if dir_meta.uid() != meta.uid() {
            return Err(format!(
                "{} is not owned by the owner of {}; the tool refuses",
                path.display(),
                dir.display()
            ));
        }
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(format!(
            "{} is writable by group or other (mode {mode:o}); set mode 0600",
            path.display()
        ));
    }
    Ok(())
}

/// The SHA-256 of exactly `size` bytes of the file, read once (TR-XFER-04).
///
/// A file that is shorter or longer than the size that the open reported changed
/// while it was read, and the pass fails.
fn hash_local_file(mut file: fs::File, size: i64) -> Result<String, String> {
    use std::io::Read;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut remaining = size;
    while remaining > 0 {
        let take = usize::try_from(remaining).map_or(buffer.len(), |left| left.min(buffer.len()));
        let read = file
            .read(&mut buffer[..take])
            .map_err(|error| format!("cannot read the local file: {error}"))?;
        if read == 0 {
            return Err(LOCAL_FILE_CHANGED.to_owned());
        }
        hasher.update(&buffer[..read]);
        remaining -= i64::try_from(read).unwrap_or(0);
    }
    let mut probe = [0u8; 1];
    let extra = file
        .read(&mut probe)
        .map_err(|error| format!("cannot read the local file: {error}"))?;
    if extra != 0 {
        return Err(LOCAL_FILE_CHANGED.to_owned());
    }
    Ok(hex_sha256(&hasher.finalize()))
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

/// The count lines of a copy or move prompt: the file, directory and byte counts of
/// a directory source, or the size of a file (TR-SEC-21). A truncated scan names the
/// counts as lower bounds, so the operator is not misled.
fn source_size_fields(scan: &SourceScan) -> Vec<(&'static str, String)> {
    if scan.is_directory {
        let suffix = if scan.truncated {
            " (lower bound; the scan hit its cap)"
        } else {
            ""
        };
        vec![
            ("Files", format!("{}{suffix}", scan.file_count)),
            ("Directories", format!("{}{suffix}", scan.dir_count)),
            ("Bytes", format!("{}{suffix}", scan.byte_count)),
        ]
    } else {
        vec![("Bytes", scan.byte_count.to_string())]
    }
}

/// The number of directory levels a create adds, from the pre-scan. A missing field
/// gives 0, so a wrong count never appears as a positive number.
fn missing_levels(stdout: &str) -> i64 {
    serde_json::from_str::<serde_json::Value>(stdout.trim())
        .ok()
        .and_then(|value| {
            value
                .get("MissingLevels")
                .and_then(serde_json::Value::as_i64)
        })
        .unwrap_or(0)
}

/// The shallowest absent directory level a create adds, from the pre-scan. It is the
/// highest directory the call would create, and the write boundary checks it as a
/// target (TR-FS-11).
fn top_missing(stdout: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).ok()?;
    value
        .get("TopMissing")
        .and_then(serde_json::Value::as_str)
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
}

/// The reply of a modifying file operation: the host JSON of a success, or a plain
/// error. A non-zero exit of the command (a refusal or a partial copy) is a failure,
/// never a success (TR-FS-09/10).
fn file_op_reply(reply: &serde_json::Value) -> CallToolResult {
    let stdout = reply
        .get("stdout")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    match WinrigServer::successful_stdout(reply) {
        Some(out) => {
            let mut value = serde_json::from_str::<serde_json::Value>(out.trim())
                .ok()
                .filter(serde_json::Value::is_object)
                .unwrap_or_else(|| json!({}));
            if let Some(map) = value.as_object_mut() {
                map.insert("status".to_owned(), json!("ok"));
            }
            CallToolResult::structured(value)
        }
        None => {
            // A non-zero exit is a refusal or a partial operation. The plain error
            // comes from the command JSON, then the stderr of the call (TR-FS-09/10).
            let from_json = serde_json::from_str::<serde_json::Value>(stdout.trim())
                .ok()
                .and_then(|value| {
                    value
                        .get("Error")
                        .and_then(serde_json::Value::as_str)
                        .filter(|error| !error.is_empty())
                        .map(str::to_owned)
                });
            let error = reply
                .get("stderr")
                .and_then(serde_json::Value::as_str)
                .filter(|error| !error.is_empty())
                .map(str::to_owned)
                .or(from_json)
                .or_else(|| {
                    reply
                        .get("error")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                })
                .unwrap_or_else(|| "The file operation failed.".to_owned());
            CallToolResult::structured(json!({ "error": error, "output": stdout }))
        }
    }
}

/// The prompt label for the number of directory levels a create adds (TR-FS-11).
fn created_levels_label(levels: i64) -> String {
    if levels == 1 {
        "1 level".to_owned()
    } else {
        format!("{levels} levels")
    }
}

/// The parent directory of the resolved path plus a new name. The host resolved
/// path is used, so the check and the call agree.
fn rename_target(resolved: &str, new_name: &str) -> Option<String> {
    let parent = resolved.rsplit_once(['\\', '/']).map(|(head, _)| head)?;
    (!parent.is_empty()).then(|| format!("{parent}\\{new_name}"))
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

    /// TR-FS-08, AC-FS-13: the four file operations are not advertised while the
    /// flag is off, and each has no route. Enabling them adds exactly four tools.
    #[test]
    fn file_ops_are_absent_until_the_operator_enables_them() {
        let off = server_with(&[]);
        let names: Vec<String> = off
            .tool_router
            .list_all()
            .iter()
            .map(|tool| tool.name.to_string())
            .collect();
        for tool in ["copy_file", "move_file", "rename_file", "create_directory"] {
            assert!(
                !names.iter().any(|name| name == tool),
                "{tool} must not be advertised while disabled"
            );
            assert!(
                !off.tool_router.has_route(tool),
                "{tool} must have no route"
            );
        }
        assert_eq!(
            names.len(),
            43,
            "expected 43 tools without the file operations"
        );

        let on = server_with(&[("WINRIG_ALLOW_FILE_OPS", "true")]);
        let names: Vec<String> = on
            .tool_router
            .list_all()
            .iter()
            .map(|tool| tool.name.to_string())
            .collect();
        for tool in ["copy_file", "move_file", "rename_file", "create_directory"] {
            assert!(names.iter().any(|name| name == tool), "{tool} is missing");
            assert!(on.tool_router.has_route(tool), "{tool} has no route");
        }
        assert_eq!(
            names.len(),
            47,
            "expected 47 tools with the file operations"
        );
    }

    /// TR-XFER-02, AC-XFER-05: `download_file` is not advertised by default and
    /// appears when the operator enables it. Enabling it adds exactly one tool.
    #[test]
    fn transfer_tools_are_absent_until_the_operator_enables_them() {
        let off = server_with(&[]);
        let names: Vec<String> = off
            .tool_router
            .list_all()
            .iter()
            .map(|tool| tool.name.to_string())
            .collect();
        assert!(
            !names.iter().any(|name| name == "download_file"),
            "download_file must not be advertised while disabled"
        );
        assert!(!off.tool_router.has_route("download_file"));
        assert!(
            !names.iter().any(|name| name == "upload_file"),
            "upload_file must not be advertised while disabled"
        );
        assert!(!off.tool_router.has_route("upload_file"));
        assert_eq!(
            names.len(),
            43,
            "expected 43 tools without the transfer tools"
        );

        let on = server_with(&[("WINRIG_ALLOW_FILE_DOWNLOAD", "true")]);
        let names: Vec<String> = on
            .tool_router
            .list_all()
            .iter()
            .map(|tool| tool.name.to_string())
            .collect();
        assert!(names.iter().any(|name| name == "download_file"));
        assert!(on.tool_router.has_route("download_file"));
        assert!(!names.iter().any(|name| name == "upload_file"));
        assert_eq!(names.len(), 44, "expected 44 tools with download_file");

        let on = server_with(&[("WINRIG_ALLOW_FILE_UPLOAD", "true")]);
        let names: Vec<String> = on
            .tool_router
            .list_all()
            .iter()
            .map(|tool| tool.name.to_string())
            .collect();
        assert!(names.iter().any(|name| name == "upload_file"));
        assert!(on.tool_router.has_route("upload_file"));
        assert!(!names.iter().any(|name| name == "download_file"));
        assert_eq!(names.len(), 44, "expected 44 tools with upload_file");

        let both = server_with(&[
            ("WINRIG_ALLOW_FILE_DOWNLOAD", "true"),
            ("WINRIG_ALLOW_FILE_UPLOAD", "true"),
        ]);
        assert_eq!(
            both.tool_router.list_all().len(),
            45,
            "expected 45 tools with both transfer tools"
        );
    }

    /// TR-XFER-05, AC-XFER-03: a file above `WINRIG_MAX_TRANSFER_BYTES` is refused
    /// before the read, with the real size and the limit.
    #[test]
    fn download_refuses_a_file_above_the_transfer_limit() {
        let limit: usize = 1024;
        let decision = crate::policy::decide_transfer_size((limit + 1) as i64, limit);
        assert!(!decision.allow);
        assert_eq!(decision.code, "TRANSFER_TOO_LARGE");
        assert!(decision.reason.contains(&(limit + 1).to_string()));
        assert!(decision.reason.contains(&limit.to_string()));
        assert!(crate::policy::decide_transfer_size(limit as i64, limit).allow);
        assert!(
            !crate::policy::decide_transfer_size(-1, limit).allow,
            "a negative size must refuse"
        );
    }

    /// TR-XFER-01, AC-XFER-01: a local name with a separator escape, a `..`
    /// component or a leading dot is refused before any host call.
    #[test]
    fn transfer_path_traversal_is_refused() {
        for name in [
            "",
            ".",
            "..",
            "../escape",
            "..\\escape",
            "dir/file",
            "dir\\file",
            "/abs",
            "C:evil",
            ".hidden",
            "CON",
            "com1.txt",
            "trail.",
            "trail ",
            "wild*",
            "PROGRA~1",
        ] {
            let decision = crate::policy::decide_transfer_name(name);
            assert!(!decision.allow, "{name:?} must be refused");
            assert_eq!(decision.code, "TRANSFER_NAME_INVALID");
        }
        for name in ["db.sqlite", "CBS.log", "snapshot-2026.bin"] {
            assert!(
                crate::policy::decide_transfer_name(name).allow,
                "{name:?} must pass"
            );
        }
    }

    /// TR-XFER-01, AC-XFER-01: a symbolic link at the local target is refused in
    /// all cases, so the write cannot leave the transfer directory.
    #[cfg(unix)]
    #[test]
    fn transfer_symlink_escape_is_refused() {
        let dir = std::env::temp_dir().join(format!("winrig-transfer-link-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("dir");
        let link = dir.join("escape");
        std::os::unix::fs::symlink("/etc/passwd", &link).expect("symlink");
        let (exists, is_symlink) = local_target_state(&link);
        assert!(!exists && is_symlink, "the link must read as a symlink");
        let decision = crate::policy::decide_transfer_target(exists, is_symlink, true);
        assert!(!decision.allow);
        assert_eq!(decision.code, "TRANSFER_SYMLINK");
        fs::remove_dir_all(&dir).ok();
    }

    /// TR-XFER-01, DR-3: in HTTP mode two identities write into different
    /// subdirectories, and the slug cannot collide.
    #[test]
    fn transfer_users_are_isolated() {
        let root = Path::new("/transfer");
        let alice = transfer_user_dir(root, "contoso\\alice", true);
        let bob = transfer_user_dir(root, "contoso\\bob", true);
        assert_ne!(alice, bob);
        // The identity is canonicalized: the same name in another case gives the same
        // directory.
        assert_eq!(alice, transfer_user_dir(root, "CONTOSO\\ALICE", true));
        // Two identities with the same sanitized slug still differ by the hash.
        let one = transfer_user_dir(root, "corp/a b", true);
        let two = transfer_user_dir(root, "corp a/b", true);
        assert_ne!(one, two, "the hash suffix must keep the directories apart");
        // Stdio mode uses the root directly.
        assert_eq!(transfer_user_dir(root, "contoso\\alice", false), root);
        assert_eq!(transfer_user_slug(""), "_-e3b0c44298fc1c149afbf4c8996fb924");
        assert_eq!(
            transfer_user_slug("contoso\\alice"),
            "contoso_alice-".to_owned() + &hex_sha256(&Sha256::digest(b"contoso\\alice"))[..32]
        );
    }

    /// TR-XFER-01: a symbolic link at the root or at the per-user directory is
    /// refused before the confirmation and before any creation.
    #[cfg(unix)]
    #[test]
    fn transfer_dir_symlink_is_refused() {
        let base =
            std::env::temp_dir().join(format!("winrig-transfer-root-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("base");
        let real = base.join("real");
        fs::create_dir_all(&real).expect("real");
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        let err = precheck_transfer_dir(&link, &link, false).expect_err("a symlink root refuses");
        assert!(err.contains("WINRIG_TRANSFER_DIR"), "{err}");

        // A per-user directory that is a symlink is refused in HTTP mode.
        let user = base.join("user");
        std::os::unix::fs::symlink(&real, &user).expect("symlink");
        let err =
            precheck_transfer_dir(&base, &user, true).expect_err("a symlink user dir refuses");
        assert!(err.contains("WINRIG_TRANSFER_DIR"), "{err}");

        // A root with a group-write bit makes the check refuse it.
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&real, fs::Permissions::from_mode(0o770)).expect("chmod");
        let err = precheck_transfer_dir(&real, &real, false).expect_err("a wide root refuses");
        assert!(err.contains("mode 770"), "{err}");
        fs::remove_dir_all(&base).ok();
    }

    /// TR-XFER-02, AC-XFER-02: a download of a small file reads the source, the
    /// reply carries the name, the size and the SHA-256, and the file on disk
    /// matches the source bytes.
    #[tokio::test]
    async fn download_hash_matches_on_both_sides() {
        let transport = Arc::new(TransferTransport::new());
        let (server, identity) = download_server(Arc::clone(&transport)).await;
        let dir = download_dir("hash");
        let size: i64 = 4096;
        let scan = download_scan_stub("C:\\Data\\db.bin", size);
        let local = dir.join("db.bin");
        let result = server
            .perform_download(
                &identity,
                "host1",
                &scan,
                &local,
                &dir,
                false,
                false,
                "confirmed",
            )
            .await
            .expect("download");
        let value = result.structured_content.expect("structured");
        assert_eq!(
            value.get("error").and_then(serde_json::Value::as_str),
            None,
            "{value}"
        );
        let expected = hex_sha256(&Sha256::digest(pattern_bytes(size)));
        assert_eq!(
            value.get("sha256").and_then(serde_json::Value::as_str),
            Some(expected.as_str()),
            "{value}"
        );
        assert_eq!(
            value.get("size").and_then(serde_json::Value::as_i64),
            Some(size)
        );
        assert_eq!(fs::read(&local).expect("read"), pattern_bytes(size));
        fs::remove_dir_all(&dir).ok();
    }

    /// TR-XFER-02: a file larger than one window is read window by window at the
    /// right offsets, and the last window is short.
    #[tokio::test]
    async fn download_reads_each_window_at_its_offset() {
        let transport = Arc::new(TransferTransport::new());
        let (server, identity) = download_server(Arc::clone(&transport)).await;
        let dir = download_dir("windows");
        let size = ps::TRANSFER_WINDOW_BYTES + 4096;
        let scan = download_scan_stub("C:\\Data\\big.bin", size);
        let local = dir.join("big.bin");
        let result = server
            .perform_download(
                &identity,
                "host1",
                &scan,
                &local,
                &dir,
                false,
                false,
                "confirmed",
            )
            .await
            .expect("download");
        let value = result.structured_content.expect("structured");
        assert_eq!(
            value.get("error").and_then(serde_json::Value::as_str),
            None,
            "{value}"
        );
        let windows = transport.windows.lock().expect("lock").clone();
        assert_eq!(
            windows,
            vec![
                (0, ps::TRANSFER_WINDOW_BYTES),
                (ps::TRANSFER_WINDOW_BYTES, 4096)
            ],
            "the offsets and lengths of the two windows must be exact"
        );
        assert_eq!(fs::read(&local).expect("read"), pattern_bytes(size));
        fs::remove_dir_all(&dir).ok();
    }

    /// TR-XFER-02: a window split into lines of uneven size (a short read on a network
    /// share) still assembles the right file, because only the window total is checked.
    #[tokio::test]
    async fn download_accepts_uneven_lines() {
        let mut transport = TransferTransport::new();
        transport.uneven = true;
        let transport = Arc::new(transport);
        let (server, identity) = download_server(Arc::clone(&transport)).await;
        let dir = download_dir("uneven");
        let size: i64 = 5000;
        let scan = download_scan_stub("C:\\Data\\uneven.bin", size);
        let local = dir.join("uneven.bin");
        let result = server
            .perform_download(
                &identity,
                "host1",
                &scan,
                &local,
                &dir,
                false,
                false,
                "confirmed",
            )
            .await
            .expect("download");
        let value = result.structured_content.expect("structured");
        assert_eq!(
            value.get("error").and_then(serde_json::Value::as_str),
            None,
            "{value}"
        );
        assert_eq!(fs::read(&local).expect("read"), pattern_bytes(size));
        fs::remove_dir_all(&dir).ok();
    }

    /// TR-XFER-02: a read that returns fewer bytes in total than the scanned length is
    /// refused as "the source changed during the transfer".
    #[tokio::test]
    async fn download_refuses_a_short_window() {
        let mut transport = TransferTransport::new();
        transport.truncate_first = true;
        let transport = Arc::new(transport);
        let (server, identity) = download_server(Arc::clone(&transport)).await;
        let dir = download_dir("short");
        let size: i64 = 5000;
        let scan = download_scan_stub("C:\\Data\\short.bin", size);
        let local = dir.join("short.bin");
        let result = server
            .perform_download(
                &identity,
                "host1",
                &scan,
                &local,
                &dir,
                false,
                false,
                "confirmed",
            )
            .await
            .expect("download");
        let value = result.structured_content.expect("structured");
        assert!(
            value
                .get("error")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|error| error.contains("source changed during the transfer")),
            "{value}"
        );
        assert!(!local.exists(), "a refused download leaves no file");
        fs::remove_dir_all(&dir).ok();
    }

    /// TR-XFER-01: a file system without hard links falls back to a rename only for
    /// `Unsupported` and `PermissionDenied`, never for a real error like `EEXIST`.
    #[test]
    fn hard_link_fallback_covers_the_unsupported_kinds() {
        use std::io::ErrorKind;
        assert!(placement_uses_rename_fallback(ErrorKind::Unsupported));
        assert!(placement_uses_rename_fallback(ErrorKind::PermissionDenied));
        assert!(!placement_uses_rename_fallback(ErrorKind::AlreadyExists));
        assert!(!placement_uses_rename_fallback(ErrorKind::NotFound));
        assert!(!placement_uses_rename_fallback(ErrorKind::Other));
    }

    /// TR-XFER-01: after a successful hard link the placement is done, so a temp that
    /// cannot be removed does not fail the transfer; only a stale temp remains.
    #[cfg(unix)]
    #[test]
    fn transfer_placement_succeeds_when_the_temp_cannot_be_removed() {
        use std::os::unix::fs::PermissionsExt;
        let base = download_dir("place-keep");
        let temp_dir = base.join("a");
        let target_dir = base.join("b");
        fs::create_dir_all(&temp_dir).expect("a");
        fs::create_dir_all(&target_dir).expect("b");
        let temp = temp_dir.join(".winrig-x.part");
        fs::write(&temp, b"new").expect("temp");
        let target = target_dir.join("out.bin");
        // The temp directory loses its write bit, so the temp cannot be removed; the
        // link into the target directory still succeeds.
        fs::set_permissions(&temp_dir, fs::Permissions::from_mode(0o500)).expect("chmod");
        replace_transfer_file(&temp, &target, false).expect("the placement succeeds");
        assert_eq!(fs::read(&target).expect("read"), b"new");
        assert!(temp.exists(), "the temp stays when it cannot be removed");
        fs::set_permissions(&temp_dir, fs::Permissions::from_mode(0o700)).ok();
        fs::remove_dir_all(&base).ok();
    }

    /// TR-XFER-01: the best-effort removal tolerates a temp that is already gone.
    #[test]
    fn remove_temp_best_effort_tolerates_a_missing_file() {
        let dir = download_dir("best-effort");
        fs::create_dir_all(&dir).expect("dir");
        remove_temp_best_effort(&dir.join("absent.part"));
        fs::remove_dir_all(&dir).ok();
    }

    /// TR-XFER-01: a client disconnect drops the transfer future, removes the
    /// partial file and records a `cancelled` audit entry.
    #[tokio::test]
    async fn download_cancellation_removes_the_temp_and_audits() {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer({
                let buffer = Arc::clone(&buffer);
                move || BufferWriter(Arc::clone(&buffer))
            })
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        let transport = Arc::new(TransferTransport::new());
        *transport.hang_from.lock().expect("lock") = Some(ps::TRANSFER_WINDOW_BYTES);
        let (server, identity) = download_server(Arc::clone(&transport)).await;
        let dir = download_dir("cancel");
        let size = ps::TRANSFER_WINDOW_BYTES + 4096;
        let scan = download_scan_stub("C:\\Data\\big.bin", size);
        let local = dir.join("big.bin");
        let future = server.perform_download(
            &identity,
            "host1",
            &scan,
            &local,
            &dir,
            false,
            false,
            "confirmed",
        );
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), future).await;

        drop(guard);
        let text = String::from_utf8_lossy(&buffer.lock().expect("lock")).into_owned();
        assert!(!local.exists(), "the target must not exist after a cancel");
        let leftovers: Vec<String> = fs::read_dir(&dir)
            .expect("dir")
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".winrig-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "the partial file remains: {leftovers:?}"
        );
        assert!(
            text.contains("FILE TRANSFER") && text.contains("cancelled"),
            "the cancel is not audited: {text}"
        );
        fs::remove_dir_all(&dir).ok();
    }

    /// A writer that collects the log of one test into a buffer.
    struct BufferWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for BufferWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("lock").extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A deterministic byte of the fake source, so every offset is distinct.
    fn pattern_byte(index: i64) -> u8 {
        (index % 251) as u8
    }

    /// The fake source bytes of a range that starts at zero.
    fn pattern_bytes(size: i64) -> Vec<u8> {
        (0..size).map(pattern_byte).collect()
    }

    /// The base64 lines the fake host emits for `[offset, offset+length)`.
    fn pattern_lines(offset: i64, length: i64) -> String {
        let mut lines = Vec::new();
        let mut done = 0i64;
        while done < length {
            let take = ps::TRANSFER_LINE_BYTES.min(length - done);
            let bytes: Vec<u8> = (0..take).map(|i| pattern_byte(offset + done + i)).collect();
            lines.push(ps::encode_base64(&bytes));
            done += take;
        }
        lines.join("\n")
    }

    /// The same bytes as [`pattern_lines`], but split into lines of uneven size, to
    /// model a host that returns short reads.
    fn uneven_lines(offset: i64, length: i64) -> String {
        let sizes = [1usize, 2, 3, 5, 7, 11, 13];
        let mut lines = Vec::new();
        let mut done = 0i64;
        let mut index = 0usize;
        while done < length {
            let take = (sizes[index % sizes.len()] as i64).min(length - done);
            let bytes: Vec<u8> = (0..take).map(|i| pattern_byte(offset + done + i)).collect();
            lines.push(ps::encode_base64(&bytes));
            done += take;
            index += 1;
        }
        lines.join("\n")
    }

    /// The integer that follows `marker` in a generated script.
    fn number_after(script: &str, marker: &str) -> Option<i64> {
        let start = script.find(marker)? + marker.len();
        let rest = &script[start..];
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        rest[..end].parse().ok()
    }

    /// A fake host for the download tests: it serves the deterministic pattern per
    /// offset for a read command and the matching SHA-256 for the hash pass. It can
    /// hang on a chosen read to exercise the cancellation guard, split a window into
    /// uneven lines, and return one byte less than the window.
    struct TransferTransport {
        /// The `(offset, length)` of each read the fake was asked for.
        windows: Mutex<Vec<(i64, i64)>>,
        /// When set, a read at or above this offset never resolves.
        hang_from: Mutex<Option<i64>>,
        /// When true, each read returns lines of mixed size.
        uneven: bool,
        /// When true, the first read returns one byte less.
        truncate_first: bool,
    }

    impl TransferTransport {
        fn new() -> Self {
            Self {
                windows: Mutex::new(Vec::new()),
                hang_from: Mutex::new(None),
                uneven: false,
                truncate_first: false,
            }
        }
    }

    #[async_trait::async_trait]
    impl WinRmTransport for TransferTransport {
        async fn run_powershell(
            &self,
            _target: &SessionTarget,
            script: &str,
        ) -> Result<RemoteOutput, TransportError> {
            if script.contains("TransformBlock") {
                let size = number_after(script, "$remaining = ").unwrap_or(0);
                let hex = hex_sha256(&Sha256::digest(pattern_bytes(size)));
                return Ok(RemoteOutput {
                    stdout: format!("progress 0\n{hex}").into_bytes(),
                    stderr: Vec::new(),
                    exit_code: 0,
                });
            }
            if script.contains("Seek(") {
                let offset = number_after(script, "Seek(").unwrap_or(0);
                let length = number_after(script, "$remaining = ").unwrap_or(0);
                self.windows.lock().expect("lock").push((offset, length));
                let hang = *self.hang_from.lock().expect("lock");
                if let Some(limit) = hang
                    && offset >= limit
                {
                    std::future::pending::<()>().await;
                }
                let effective = if self.truncate_first && offset == 0 {
                    (length - 1).max(0)
                } else {
                    length
                };
                let stdout = if self.uneven {
                    uneven_lines(offset, effective)
                } else {
                    pattern_lines(offset, effective)
                };
                return Ok(RemoteOutput {
                    stdout: stdout.into_bytes(),
                    stderr: Vec::new(),
                    exit_code: 0,
                });
            }
            Ok(RemoteOutput {
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_code: 0,
            })
        }
    }

    /// A fresh local directory for one download test.
    fn download_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("winrig-download-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    /// The scan a download uses for a file of `size` bytes.
    fn download_scan_stub(full_name: &str, size: i64) -> TransferScan {
        TransferScan {
            full_name: full_name.to_owned(),
            is_directory: false,
            link_type: None,
            size_bytes: size,
            last_write_utc: Some("2026-01-02T03:04:05.0000000Z".to_owned()),
            roots: crate::policy::HostRoots::default(),
        }
    }

    /// TR-XFER-01: without `overwrite` a hard link refuses an existing target and
    /// leaves it unchanged; with `overwrite` the rename replaces it.
    #[test]
    fn transfer_placement_refuses_an_existing_target_without_overwrite() {
        let dir = download_dir("place");
        fs::create_dir_all(&dir).expect("dir");
        let temp = dir.join(".winrig-x.part");
        fs::write(&temp, b"new").expect("temp");
        let target = dir.join("out.bin");
        fs::write(&target, b"old").expect("target");

        let err = replace_transfer_file(&temp, &target, false).expect_err("must refuse");
        assert!(err.contains("cannot place"), "{err}");
        assert_eq!(fs::read(&target).expect("read"), b"old");
        assert!(temp.exists(), "the temp stays for the caller to remove");

        replace_transfer_file(&temp, &target, true).expect("overwrite places");
        assert_eq!(fs::read(&target).expect("read"), b"new");
        assert!(!temp.exists());
        fs::remove_dir_all(&dir).ok();
    }

    /// TR-XFER-01: a dangling symbolic link at the target counts as existing and is
    /// refused with and without `overwrite`.
    #[cfg(unix)]
    #[test]
    fn transfer_target_counts_a_dangling_symlink_as_existing() {
        let dir = download_dir("dangling");
        fs::create_dir_all(&dir).expect("dir");
        let target = dir.join("link");
        std::os::unix::fs::symlink(dir.join("nope"), &target).expect("symlink");
        let (exists, is_symlink) = local_target_state(&target);
        assert!(!exists && is_symlink);
        assert!(!crate::policy::decide_transfer_target(exists, is_symlink, false).allow);
        assert!(!crate::policy::decide_transfer_target(exists, is_symlink, true).allow);
        fs::remove_dir_all(&dir).ok();
    }

    /// A server with the fake host and one open session.
    async fn download_server(transport: Arc<TransferTransport>) -> (WinrigServer, RequestIdentity) {
        let registry = Arc::new(SessionRegistry::new(
            transport as Arc<dyn WinRmTransport>,
            RegistryConfig::default(),
        ));
        let lookup: Box<crate::config::Env> = Box::new(|name: &str| match name {
            "WINRIG_AUTH_TOKEN" => Some("token".to_owned()),
            "WINRIG_ALLOWED_HOSTS" => Some("host1".to_owned()),
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
        (server, identity)
    }

    /// A fake host for the upload tests: it records every window that arrives on the
    /// standard input, appends the bytes to a fake temp file and answers the commit
    /// with the digest of what it received. It can report another digest and can hang
    /// on a window to exercise the cancellation guard.
    struct UploadTransport {
        /// Offset, length and bytes of every chunk the fake got.
        windows: Mutex<Vec<(i64, i64, Vec<u8>)>>,
        /// All commands the fake saw, with or without standard input.
        scripts: Mutex<Vec<String>>,
        received: Mutex<Vec<u8>>,
        /// When set, the commit reports this digest instead of the real one.
        digest_override: Mutex<Option<String>>,
        /// When set, a window at or above this offset never resolves.
        hang_from: Mutex<Option<i64>>,
        /// When true, the commit never resolves.
        hang_commit: Mutex<bool>,
        /// When true, the commit fails at the transport, with no answer.
        commit_error: Mutex<bool>,
        /// Exit code that the cleanup command reports.
        remove_exit: Mutex<i32>,
    }

    impl UploadTransport {
        fn new() -> Self {
            Self {
                windows: Mutex::new(Vec::new()),
                scripts: Mutex::new(Vec::new()),
                received: Mutex::new(Vec::new()),
                digest_override: Mutex::new(None),
                hang_from: Mutex::new(None),
                hang_commit: Mutex::new(false),
                commit_error: Mutex::new(false),
                remove_exit: Mutex::new(0),
            }
        }

        fn saw(&self, needle: &str) -> bool {
            self.scripts
                .lock()
                .expect("lock")
                .iter()
                .any(|script| script.contains(needle))
        }
    }

    #[async_trait::async_trait]
    impl WinRmTransport for UploadTransport {
        async fn run_powershell(
            &self,
            _target: &SessionTarget,
            script: &str,
        ) -> Result<RemoteOutput, TransportError> {
            self.scripts.lock().expect("lock").push(script.to_owned());
            if !script.contains("TransformBlock") {
                return Ok(RemoteOutput {
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    exit_code: *self.remove_exit.lock().expect("lock"),
                });
            }
            if *self.hang_commit.lock().expect("lock") {
                std::future::pending::<()>().await;
            }
            if *self.commit_error.lock().expect("lock") {
                return Err(TransportError::Other("connection lost".to_owned()));
            }
            let actual = self
                .digest_override
                .lock()
                .expect("lock")
                .clone()
                .unwrap_or_else(|| {
                    hex_sha256(&Sha256::digest(&*self.received.lock().expect("lock")))
                });
            let marker = "$actual -ne '";
            let start = script.find(marker).expect("digest check") + marker.len();
            let expected = &script[start..start + 64];
            if actual.eq_ignore_ascii_case(expected) {
                Ok(RemoteOutput {
                    stdout: format!("progress 0\n{actual}\nplaced").into_bytes(),
                    stderr: Vec::new(),
                    exit_code: 0,
                })
            } else {
                Ok(RemoteOutput {
                    stdout: actual.into_bytes(),
                    stderr: Vec::new(),
                    exit_code: ps::UPLOAD_MISMATCH_EXIT,
                })
            }
        }

        async fn run_powershell_stdin(
            &self,
            _target: &SessionTarget,
            script: &str,
            stdin: &[u8],
        ) -> Result<RemoteOutput, TransportError> {
            self.scripts.lock().expect("lock").push(script.to_owned());
            let offset = number_after(script, "$fs.Length -ne ").unwrap_or(0);
            let length = number_after(script, "$got -ne ").unwrap_or(0);
            let hang = *self.hang_from.lock().expect("lock");
            if let Some(limit) = hang
                && offset >= limit
            {
                std::future::pending::<()>().await;
            }
            self.windows
                .lock()
                .expect("lock")
                .push((offset, length, stdin.to_vec()));
            self.received.lock().expect("lock").extend_from_slice(stdin);
            Ok(RemoteOutput {
                stdout: (offset + stdin.len() as i64).to_string().into_bytes(),
                stderr: Vec::new(),
                exit_code: 0,
            })
        }
    }

    /// A server wired to the fake host, with one open session.
    async fn upload_server(transport: Arc<UploadTransport>) -> (WinrigServer, RequestIdentity) {
        let registry = Arc::new(SessionRegistry::new(
            transport as Arc<dyn WinRmTransport>,
            RegistryConfig::default(),
        ));
        let lookup: Box<crate::config::Env> = Box::new(|name: &str| match name {
            "WINRIG_AUTH_TOKEN" => Some("token".to_owned()),
            "WINRIG_ALLOWED_HOSTS" => Some("host1".to_owned()),
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
        (server, identity)
    }

    /// A local transfer directory that holds one file for an upload test.
    fn upload_fixture(name: &str, content: &[u8]) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("winrig-upload-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("dir");
        let file = dir.join("db.bin");
        fs::write(&file, content).expect("file");
        private_mode(&file);
        (dir, file)
    }

    /// Sets the mode `0600`, because the umask of the test host may leave a file
    /// writable by its group.
    fn private_mode(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("mode");
        }
        #[cfg(not(unix))]
        let _ = path;
    }

    const UPLOAD_TEMP: &str = "C:\\Data\\db.bin.winrig-0000000000000000.part";

    /// The plan for `content`, aimed at `C:\Data\db.bin`.
    fn upload_plan<'a>(
        dir: &'a Path,
        file: &'a Path,
        content: &[u8],
        sha256: &'a str,
        overwrite: bool,
    ) -> UploadPlan<'a> {
        UploadPlan {
            local_path: file,
            root: dir,
            dir,
            isolated: false,
            remote_path: "C:\\Data\\db.bin",
            target_path: "C:\\Data\\db.bin",
            temp_path: UPLOAD_TEMP,
            size: content.len() as i64,
            sha256,
            overwrite,
            existed: false,
        }
    }

    /// TR-XFER-04, AC-XFER-04: an upload writes the windows into the host temp file
    /// and the commit places it. The SHA-256 of the reply is the confirmed one, the
    /// host received exactly the file bytes, and the commit carries the same digest.
    #[tokio::test]
    async fn upload_hash_matches_on_both_sides() {
        let transport = Arc::new(UploadTransport::new());
        let (server, identity) = upload_server(Arc::clone(&transport)).await;
        let content = pattern_bytes(4096);
        let (dir, file) = upload_fixture("hash", &content);
        let sha = hex_sha256(&Sha256::digest(&content));
        let result = server
            .perform_upload(
                &identity,
                "host1",
                &upload_plan(&dir, &file, &content, &sha, false),
                "confirmed",
            )
            .await
            .expect("upload");
        let value = result.structured_content.expect("structured");
        assert_eq!(
            value.get("error").and_then(serde_json::Value::as_str),
            None,
            "{value}"
        );
        assert_eq!(
            value.get("status").and_then(serde_json::Value::as_str),
            Some("uploaded")
        );
        assert_eq!(
            value.get("sha256").and_then(serde_json::Value::as_str),
            Some(sha.as_str())
        );
        assert_eq!(
            value.get("size").and_then(serde_json::Value::as_i64),
            Some(4096)
        );
        assert_eq!(*transport.received.lock().expect("lock"), content);
        assert!(transport.saw(&format!("if ($actual -ne '{sha}')")));
        assert!(
            !transport.saw("Remove-Item"),
            "a good upload leaves no cleanup"
        );
        fs::remove_dir_all(&dir).ok();
    }

    /// TR-XFER-04: a file larger than one window goes window by window at the right
    /// offsets, the last window is short, and the host gets the whole file in order.
    #[tokio::test]
    async fn upload_sends_each_window_at_its_offset() {
        let transport = Arc::new(UploadTransport::new());
        let (server, identity) = upload_server(Arc::clone(&transport)).await;
        let content = pattern_bytes(ps::UPLOAD_WINDOW_BYTES + 4096);
        let (dir, file) = upload_fixture("windows", &content);
        let sha = hex_sha256(&Sha256::digest(&content));
        let result = server
            .perform_upload(
                &identity,
                "host1",
                &upload_plan(&dir, &file, &content, &sha, true),
                "confirmed",
            )
            .await
            .expect("upload");
        let value = result.structured_content.expect("structured");
        assert_eq!(
            value.get("error").and_then(serde_json::Value::as_str),
            None,
            "{value}"
        );
        let windows: Vec<(i64, i64)> = transport
            .windows
            .lock()
            .expect("lock")
            .iter()
            .map(|(offset, length, _)| (*offset, *length))
            .collect();
        assert_eq!(
            windows,
            vec![
                (0, ps::UPLOAD_WINDOW_BYTES),
                (ps::UPLOAD_WINDOW_BYTES, 4096)
            ]
        );
        assert_eq!(*transport.received.lock().expect("lock"), content);
        fs::remove_dir_all(&dir).ok();
    }

    /// TR-XFER-04: an empty file still creates an empty temp file with one empty
    /// window, and the commit places it.
    #[tokio::test]
    async fn upload_of_an_empty_file_sends_one_empty_window() {
        let transport = Arc::new(UploadTransport::new());
        let (server, identity) = upload_server(Arc::clone(&transport)).await;
        let (dir, file) = upload_fixture("empty", b"");
        let sha = hex_sha256(&Sha256::digest(b""));
        let result = server
            .perform_upload(
                &identity,
                "host1",
                &upload_plan(&dir, &file, b"", &sha, false),
                "confirmed",
            )
            .await
            .expect("upload");
        let value = result.structured_content.expect("structured");
        assert_eq!(
            value.get("error").and_then(serde_json::Value::as_str),
            None,
            "{value}"
        );
        let windows: Vec<(i64, i64)> = transport
            .windows
            .lock()
            .expect("lock")
            .iter()
            .map(|(offset, length, _)| (*offset, *length))
            .collect();
        assert_eq!(windows, vec![(0, 0)]);
        fs::remove_dir_all(&dir).ok();
    }

    /// TR-XFER-04, AC-XFER-04, DR-6: a protected target is refused before any host
    /// call, and an operator allowlist entry that covers it lifts the refusal.
    #[test]
    fn upload_refuses_a_protected_target() {
        let path = "C:\\Windows\\System32\\drivers\\etc\\hosts";
        let refused = decide_write_path(path, &[]);
        assert!(!refused.allow, "{}", refused.reason);
        let allowed = decide_write_path(path, &["C:\\Windows\\System32\\drivers\\etc".to_owned()]);
        assert!(allowed.allow, "{}", allowed.reason);
        for relative in ["hosts", "..\\hosts", "dir\\hosts"] {
            assert!(
                !crate::policy::decide_transfer_remote_path(relative).allow,
                "{relative:?} must be refused as not absolute"
            );
        }
        assert!(crate::policy::decide_transfer_remote_path("D:\\Data\\a.bin").allow);
        assert!(crate::policy::decide_transfer_remote_path("\\\\srv\\share\\a.bin").allow);
    }

    /// TR-XFER-04: a local file that changed after the confirmation is never placed.
    /// The digest of the bytes read for the upload differs from the confirmed one, so
    /// the commit does not run and the host temp file is removed.
    #[tokio::test]
    async fn upload_refuses_a_file_that_changed_after_the_confirmation() {
        let transport = Arc::new(UploadTransport::new());
        let (server, identity) = upload_server(Arc::clone(&transport)).await;
        let confirmed = pattern_bytes(2048);
        let (dir, file) = upload_fixture("changed", &confirmed);
        let sha = hex_sha256(&Sha256::digest(&confirmed));
        let mut changed = confirmed.clone();
        changed[100] ^= 0xff;
        fs::write(&file, &changed).expect("change the file");
        let result = server
            .perform_upload(
                &identity,
                "host1",
                &upload_plan(&dir, &file, &confirmed, &sha, false),
                "confirmed",
            )
            .await
            .expect("upload");
        let value = result.structured_content.expect("structured");
        let error = value
            .get("error")
            .and_then(serde_json::Value::as_str)
            .expect("a refusal");
        assert!(error.contains("changed"), "{error}");
        assert!(
            !transport.saw("TransformBlock"),
            "the commit ran for a changed file"
        );
        assert!(
            transport.saw("Remove-Item"),
            "the host temp file was not removed"
        );
        fs::remove_dir_all(&dir).ok();
    }

    /// TR-XFER-04: a file that grew or shrank after the size was confirmed fails too.
    #[tokio::test]
    async fn upload_refuses_a_file_whose_size_changed() {
        let transport = Arc::new(UploadTransport::new());
        let (server, identity) = upload_server(Arc::clone(&transport)).await;
        let confirmed = pattern_bytes(2048);
        let (dir, file) = upload_fixture("size", &confirmed);
        let sha = hex_sha256(&Sha256::digest(&confirmed));
        let mut grown = confirmed.clone();
        grown.push(1);
        fs::write(&file, &grown).expect("grow the file");
        let result = server
            .perform_upload(
                &identity,
                "host1",
                &upload_plan(&dir, &file, &confirmed, &sha, false),
                "confirmed",
            )
            .await
            .expect("upload");
        let value = result.structured_content.expect("structured");
        assert!(value.get("error").is_some(), "{value}");
        assert!(!transport.saw("TransformBlock"));
        assert!(
            transport.windows.lock().expect("lock").is_empty(),
            "bytes reached the host for a file of another size"
        );
        fs::remove_dir_all(&dir).ok();
    }

    /// TR-XFER-04: when the host digest differs from the confirmed one, the host
    /// refuses to place the file, and the tool removes the host temp file and reports
    /// both digests in the audit.
    #[tokio::test]
    async fn upload_host_hash_mismatch_removes_the_temp() {
        let transport = Arc::new(UploadTransport::new());
        *transport.digest_override.lock().expect("lock") = Some("0".repeat(64));
        let (server, identity) = upload_server(Arc::clone(&transport)).await;
        let content = pattern_bytes(512);
        let (dir, file) = upload_fixture("mismatch", &content);
        let sha = hex_sha256(&Sha256::digest(&content));
        let result = server
            .perform_upload(
                &identity,
                "host1",
                &upload_plan(&dir, &file, &content, &sha, false),
                "confirmed",
            )
            .await
            .expect("upload");
        let value = result.structured_content.expect("structured");
        let error = value
            .get("error")
            .and_then(serde_json::Value::as_str)
            .expect("a refusal");
        assert!(error.contains("differs"), "{error}");
        assert!(
            transport.saw("Remove-Item"),
            "the temp file stays on the host"
        );
        fs::remove_dir_all(&dir).ok();
    }

    /// TR-XFER-04: a client disconnect drops the upload future, records a `cancelled`
    /// audit entry and sends the removal of the host temp file.
    #[tokio::test]
    async fn upload_cancellation_removes_the_host_temp_and_audits() {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer({
                let buffer = Arc::clone(&buffer);
                move || BufferWriter(Arc::clone(&buffer))
            })
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        let transport = Arc::new(UploadTransport::new());
        *transport.hang_from.lock().expect("lock") = Some(ps::UPLOAD_WINDOW_BYTES);
        let (server, identity) = upload_server(Arc::clone(&transport)).await;
        let content = pattern_bytes(ps::UPLOAD_WINDOW_BYTES + 4096);
        let (dir, file) = upload_fixture("cancel", &content);
        let sha = hex_sha256(&Sha256::digest(&content));
        let plan = upload_plan(&dir, &file, &content, &sha, false);
        let future = server.perform_upload(&identity, "host1", &plan, "confirmed");
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), future).await;
        // The removal runs as a task after the first delay of the schedule.
        tokio::time::sleep(CANCEL_CLEANUP_DELAYS[0] + std::time::Duration::from_millis(500)).await;

        drop(guard);
        let text = String::from_utf8_lossy(&buffer.lock().expect("lock")).into_owned();
        assert!(
            transport.saw("Remove-Item"),
            "the host temp file was not removed after the cancel"
        );
        assert!(
            !transport.saw("TransformBlock"),
            "a cancelled upload reached the commit"
        );
        assert!(
            text.contains("FILE TRANSFER") && text.contains("cancelled"),
            "the cancel is not audited: {text}"
        );
        fs::remove_dir_all(&dir).ok();
    }

    /// The audit text of one upload run that a hung or failing commit ends.
    async fn audit_of_a_placement_that_goes_wrong(
        configure: impl Fn(&UploadTransport),
    ) -> (String, Arc<UploadTransport>, Option<String>) {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer({
                let buffer = Arc::clone(&buffer);
                move || BufferWriter(Arc::clone(&buffer))
            })
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        let transport = Arc::new(UploadTransport::new());
        configure(&transport);
        let (server, identity) = upload_server(Arc::clone(&transport)).await;
        let content = pattern_bytes(1024);
        let (dir, file) = upload_fixture("placing", &content);
        let sha = hex_sha256(&Sha256::digest(&content));
        let plan = upload_plan(&dir, &file, &content, &sha, true);
        let future = server.perform_upload(&identity, "host1", &plan, "confirmed");
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(1), future).await;
        let error = outcome.ok().and_then(|result| {
            result
                .ok()
                .and_then(|reply| reply.structured_content)
                .and_then(|value| {
                    value
                        .get("error")
                        .and_then(|e| e.as_str().map(str::to_owned))
                })
        });
        tokio::time::sleep(CANCEL_CLEANUP_DELAYS[0] + std::time::Duration::from_millis(500)).await;
        drop(guard);
        let text = String::from_utf8_lossy(&buffer.lock().expect("lock")).into_owned();
        fs::remove_dir_all(&dir).ok();
        (text, transport, error)
    }

    /// TR-XFER-04, ADR-0017 §38: a cancel while the placement command runs may come after
    /// the replace, so the audit says `unknown`, not `cancelled`, and the temp file is
    /// still removed.
    #[tokio::test]
    async fn upload_cancel_during_the_placement_is_audited_as_unknown() {
        let (text, transport, _) =
            audit_of_a_placement_that_goes_wrong(|t| *t.hang_commit.lock().expect("lock") = true)
                .await;
        assert!(text.contains("FILE TRANSFER"), "{text}");
        assert!(
            text.contains("status        : unknown"),
            "the audit must not claim an unchanged target: {text}"
        );
        assert!(!text.contains("status        : cancelled"), "{text}");
        assert!(
            transport.saw("Remove-Item"),
            "the temp file stays on the host"
        );
    }

    /// TR-XFER-04: a placement that ends without an answer from the host is `unknown`
    /// too, and the reply says that the target may have been replaced.
    #[tokio::test]
    async fn upload_placement_without_an_answer_is_unknown() {
        let (text, _, error) =
            audit_of_a_placement_that_goes_wrong(|t| *t.commit_error.lock().expect("lock") = true)
                .await;
        let error = error.expect("an error reply");
        assert!(error.contains("may have been replaced"), "{error}");
        assert!(text.contains("status        : unknown"), "{text}");
    }

    /// TR-XFER-04: the removal of the host temp file is trusted by the exit code of the
    /// dedicated command, and a failed removal is named in the error.
    #[tokio::test]
    async fn upload_temp_removal_trusts_the_exit_code() {
        let transport = Arc::new(UploadTransport::new());
        let (server, identity) = upload_server(Arc::clone(&transport)).await;
        assert!(remove_host_temp(&server.registry, &identity.username, "host1", UPLOAD_TEMP).await);
        assert!(transport.saw("if (Test-Path -LiteralPath $p) { exit 1 }"));
        *transport.remove_exit.lock().expect("lock") = 1;
        assert!(
            !remove_host_temp(&server.registry, &identity.username, "host1", UPLOAD_TEMP).await
        );

        // A failed upload whose cleanup fails names the temp file.
        let confirmed = pattern_bytes(64);
        let (dir, file) = upload_fixture("removal", &confirmed);
        let sha = hex_sha256(&Sha256::digest(&confirmed));
        let mut changed = confirmed.clone();
        changed[3] ^= 1;
        fs::write(&file, &changed).expect("change");
        let result = server
            .perform_upload(
                &identity,
                "host1",
                &upload_plan(&dir, &file, &confirmed, &sha, false),
                "confirmed",
            )
            .await
            .expect("upload");
        let value = result.structured_content.expect("structured");
        let error = value.get("error").and_then(|e| e.as_str()).expect("error");
        assert!(error.contains("may remain on the host"), "{error}");
        fs::remove_dir_all(&dir).ok();
    }

    /// TR-XFER-01: a source with a second hard link is refused, because the content
    /// could be rewritten from outside the transfer directory.
    #[cfg(unix)]
    #[test]
    fn upload_source_with_a_second_hard_link_is_refused() {
        let (dir, file) = upload_fixture("nlink", b"data");
        let other = std::env::temp_dir().join(format!("winrig-upload-link-{}", std::process::id()));
        let _ = fs::remove_file(&other);
        fs::hard_link(&file, &other).expect("hard link");
        let error = open_upload_source(&dir, &dir, &file, false).expect_err("must refuse");
        assert!(error.contains("hard link"), "{error}");
        fs::remove_file(&other).ok();
        fs::remove_dir_all(&dir).ok();
    }

    /// TR-XFER-01, DR-3: a user reads only from the own subdirectory, so the same name
    /// in the directory of another user is a different file, and the other user's
    /// directory is not visible.
    #[test]
    fn upload_reads_only_the_directory_of_the_user() {
        let root = std::env::temp_dir().join(format!("winrig-upload-users-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let alice = transfer_user_dir(&root, "contoso\\alice", true);
        let bob = transfer_user_dir(&root, "contoso\\bob", true);
        assert_ne!(alice, bob);
        fs::create_dir_all(&alice).expect("alice");
        fs::write(alice.join("db.bin"), b"alice").expect("file");
        private_mode(&alice.join("db.bin"));
        let (_, size) = open_upload_source(&root, &alice, &alice.join("db.bin"), true)
            .expect("alice reads the own file");
        assert_eq!(size, 5);
        let error = open_upload_source(&root, &bob, &bob.join("db.bin"), true)
            .expect_err("bob has no such file");
        assert!(error.contains("does not exist"), "{error}");
        fs::remove_dir_all(&root).ok();
    }

    /// TR-XFER-01: a symbolic link as the source is refused, even when it points to
    /// a file inside the transfer directory, and a directory is not a file.
    #[cfg(unix)]
    #[test]
    fn upload_source_symlink_is_refused() {
        let (dir, file) = upload_fixture("symlink", b"data");
        let link = dir.join("link.bin");
        std::os::unix::fs::symlink(&file, &link).expect("symlink");
        let error = open_upload_source(&dir, &dir, &link, false).expect_err("must refuse");
        assert!(error.contains("symbolic link"), "{error}");
        let sub = dir.join("sub");
        fs::create_dir(&sub).expect("sub");
        let error = open_upload_source(&dir, &dir, &sub, false).expect_err("must refuse");
        assert!(error.contains("not a regular file"), "{error}");
        fs::remove_dir_all(&dir).ok();
    }

    /// TR-XFER-01: a source that another user can write is refused.
    #[cfg(unix)]
    #[test]
    fn upload_source_writable_by_others_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, file) = upload_fixture("mode", b"data");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o666)).expect("mode");
        let error = open_upload_source(&dir, &dir, &file, false).expect_err("must refuse");
        assert!(error.contains("writable by group or other"), "{error}");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("mode");
        assert!(open_upload_source(&dir, &dir, &file, false).is_ok());
        fs::remove_dir_all(&dir).ok();
    }

    /// TR-XFER-04: the hash pass reads exactly the size that the open reported and
    /// fails for a file that is shorter or longer.
    #[test]
    fn hash_local_file_detects_a_change_of_size() {
        let (dir, file) = upload_fixture("hashpass", b"0123456789");
        let open = || fs::File::open(&file).expect("open");
        assert_eq!(
            hash_local_file(open(), 10).expect("exact"),
            hex_sha256(&Sha256::digest(b"0123456789"))
        );
        assert!(hash_local_file(open(), 11).is_err(), "a longer claim");
        assert!(hash_local_file(open(), 9).is_err(), "a shorter claim");
        fs::remove_dir_all(&dir).ok();
    }

    /// AC-FS-10: the confirmation of a directory copy shows the file, directory
    /// and byte counts from the scan; a file copy shows the size.
    #[test]
    fn copy_file_shows_the_counts() {
        let directory = SourceScan {
            full_name: "D:\\Data\\tree".to_owned(),
            is_directory: true,
            link_type: None,
            nested_link: false,
            truncated: false,
            unreadable: false,
            file_count: 3,
            dir_count: 2,
            byte_count: 4096,
            roots: crate::policy::HostRoots::default(),
        };
        let fields = source_size_fields(&directory);
        assert_eq!(
            fields,
            vec![
                ("Files", "3".to_owned()),
                ("Directories", "2".to_owned()),
                ("Bytes", "4096".to_owned()),
            ]
        );
        let prompt = Confirmation::new("copy_file", "COPY DIRECTORY", "host1", "contoso\\alice")
            .path("Source", "D:\\Data\\tree")
            .path("Target", "D:\\Backup\\tree")
            .field("Overwrite", "no")
            .field(fields[0].0, &fields[0].1)
            .field(fields[1].0, &fields[1].1)
            .field(fields[2].0, &fields[2].1)
            .render();
        assert!(prompt.contains("Files: 3"), "{prompt}");
        assert!(prompt.contains("Directories: 2"), "{prompt}");
        assert!(prompt.contains("Bytes: 4096"), "{prompt}");

        // A copy of one file names its size, not the tree counts.
        let file = SourceScan {
            is_directory: false,
            byte_count: 12,
            ..directory
        };
        assert_eq!(source_size_fields(&file), vec![("Bytes", "12".to_owned())]);
        // A truncated scan names the counts as lower bounds.
        let big = SourceScan {
            is_directory: true,
            truncated: true,
            ..file
        };
        assert!(source_size_fields(&big)[0].1.contains("lower bound"));
    }

    /// AC-FS-10, ADR-0017 §15: an existing directory target is refused before the
    /// network, with or without `overwrite`.
    #[test]
    fn copy_refuses_a_directory_overwrite() {
        let target = "D:\\Backup\\logs";
        let scan = WriteScan {
            full_name: target.to_owned(),
            dotnet_full_name: target.to_owned(),
            exists: true,
            is_directory: true,
            link_type: None,
            roots: crate::policy::HostRoots::default(),
        };
        for overwrite in [false, true] {
            let decision = decide_file_op_target(&scan, target, true, overwrite, "copy to", &[]);
            assert!(!decision.allow, "overwrite={overwrite}");
            assert_eq!(decision.code, "PATH_IS_DIRECTORY");
        }
    }

    /// AC-FS-11, ADR-0017 §18: a cross-volume move of a directory is refused; a file
    /// across volumes and anything on one volume is allowed.
    #[test]
    fn cross_volume_directory_move_is_refused() {
        let decision = decide_move_volume("C:\\Data\\dir", "D:\\Data\\dir", true);
        assert!(!decision.allow, "{}", decision.reason);
        assert_eq!(decision.code, "CROSS_VOLUME_MOVE");
        assert!(decide_move_volume("C:\\Data\\a.txt", "D:\\Data\\a.txt", false).allow);
        assert!(decide_move_volume("C:\\Data\\dir", "C:\\Data\\dir2", true).allow);
    }

    /// AC-FS-12, TR-FS-11: the create-directory confirmation shows the number of
    /// created levels, and every created level lies under the resolved path.
    #[test]
    fn create_directory_shows_the_created_levels() {
        assert_eq!(created_levels_label(1), "1 level");
        assert_eq!(created_levels_label(3), "3 levels");
        let prompt = Confirmation::new(
            "create_directory",
            "CREATE DIRECTORY",
            "host1",
            "contoso\\alice",
        )
        .path("Path", "C:\\Data\\a\\b\\c")
        .path("Resolved", "C:\\Data\\a\\b\\c")
        .field("Created levels", &created_levels_label(3))
        .render();
        assert!(prompt.contains("Created levels: 3 levels"), "{prompt}");

        let raw = r#"{"FullName":"C:\\Data\\a\\b\\c","DotNetFullName":"C:\\Data\\a\\b\\c","Exists":false,"IsDirectory":false,"LinkType":null,"MissingLevels":3,"TopMissing":"C:\\Data\\a","Roots":{"SystemRoot":"C:\\Windows"}}"#;
        assert_eq!(missing_levels(raw), 3);
        assert_eq!(missing_levels("not json"), 0);
        assert_eq!(top_missing(raw).as_deref(), Some("C:\\Data\\a"));
        assert_eq!(top_missing("not json"), None);

        // A rename derives its target from the resolved path plus the new name.
        assert_eq!(
            rename_target("C:\\Data\\old.txt", "new.txt").as_deref(),
            Some("C:\\Data\\new.txt")
        );
        assert_eq!(rename_target("old.txt", "new.txt"), None);
    }

    /// TR-FS-09/10, item 7: a command with a non-zero exit is a failure, and its JSON
    /// carries the counts and a plain error; a zero exit with JSON is a success.
    #[test]
    fn file_op_reply_reports_a_partial_copy_as_an_error() {
        let partial = json!({
            "status_code": 1,
            "stdout": "{\"Mode\":\"directory\",\"Total\":5,\"Copied\":2,\"Error\":\"the target may be partial: access denied\"}",
            "stderr": "",
        });
        let value = file_op_reply(&partial)
            .structured_content
            .expect("structured");
        assert!(
            value
                .get("error")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|error| error.contains("may be partial")),
            "{value}"
        );
        assert!(
            value
                .get("output")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|out| out.contains("\"Copied\":2")),
            "{value}"
        );

        let done = json!({
            "status_code": 0,
            "stdout": "{\"Mode\":\"file\",\"Total\":1,\"Copied\":1,\"Error\":\"\"}",
            "stderr": "",
        });
        let value = file_op_reply(&done).structured_content.expect("structured");
        assert_eq!(
            value.get("status").and_then(serde_json::Value::as_str),
            Some("ok")
        );
        assert_eq!(
            value.get("Copied").and_then(serde_json::Value::as_i64),
            Some(1)
        );
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
        assert!(!decide_write_path("C:\\Windows\\System32\\config", &[]).allow);
        assert!(decide_write_path("C:\\App\\config.json", &[]).allow);
    }

    /// AC-FS-08, TR-SEC-21: a protected write that the operator allowlist covers
    /// passes the policy with the warning sentence, and the confirmation line names
    /// the class.
    #[test]
    fn allowed_write_path_carries_the_warning_line() {
        let allowed = vec!["C:\\ProgramData\\Vendor".to_owned()];
        let target = "C:\\ProgramData\\Vendor\\db.sqlite";
        let scan = WriteScan {
            full_name: target.to_owned(),
            dotnet_full_name: target.to_owned(),
            exists: false,
            is_directory: false,
            link_type: None,
            roots: crate::policy::HostRoots::default(),
        };
        let decision = decide_write_scan(&scan, target, false, &allowed);
        assert!(decision.allow, "{}", decision.reason);
        assert_eq!(
            decision.class,
            Some("the target lies in a system directory")
        );
        assert_eq!(decision.matched.as_deref(), Some("C:\\ProgramData\\Vendor"));

        let prompt = Confirmation::new("write_file", "WRITE FILE", "host1", "contoso\\alice")
            .field("Warning", decision.class.expect("a class"))
            .render();
        assert!(
            prompt.contains("Warning: the target lies in a system directory"),
            "{prompt}"
        );
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
        assert!(tools.iter().any(|tool| tool.name == "copy_file"));
        assert!(tools.iter().any(|tool| tool.name == "move_file"));
        assert!(tools.iter().any(|tool| tool.name == "rename_file"));
        assert!(tools.iter().any(|tool| tool.name == "create_directory"));
        assert!(tools.iter().any(|tool| tool.name == "download_file"));
        assert!(tools.iter().any(|tool| tool.name == "upload_file"));
        // An exact count: "at least 30" would catch neither a lost tool nor a
        // duplicate. These are all declared tools; the configuration decides
        // how many the agent sees (TR-FS-01, TR-FS-08, TR-EXE-01, TR-EXE-05), and
        // `write_file_is_absent_until_the_operator_enables_it`,
        // `file_ops_are_absent_until_the_operator_enables_them`,
        // `run_command_is_absent_until_the_operator_enables_it` and
        // `run_script_is_absent_until_the_operator_enables_it` check that.
        assert_eq!(tools.len(), 52, "expected 52 declared tools");
        let mut names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 52, "tool names must be unique");
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
            "copy_file",
            "create_directory",
            "delete_directory",
            "delete_file",
            "download_file",
            "flush_dns",
            "kill_process",
            "move_file",
            "rename_file",
            "restart_service",
            "run_command",
            "run_script",
            "set_registry",
            "set_service_start_type",
            "start_service",
            "stop_service",
            "upload_file",
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
            EFFECT_COPY_FILE,
            EFFECT_COPY_DIRECTORY,
            EFFECT_MOVE,
            EFFECT_RENAME,
            EFFECT_CREATE_DIRECTORY,
            EFFECT_DOWNLOAD_FILE,
            EFFECT_UPLOAD_NEW,
            EFFECT_UPLOAD_REPLACE,
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
