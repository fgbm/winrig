//! Tool calls through the real MCP channel and the confirmation channel (DR-5).
//!
//! The server unit tests call the functions directly and therefore never touch
//! `WinrigServer::confirm`: elicitation exists only between two peers. Here the
//! client and the server are joined by a pair of in-memory transports
//! (`tokio::io::duplex`), the Windows host is replaced by a recording transport
//! (AGENTS.md §4), and the client answer selects the confirmation branch.
//!
//! The check covers not only the tool response text but also whether the command
//! reached the transport: a refusal must be fail-closed, not "answered cancelled
//! and still executed".

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rmcp::ServiceExt;
use rmcp::handler::client::ClientHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ClientCapabilities, ClientConfig, ElicitRequestParams,
    ElicitResult, ElicitationAction, ElicitationCapability, ErrorData as McpError, JsonObject,
    UrlElicitationCapability,
};
use rmcp::service::{RequestContext, RoleClient, RunningService};
use winrig::config::{AppConfig, load_config_from};
use winrig::identity::ProfileIdentity;
use winrig::server::WinrigServer;
use winrig::session::{
    RegistryConfig, RemoteOutput, SessionRegistry, SessionTarget, TransportError, WinRmTransport,
};

const HOST: &str = "host1";
const USER: &str = "contoso\\alice";
const PASSWORD: &str = "s3cret";
/// Signature of the mutating `flush_dns` command in the script sent to the host.
const MUTATION: &str = "Clear-DnsClientCache";
/// Output the fake host prints for any command.
const HOST_STDOUT: &str = "HOST1|Windows|10.0|2026-01-01 00:00:00";

/// A fake Windows host that records every script it receives.
struct RecordingTransport {
    calls: Mutex<Vec<String>>,
    /// Canned stdout per substring: the first entry whose key is in the script
    /// wins. Without a match the host prints [`HOST_STDOUT`].
    responses: Mutex<Vec<(String, String)>>,
    /// When set, the temp-directory probe is answered with `<dir>\<name>`, where
    /// the name is the file the probe asked for. A test sets it to satisfy the
    /// staging-path validation.
    staging_dir: Mutex<Option<String>>,
}

#[async_trait::async_trait]
impl WinRmTransport for RecordingTransport {
    async fn run_powershell(
        &self,
        _target: &SessionTarget,
        script: &str,
    ) -> Result<RemoteOutput, TransportError> {
        self.calls.lock().expect("lock").push(script.to_owned());
        if let Some(dir) = self.staging_dir.lock().expect("lock").clone()
            && script.contains("[IO.Path]::Combine")
        {
            let name = probe_file_name(script).unwrap_or_default();
            return Ok(RemoteOutput {
                stdout: format!("{dir}\\{name}").into_bytes(),
                stderr: Vec::new(),
                exit_code: 0,
            });
        }
        let stdout = self
            .responses
            .lock()
            .expect("lock")
            .iter()
            .find(|(needle, _)| script.contains(needle))
            .map(|(_, stdout)| stdout.clone())
            .unwrap_or_else(|| HOST_STDOUT.to_owned());
        Ok(RemoteOutput {
            stdout: stdout.into_bytes(),
            stderr: Vec::new(),
            exit_code: 0,
        })
    }
}

/// The `winrig-<suffix>.ps1` name that the temp-directory probe script asks for.
fn probe_file_name(script: &str) -> Option<String> {
    let start = script.find("'winrig-")? + 1;
    let rest = &script[start..];
    let end = rest.find('\'')?;
    Some(rest[..end].to_owned())
}

impl RecordingTransport {
    /// True when at least one script contains the substring.
    fn saw(&self, needle: &str) -> bool {
        self.calls
            .lock()
            .expect("lock")
            .iter()
            .any(|call| call.contains(needle))
    }

    /// Print `stdout` for every script that contains `needle`.
    fn respond(&self, needle: &str, stdout: &str) {
        self.responses
            .lock()
            .expect("lock")
            .push((needle.to_owned(), stdout.to_owned()));
    }
}

/// How the test client replies to a confirmation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    Accept,
    Decline,
    /// The user never answers; the decision stays with the server timeout.
    Silent,
    /// The client does not declare elicitation; the confirmation channel is absent.
    NoChannel,
    /// The client declares elicitation in URL mode only; a form request has no
    /// channel.
    UrlOnly,
    /// The channel is present but the request fails; the state is unknown.
    Error,
}

/// An MCP client whose only job is to answer a confirmation in a given way and
/// count how many times it was asked.
#[derive(Debug, Clone)]
struct TestClient {
    answer: Answer,
    elicitations: Arc<AtomicUsize>,
    /// The message of each confirmation the server asked for.
    messages: Arc<Mutex<Vec<String>>>,
}

impl ClientHandler for TestClient {
    async fn create_elicitation(
        &self,
        params: ElicitRequestParams,
        _context: RequestContext<RoleClient>,
    ) -> Result<ElicitResult, McpError> {
        self.elicitations.fetch_add(1, Ordering::SeqCst);
        if let ElicitRequestParams::FormElicitationParams { message, .. } = &params {
            self.messages.lock().expect("lock").push(message.clone());
        }
        match self.answer {
            Answer::Accept => Ok(ElicitResult::new(ElicitationAction::Accept)
                .with_content(serde_json::json!({ "confirm": true }))),
            Answer::Decline => Ok(ElicitResult::new(ElicitationAction::Decline)),
            // Silence is not a protocol error but an unresponsive operator: no
            // answer ever comes.
            Answer::Silent => std::future::pending().await,
            Answer::NoChannel => unreachable!("server must not elicit without the capability"),
            // A URL-only client has no form channel, so the server never asks.
            Answer::UrlOnly => unreachable!("server must not elicit without a form channel"),
            Answer::Error => Err(McpError::internal_error("channel failure", None)),
        }
    }

    fn get_info(&self) -> ClientConfig {
        let mut info = ClientConfig::default();
        info.capabilities = match self.answer {
            Answer::NoChannel => ClientCapabilities::default(),
            Answer::UrlOnly => {
                let mut capabilities = ClientCapabilities::default();
                capabilities.elicitation =
                    Some(ElicitationCapability::new().with_url(UrlElicitationCapability::new()));
                capabilities
            }
            _ => ClientCapabilities::builder().enable_elicitation().build(),
        };
        info
    }
}

/// Builds the settings with the shared secret and optional overrides.
fn config(overrides: &[(&str, &str)]) -> AppConfig {
    let owned: Vec<(String, String)> = overrides
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect();
    // `Env` carries no lifetime, so the closure must own the data.
    let lookup: Box<winrig::config::Env> = Box::new(move |name: &str| {
        if name == "WINRIG_AUTH_TOKEN" {
            return Some("token".to_owned());
        }
        let found = owned
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone());
        // The fake host is not loopback, so the harness allows it explicitly, as an
        // operator would (ADR-0015 §6). An empty override returns the default.
        if name == "WINRIG_ALLOWED_HOSTS" {
            return match found {
                Some(value) if value.is_empty() => None,
                Some(value) => Some(value),
                None => Some(HOST.to_owned()),
            };
        }
        found
    });
    load_config_from(lookup.as_ref()).expect("config")
}

/// The client, server and fake host wiring for one test.
struct Harness {
    client: RunningService<RoleClient, TestClient>,
    transport: Arc<RecordingTransport>,
    elicitations: Arc<AtomicUsize>,
    messages: Arc<Mutex<Vec<String>>>,
}

impl Harness {
    /// How many times the server asked for confirmation.
    fn elicitations(&self) -> usize {
        self.elicitations.load(Ordering::SeqCst)
    }

    /// What the server showed the operator in the most recent prompt.
    fn last_confirmation(&self) -> String {
        self.messages
            .lock()
            .expect("lock")
            .last()
            .cloned()
            .unwrap_or_default()
    }

    async fn call(&self, params: CallToolRequestParams) -> CallToolResult {
        self.client.call_tool(params).await.expect("tool call")
    }
}

/// Starts the server and the client on a pair of in-memory transports and opens a
/// session.
///
/// The identity comes from the profile, as in stdio: there are no HTTP headers
/// here, and the check targets the tool layer, not the gate (`http_gate.rs` covers
/// that).
async fn connected(answer: Answer, overrides: &[(&str, &str)]) -> Harness {
    let harness = started(answer, overrides).await;
    let connect = harness.call(connect_to(HOST)).await;
    assert_eq!(
        status_of(&connect).as_deref(),
        Some("connected"),
        "connect must succeed before the tool under test: {:?}",
        connect.structured_content
    );
    harness
}

/// One `connect` call for the given host.
fn connect_to(host: &str) -> CallToolRequestParams {
    CallToolRequestParams::new("connect").with_arguments(args(&serde_json::json!({
        "host": host
    })))
}

/// Brings up the server and the client without opening a session.
async fn started(answer: Answer, overrides: &[(&str, &str)]) -> Harness {
    let transport = Arc::new(RecordingTransport {
        calls: Mutex::new(Vec::new()),
        responses: Mutex::new(Vec::new()),
        staging_dir: Mutex::new(None),
    });
    let registry = Arc::new(SessionRegistry::new(
        Arc::clone(&transport) as Arc<dyn WinRmTransport>,
        RegistryConfig::default(),
    ));
    let identity = Arc::new(ProfileIdentity {
        username: USER.to_owned(),
        password: PASSWORD.to_owned().into(),
    });
    let server =
        WinrigServer::with_profile_identity(registry, Arc::new(config(overrides)), identity);

    let (server_side, client_side) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        if let Ok(running) = server.serve(server_side).await {
            let _ = running.waiting().await;
        }
    });
    let elicitations = Arc::new(AtomicUsize::new(0));
    let messages = Arc::new(Mutex::new(Vec::new()));
    let client = TestClient {
        answer,
        elicitations: Arc::clone(&elicitations),
        messages: Arc::clone(&messages),
    }
    .serve(client_side)
    .await
    .expect("client handshake");

    Harness {
        client,
        transport,
        elicitations,
        messages,
    }
}

/// Turns a JSON object into tool call arguments.
fn args(value: &serde_json::Value) -> JsonObject {
    value.as_object().cloned().expect("object arguments")
}

/// The string value of a structured tool response key.
fn field(result: &CallToolResult, name: &str) -> Option<String> {
    result
        .structured_content
        .as_ref()?
        .get(name)?
        .as_str()
        .map(str::to_owned)
}

/// The numeric value of a structured tool response key.
fn number(result: &CallToolResult, name: &str) -> Option<i64> {
    result.structured_content.as_ref()?.get(name)?.as_i64()
}

fn status_of(result: &CallToolResult) -> Option<String> {
    field(result, "status")
}

fn error_of(result: &CallToolResult) -> Option<String> {
    field(result, "error")
}

/// A call to the mutating tool `flush_dns` in an open session.
fn flush_dns() -> CallToolRequestParams {
    CallToolRequestParams::new("flush_dns").with_arguments(args(&serde_json::json!({
        "session_id": HOST
    })))
}

/// AC-REL09-4: a read asks no confirmation and reaches the host.
///
/// The client declares elicitation and is ready to answer Accept, so "it was not
/// asked" is a statement about the server, not about a client unable to answer.
#[tokio::test]
async fn read_only_tool_needs_no_confirmation() {
    let harness = connected(Answer::Accept, &[]).await;
    let before = harness.elicitations();
    let result = harness
        .call(
            CallToolRequestParams::new("get_system_info")
                .with_arguments(args(&serde_json::json!({ "session_id": HOST }))),
        )
        .await;

    assert_eq!(
        error_of(&result),
        None,
        "read-only tool must not fail: {:?}",
        result.structured_content
    );
    assert_eq!(
        harness.elicitations(),
        before,
        "a read-only tool asked for confirmation"
    );
    assert!(
        harness.transport.saw("Win32_OperatingSystem"),
        "the read-only command never reached the host"
    );
    harness.client.cancel().await.ok();
}

/// AC-REL09-1: a confirmed modification runs.
#[tokio::test]
async fn confirmed_modification_executes() {
    let harness = connected(Answer::Accept, &[]).await;
    let result = harness.call(flush_dns()).await;

    assert_eq!(
        harness.elicitations(),
        1,
        "a mutating tool must ask exactly once"
    );
    assert!(
        harness.transport.saw(MUTATION),
        "confirmed modification never reached the host"
    );
    // A positive sign: the response is the result of the run on the host. A refusal
    // envelope carries no such fields, so there is no need to check for a missing
    // status field.
    assert_eq!(
        number(&result, "status_code"),
        Some(0),
        "confirmed flush_dns must report the host exit code: {:?}",
        result.structured_content
    );
    assert_eq!(
        field(&result, "stdout").as_deref(),
        Some(HOST_STDOUT),
        "confirmed flush_dns must return the host output: {:?}",
        result.structured_content
    );
    assert_eq!(
        error_of(&result),
        None,
        "confirmed flush_dns must not report an error: {:?}",
        result.structured_content
    );
    harness.client.cancel().await.ok();
}

/// AC-REL09-2: an operator refusal does not run the command (DR-5).
#[tokio::test]
async fn declined_modification_does_not_execute() {
    let harness = connected(Answer::Decline, &[]).await;
    let result = harness.call(flush_dns()).await;

    assert!(
        !harness.transport.saw(MUTATION),
        "declined modification still reached the host"
    );
    assert_eq!(
        status_of(&result).as_deref(),
        Some("cancelled"),
        "declined flush_dns must answer cancelled: {:?}",
        result.structured_content
    );
    harness.client.cancel().await.ok();
}

/// AC-REL09-3: without a confirmation channel a modification refuses (fail-closed).
#[tokio::test]
async fn client_without_elicitation_is_refused() {
    let harness = connected(Answer::NoChannel, &[]).await;
    let result = harness.call(flush_dns()).await;

    assert!(
        !harness.transport.saw(MUTATION),
        "modification ran without a confirmation channel"
    );
    assert_eq!(
        harness.elicitations(),
        0,
        "the server asked a client that never declared elicitation"
    );
    // "Nobody to ask", not "asked and timed out": only the absent-channel
    // message says "cannot ask for confirmation".
    assert!(
        error_of(&result).is_some_and(|error| error.contains("cannot ask for confirmation")),
        "a client without elicitation must be refused for the absent channel: {:?}",
        result.structured_content
    );
    harness.client.cancel().await.ok();
}

/// AC-SEC12-1: scripts built in `server.rs`, not in the `ps.rs` generators, double
/// every form of a single quote (TR-SEC-12).
///
/// The check targets what went to the host: the operator confirms, so both the
/// preliminary reads and the modifications themselves reach the transport.
#[tokio::test]
async fn inline_scripts_escape_every_single_quote_form() {
    for quote in winrig::ps::SINGLE_QUOTES {
        let evil = format!("x{quote} ; Remove-Item -Recurse C:\\ ; {quote}");
        let harness = connected(Answer::Accept, &[]).await;
        let calls = [
            ("restart_service", serde_json::json!({ "name": evil })),
            ("stop_service", serde_json::json!({ "name": evil })),
            ("start_service", serde_json::json!({ "name": evil })),
            (
                "set_registry",
                serde_json::json!({ "key": evil, "value_name": evil, "value_data": evil }),
            ),
            ("delete_file", serde_json::json!({ "path": evil })),
            ("delete_directory", serde_json::json!({ "path": evil })),
        ];
        for (tool, mut arguments) in calls {
            arguments["session_id"] = serde_json::json!(HOST);
            harness
                .call(CallToolRequestParams::new(tool).with_arguments(args(&arguments)))
                .await;
        }
        let scripts = harness.transport.calls.lock().expect("lock").clone();
        let opened = format!("x{quote} ");
        let doubled = format!("x{quote}{quote} ");
        assert!(
            scripts.iter().any(|script| script.contains(&doubled)),
            "no escaped value reached the host: {scripts:#?}"
        );
        for script in scripts {
            assert!(
                !script.contains(&opened),
                "quote {quote:?} left unescaped: {script}"
            );
        }
        harness.client.cancel().await.ok();
    }
}

/// AC-REL08-1: operator silence is a timeout refusal, not execution.
#[tokio::test]
async fn timeout_refuses_and_does_not_execute() {
    let harness = connected(Answer::Silent, &[("WINRIG_CONFIRM_TIMEOUT_SECONDS", "1")]).await;
    let result = harness.call(flush_dns()).await;

    assert!(
        !harness.transport.saw(MUTATION),
        "modification ran after the confirmation timed out"
    );
    assert_eq!(
        harness.elicitations(),
        1,
        "the timeout must follow an unanswered question, not a missing one"
    );
    assert_eq!(
        status_of(&result).as_deref(),
        Some("timeout"),
        "silence must end in a timeout refusal: {:?}",
        result.structured_content
    );
    harness.client.cancel().await.ok();
}

/// AC-REL11-1: with `subkeys=true` the recorded command lists the child key names
/// down to the given depth next to the values, and a depth above the range is
/// clamped to the deepest walk (TR-REL-11).
#[tokio::test]
async fn get_registry_subkeys_lists_the_child_key_names() {
    let harness = connected(Answer::Accept, &[]).await;
    let key = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Print\\Printers";
    let result = harness
        .call(
            CallToolRequestParams::new("get_registry").with_arguments(args(&serde_json::json!({
                "session_id": HOST,
                "key": key,
                "subkeys": true,
                "depth": 2
            }))),
        )
        .await;
    assert_eq!(
        error_of(&result),
        None,
        "subkeys read must not fail: {:?}",
        result.structured_content
    );
    // `depth` counts child levels, so depth 2 is `-Depth 1`.
    assert!(
        harness.transport.saw(&format!(
            "Get-ChildItem -LiteralPath '{key}' -Recurse -Depth 1"
        )),
        "the subkey walk of depth 2 never reached the host"
    );
    assert!(
        harness
            .transport
            .saw("$_.Name.Substring($root.Name.Length+1)"),
        "the child keys are not returned as paths relative to the key"
    );
    assert!(
        harness.transport.saw("Get-ItemProperty"),
        "the values part left the command"
    );

    let clamped = harness
        .call(
            CallToolRequestParams::new("get_registry").with_arguments(args(&serde_json::json!({
                "session_id": HOST,
                "key": key,
                "subkeys": true,
                "depth": 7
            }))),
        )
        .await;
    assert_eq!(
        error_of(&clamped),
        None,
        "a clamped depth must not fail: {:?}",
        clamped.structured_content
    );
    assert!(
        harness.transport.saw("-Depth 4"),
        "depth 5 is the deepest walk, so a higher value clamps to -Depth 4"
    );
    harness.client.cancel().await.ok();
}

/// AC-REL11-2: with the default `subkeys=false` the recorded command stays the
/// values-only form (TR-REL-11).
#[tokio::test]
async fn get_registry_default_stays_values_only() {
    let harness = connected(Answer::Accept, &[]).await;
    let key = "HKLM:\\SOFTWARE\\MyApp";
    let result = harness
        .call(
            CallToolRequestParams::new("get_registry").with_arguments(args(&serde_json::json!({
                "session_id": HOST,
                "key": key
            }))),
        )
        .await;
    assert_eq!(
        error_of(&result),
        None,
        "values-only read must not fail: {:?}",
        result.structured_content
    );
    assert!(
        harness.transport.saw(&format!(
            "Get-ItemProperty -LiteralPath '{key}' -ErrorAction Stop"
        )),
        "the values read never reached the host"
    );
    assert!(
        !harness.transport.saw("Get-ChildItem"),
        "the default call must not walk the key"
    );
    harness.client.cancel().await.ok();
}

/// AC-REL12-2: `list_event_logs` reads the channel list on the host, and a read
/// asks no confirmation.
#[tokio::test]
async fn list_event_logs_reads_the_channel_list_on_the_host() {
    let harness = connected(Answer::Accept, &[]).await;
    let before = harness.elicitations();
    let result = harness
        .call(
            CallToolRequestParams::new("list_event_logs").with_arguments(args(
                &serde_json::json!({
                    "session_id": HOST,
                    "filter": "Microsoft-Windows-*"
                }),
            )),
        )
        .await;
    assert_eq!(
        error_of(&result),
        None,
        "the channel list must not fail: {:?}",
        result.structured_content
    );
    assert_eq!(
        harness.elicitations(),
        before,
        "a read-only tool asked for confirmation"
    );
    assert!(
        harness
            .transport
            .saw("Get-WinEvent -ListLog 'Microsoft-Windows-*'"),
        "the channel list query never reached the host"
    );
    assert!(
        harness.transport.saw("name=$_.LogName"),
        "the recorded command does not name the channel"
    );
    assert!(
        harness.transport.saw("enabled=[bool]$_.IsEnabled"),
        "the recorded command does not return the enabled state"
    );
    harness.client.cancel().await.ok();
}

/// AC-REL12-1: a channel name with a single quote reaches the host with every
/// form of the quote doubled (TR-SEC-12).
#[tokio::test]
async fn get_event_log_doubles_the_channel_quote_on_the_host() {
    let harness = connected(Answer::Accept, &[]).await;
    let result = harness
        .call(
            CallToolRequestParams::new("get_event_log").with_arguments(args(&serde_json::json!({
                "session_id": HOST,
                "log_name": "Microsoft-Windows-X'Operational"
            }))),
        )
        .await;
    assert_eq!(
        error_of(&result),
        None,
        "the event read must not fail: {:?}",
        result.structured_content
    );
    assert!(
        harness
            .transport
            .saw("LogName='Microsoft-Windows-X''Operational'"),
        "the channel quote is not doubled in the recorded command"
    );
    harness.client.cancel().await.ok();
}

/// AC-REL13-1: `get_tcp_connections` with `state_filter='Listen'` and
/// `summary=true` filters on the state, groups the rows with a count and a
/// `Listen` row holds the bound address (TR-REL-13). The summary is read-only.
#[tokio::test]
async fn get_tcp_connections_summary_groups_listeners() {
    let harness = connected(Answer::Accept, &[]).await;
    let before = harness.elicitations();
    let result = harness
        .call(
            CallToolRequestParams::new("get_tcp_connections").with_arguments(args(
                &serde_json::json!({
                    "session_id": HOST,
                    "state_filter": "Listen",
                    "summary": true
                }),
            )),
        )
        .await;
    assert_eq!(
        error_of(&result),
        None,
        "the summary must not fail: {:?}",
        result.structured_content
    );
    assert_eq!(
        harness.elicitations(),
        before,
        "a read-only tool asked for confirmation"
    );
    assert!(
        harness.transport.saw("$_.State -eq 'Listen'"),
        "the state filter never reached the host"
    );
    assert!(
        harness.transport.saw("Group-Object"),
        "the summary does not group the rows"
    );
    assert!(
        harness.transport.saw("count=$_.Count"),
        "the summary groups carry no count"
    );
    assert!(
        harness
            .transport
            .saw("local_address=[string]$first.LocalAddress"),
        "a Listen row does not hold the bound address"
    );
    harness.client.cancel().await.ok();
}

/// TR-REL-13 backward compatibility: the default call still filters on
/// `Established` and returns the tabular form, not the grouped summary.
#[tokio::test]
async fn get_tcp_connections_default_stays_tabular() {
    let harness = connected(Answer::Accept, &[]).await;
    let result = harness
        .call(
            CallToolRequestParams::new("get_tcp_connections")
                .with_arguments(args(&serde_json::json!({ "session_id": HOST }))),
        )
        .await;
    assert_eq!(
        error_of(&result),
        None,
        "the default read must not fail: {:?}",
        result.structured_content
    );
    assert!(
        harness.transport.saw("$_.State -eq 'Established'"),
        "the default state filter never reached the host"
    );
    assert!(
        harness.transport.saw("Format-Table"),
        "the default output is not the tabular form"
    );
    assert!(
        !harness.transport.saw("Group-Object"),
        "the default call must not use the grouped summary"
    );
    harness.client.cancel().await.ok();
}

/// TR-REL-13: a `process` wildcard over 256 characters is refused before any
/// host call, with the limit in the message.
#[tokio::test]
async fn get_tcp_connections_refuses_a_long_process_filter_before_the_network() {
    let harness = connected(Answer::Accept, &[]).await;
    let result = harness
        .call(
            CallToolRequestParams::new("get_tcp_connections").with_arguments(args(
                &serde_json::json!({
                    "session_id": HOST,
                    "process": "a".repeat(257)
                }),
            )),
        )
        .await;
    let error = error_of(&result).expect("a refusal");
    assert!(error.contains("256"), "the limit is not named: {error}");
    assert!(
        !harness.transport.saw("Get-NetTCPConnection"),
        "the refused filter reached the host"
    );
    let at_limit = harness
        .call(
            CallToolRequestParams::new("get_tcp_connections").with_arguments(args(
                &serde_json::json!({
                    "session_id": HOST,
                    "process": "a".repeat(256)
                }),
            )),
        )
        .await;
    assert_eq!(
        error_of(&at_limit),
        None,
        "a filter at the limit is valid: {:?}",
        at_limit.structured_content
    );
    harness.client.cancel().await.ok();
}

/// TR-REL-13: an unknown `state_filter` is refused with the list of the accepted
/// values before any host call.
#[tokio::test]
async fn get_tcp_connections_refuses_an_unknown_state_before_the_network() {
    let harness = connected(Answer::Accept, &[]).await;
    let result = harness
        .call(
            CallToolRequestParams::new("get_tcp_connections").with_arguments(args(
                &serde_json::json!({
                    "session_id": HOST,
                    "state_filter": "galaxy"
                }),
            )),
        )
        .await;
    let error = error_of(&result).expect("a refusal");
    assert!(error.contains("Established"), "{error}");
    assert!(error.contains("Listen"), "{error}");
    assert!(error.contains("All"), "{error}");
    assert!(
        !harness.transport.saw("Get-NetTCPConnection"),
        "the refused state reached the host"
    );
    harness.client.cancel().await.ok();
}

/// AC-REL16-1: `search_file_content` with `from_end=true` records a command that
/// takes the last matches and streams the file. The tool is read-only (TR-REL-16).
#[tokio::test]
async fn search_file_content_from_end_takes_the_last_matches() {
    let harness = connected(Answer::Accept, &[]).await;
    let before = harness.elicitations();
    let result = harness
        .call(
            CallToolRequestParams::new("search_file_content").with_arguments(args(
                &serde_json::json!({
                    "session_id": HOST,
                    "path": "C:\\logs\\app.log",
                    "pattern": "ERROR",
                    "from_end": true
                }),
            )),
        )
        .await;
    assert_eq!(
        error_of(&result),
        None,
        "the search must not fail: {:?}",
        result.structured_content
    );
    assert_eq!(
        harness.elicitations(),
        before,
        "a read-only tool asked for confirmation"
    );
    assert!(
        harness
            .transport
            .saw("Select-String -Pattern 'ERROR' -SimpleMatch"),
        "the pattern never reached the host"
    );
    assert!(
        harness.transport.saw("Select-Object -Last 50"),
        "the command does not take the last matches"
    );
    harness.client.cancel().await.ok();
}

/// AC-REL16-1: `count_only=true` records a command that counts with
/// `Measure-Object` and returns no matching lines.
#[tokio::test]
async fn search_file_content_count_only_counts_matches() {
    let harness = connected(Answer::Accept, &[]).await;
    let result = harness
        .call(
            CallToolRequestParams::new("search_file_content").with_arguments(args(
                &serde_json::json!({
                    "session_id": HOST,
                    "path": "C:\\logs\\app.log",
                    "pattern": "ERROR",
                    "count_only": true
                }),
            )),
        )
        .await;
    assert_eq!(
        error_of(&result),
        None,
        "the count must not fail: {:?}",
        result.structured_content
    );
    assert!(
        harness.transport.saw("Measure-Object).Count"),
        "the command does not count the matches"
    );
    assert!(
        !harness.transport.saw("Select-Object -First"),
        "the count must not return matching lines"
    );
    harness.client.cancel().await.ok();
}

/// AC-REL16-2: `since`, `until` and `timestamp_format` record a command that
/// filters the lines by the timestamp at the start of the line, with the
/// invariant culture (TR-REL-16, Q-22).
#[tokio::test]
async fn search_file_content_time_filter_reaches_the_host() {
    let harness = connected(Answer::Accept, &[]).await;
    let result = harness
        .call(
            CallToolRequestParams::new("search_file_content").with_arguments(args(
                &serde_json::json!({
                    "session_id": HOST,
                    "path": "C:\\logs\\app.log",
                    "pattern": "ERROR",
                    "since": "2026-01-01 09:30:00",
                    "until": "2026-01-01 11:00:00",
                    "timestamp_format": "yyyy-MM-dd HH:mm:ss"
                }),
            )),
        )
        .await;
    assert_eq!(
        error_of(&result),
        None,
        "the time filter must not fail: {:?}",
        result.structured_content
    );
    assert!(
        harness
            .transport
            .saw("TryParseExact($ln.Substring(0,$len),$fmt,$inv"),
        "the command does not parse the line timestamp"
    );
    assert!(
        harness
            .transport
            .saw("[Globalization.CultureInfo]::InvariantCulture"),
        "the command does not use the invariant culture"
    );
    assert!(
        harness
            .transport
            .saw("ParseExact('2026-01-01T09:30:00.0000000','yyyy-MM-ddTHH:mm:ss.fffffff'"),
        "the lower bound is not an invariant ISO value"
    );
    harness.client.cancel().await.ok();
}

/// TR-REL-16: with `from_end` the directory search orders the files by their last
/// write time before `Select-String`, so the oldest file is not last.
#[tokio::test]
async fn search_file_content_from_end_sorts_the_directory() {
    let harness = connected(Answer::Accept, &[]).await;
    let result = harness
        .call(
            CallToolRequestParams::new("search_file_content").with_arguments(args(
                &serde_json::json!({
                    "session_id": HOST,
                    "path": "C:\\logs",
                    "pattern": "ERROR",
                    "from_end": true
                }),
            )),
        )
        .await;
    assert_eq!(
        error_of(&result),
        None,
        "the search must not fail: {:?}",
        result.structured_content
    );
    assert!(
        harness.transport.saw("Sort-Object LastWriteTime"),
        "the directory search does not sort the files"
    );
    harness.client.cancel().await.ok();
}

/// TR-REL-16: a time bound with an empty pattern records a command that matches
/// every line, without `-SimpleMatch` (AC-REL16-2).
#[tokio::test]
async fn search_file_content_time_only_uses_a_match_all_pattern() {
    let harness = connected(Answer::Accept, &[]).await;
    let result = harness
        .call(
            CallToolRequestParams::new("search_file_content").with_arguments(args(
                &serde_json::json!({
                    "session_id": HOST,
                    "path": "C:\\logs\\app.log",
                    "pattern": "",
                    "since": "2026-01-01 00:00:00"
                }),
            )),
        )
        .await;
    assert_eq!(
        error_of(&result),
        None,
        "the time-only filter must not fail: {:?}",
        result.structured_content
    );
    assert!(
        harness.transport.saw("Select-String -Pattern '.'"),
        "the time-only filter does not match every line"
    );
    assert!(
        !harness.transport.saw("-SimpleMatch"),
        "the time-only filter must not use SimpleMatch"
    );
    harness.client.cancel().await.ok();
}

/// TR-REL-16: an empty pattern without a time bound is refused before any host
/// call, because `Select-String -Pattern ''` rejects an empty string.
#[tokio::test]
async fn search_file_content_refuses_an_empty_pattern_before_the_host() {
    let harness = connected(Answer::Accept, &[]).await;
    let result = harness
        .call(
            CallToolRequestParams::new("search_file_content").with_arguments(args(
                &serde_json::json!({
                    "session_id": HOST,
                    "path": "C:\\logs\\app.log",
                    "pattern": ""
                }),
            )),
        )
        .await;
    let error = error_of(&result).expect("a refusal");
    assert!(error.contains("pattern is empty"), "{error}");
    assert!(
        !harness.transport.saw("Select-String"),
        "the refused search reached the host"
    );
    harness.client.cancel().await.ok();
}

/// TR-REL-16: `count_only` over a directory prints a summary line after the
/// per-file counts.
#[tokio::test]
async fn search_file_content_count_only_prints_the_summary() {
    let harness = connected(Answer::Accept, &[]).await;
    let result = harness
        .call(
            CallToolRequestParams::new("search_file_content").with_arguments(args(
                &serde_json::json!({
                    "session_id": HOST,
                    "path": "C:\\logs",
                    "pattern": "ERROR",
                    "count_only": true
                }),
            )),
        )
        .await;
    assert_eq!(
        error_of(&result),
        None,
        "the count must not fail: {:?}",
        result.structured_content
    );
    assert!(
        harness.transport.saw("files scanned"),
        "the count over a directory prints no summary line"
    );
    harness.client.cancel().await.ok();
}

/// TR-REL-16 backward compatibility: the default search keeps the first matches
/// and adds no time filter.
#[tokio::test]
async fn search_file_content_default_stays_first_and_without_time() {
    let harness = connected(Answer::Accept, &[]).await;
    let result = harness
        .call(
            CallToolRequestParams::new("search_file_content").with_arguments(args(
                &serde_json::json!({
                    "session_id": HOST,
                    "path": "C:\\logs\\app.log",
                    "pattern": "ERROR"
                }),
            )),
        )
        .await;
    assert_eq!(
        error_of(&result),
        None,
        "the default search must not fail: {:?}",
        result.structured_content
    );
    assert!(
        harness.transport.saw("Select-Object -First 50"),
        "the default does not keep the first matches"
    );
    assert!(
        !harness.transport.saw("TryParseExact"),
        "the default call must not add a time filter"
    );
    harness.client.cancel().await.ok();
}

/// TR-REL-16: an invalid time bound is refused before any host call, with the
/// accepted shape in the message.
#[tokio::test]
async fn search_file_content_refuses_an_invalid_time_bound_before_the_host() {
    let harness = connected(Answer::Accept, &[]).await;
    let result = harness
        .call(
            CallToolRequestParams::new("search_file_content").with_arguments(args(
                &serde_json::json!({
                    "session_id": HOST,
                    "path": "C:\\logs\\app.log",
                    "pattern": "ERROR",
                    "since": "yesterday"
                }),
            )),
        )
        .await;
    let error = error_of(&result).expect("a refusal");
    assert!(error.contains("Invalid timestamp"), "{error}");
    assert!(
        !harness.transport.saw("Select-String"),
        "the refused search reached the host"
    );
    harness.client.cancel().await.ok();
}

/// TR-REL-16, Q-22: `read_file` in the tail mode with `exclude` records a command
/// that drops the lines with the literal text. The tool is read-only.
#[tokio::test]
async fn read_file_tail_exclude_reaches_the_host() {
    let harness = connected(Answer::Accept, &[]).await;
    let before = harness.elicitations();
    let result = harness
        .call(
            CallToolRequestParams::new("read_file").with_arguments(args(&serde_json::json!({
                "session_id": HOST,
                "path": "C:\\logs\\app.log",
                "tail": true,
                "end_line": 100,
                "exclude": "heartbeat"
            }))),
        )
        .await;
    assert_eq!(
        error_of(&result),
        None,
        "the tail must not fail: {:?}",
        result.structured_content
    );
    assert_eq!(
        harness.elicitations(),
        before,
        "a read-only tool asked for confirmation"
    );
    assert!(
        harness
            .transport
            .saw("IndexOf('heartbeat', [StringComparison]::OrdinalIgnoreCase) -lt 0"),
        "the exclude filter never reached the host"
    );
    assert!(
        harness.transport.saw("-Tail $W"),
        "the tail does not grow a window from the end"
    );
    assert!(
        !harness.transport.saw("Where-Object"),
        "the exclude filter must not use Where-Object"
    );
    harness.client.cancel().await.ok();
}

/// TR-REL-16: `exclude` without `tail=true` is refused before any host call.
#[tokio::test]
async fn read_file_refuses_exclude_without_tail_before_the_host() {
    let harness = connected(Answer::Accept, &[]).await;
    let result = harness
        .call(
            CallToolRequestParams::new("read_file").with_arguments(args(&serde_json::json!({
                "session_id": HOST,
                "path": "C:\\logs\\app.log",
                "exclude": "heartbeat"
            }))),
        )
        .await;
    let error = error_of(&result).expect("a refusal");
    assert!(
        error.contains("exclude works only with tail=true"),
        "{error}"
    );
    assert!(
        !harness.transport.saw("Get-Content"),
        "the refused read reached the host"
    );
    harness.client.cancel().await.ok();
}

/// AC-SEC05-1, AC-SEC05-2: without `WINRIG_ALLOWED_HOSTS` a remote host is refused
/// before the network, and loopback passes (TR-SEC-14).
#[tokio::test]
async fn default_allowlist_refuses_remote_host_before_network() {
    let harness = started(Answer::Accept, &[("WINRIG_ALLOWED_HOSTS", "")]).await;
    let refused = harness.call(connect_to(HOST)).await;
    assert!(
        error_of(&refused).is_some_and(|error| error.contains("loopback")),
        "a remote host must be refused by the empty allowlist: {:?}",
        refused.structured_content
    );
    assert!(
        harness.transport.calls.lock().expect("lock").is_empty(),
        "the refused host reached the transport"
    );
    let local = harness.call(connect_to(" localhost ")).await;
    assert_eq!(
        status_of(&local).as_deref(),
        Some("connected"),
        "loopback must pass the empty allowlist: {:?}",
        local.structured_content
    );
    // The policy and the session see the same trimmed host string.
    assert_eq!(field(&local, "session_id").as_deref(), Some("localhost"));
    harness.client.cancel().await.ok();
}

/// AC-SEC06-1: by default `verify_cert=false` is refused before the network
/// (TR-SEC-06).
#[tokio::test]
async fn default_config_refuses_disabled_certificate_check() {
    let harness = started(Answer::Accept, &[]).await;
    let result = harness
        .call(
            CallToolRequestParams::new("connect").with_arguments(args(&serde_json::json!({
                "host": HOST,
                "port": 5986,
                "verify_cert": false
            }))),
        )
        .await;
    assert!(
        error_of(&result).is_some_and(|error| error.contains("WINRIG_ALLOW_INSECURE_TLS")),
        "disabled certificate check must be refused by default: {:?}",
        result.structured_content
    );
    assert!(
        harness.transport.calls.lock().expect("lock").is_empty(),
        "the refused connection reached the transport"
    );
    harness.client.cancel().await.ok();
}

thread_local! {
    /// Log capture buffer of the current thread; `None` means events are dropped.
    static SINK: std::cell::RefCell<Option<Arc<Mutex<Vec<u8>>>>> =
        const { std::cell::RefCell::new(None) };
}

/// Writer of the global subscriber: it puts an event into the thread buffer.
struct ThreadSink;

impl std::io::Write for ThreadSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        SINK.with(|sink| {
            if let Some(buffer) = sink.borrow().as_ref() {
                buffer.lock().expect("lock").extend_from_slice(bytes);
            }
        });
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Captures the log and the audit of the current thread.
///
/// The subscriber is global and single per binary: a temporary per-thread
/// subscriber loses events in a race for the shared callsite interest cache.
/// `tokio::test` runs the test and the server it spawns on one thread, so the
/// thread buffer sees the server audit.
fn capture() -> Arc<Mutex<Vec<u8>>> {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_writer(|| ThreadSink)
            .with_ansi(false)
            .finish();
        tracing::subscriber::set_global_default(subscriber).expect("single global subscriber");
    });
    let buffer = Arc::new(Mutex::new(Vec::new()));
    SINK.with(|sink| *sink.borrow_mut() = Some(Arc::clone(&buffer)));
    buffer
}

/// AC-OBS03-1: policy refusals before the network reach the audit with the tool and
/// the code (TR-OBS-03).
#[tokio::test]
async fn policy_refusals_are_audited() {
    let buffer = capture();
    let harness = connected(Answer::Accept, &[("WINRIG_ALLOW_FILE_WRITE", "true")]).await;
    let host = harness.call(connect_to("evil-host")).await;
    assert!(error_of(&host).is_some(), "{:?}", host.structured_content);
    let write = harness
        .call(
            CallToolRequestParams::new("write_file").with_arguments(args(&serde_json::json!({
                "session_id": HOST,
                "path": "C:\\Windows\\System32\\evil.dll",
                "content": "x"
            }))),
        )
        .await;
    assert!(error_of(&write).is_some(), "{:?}", write.structured_content);
    harness.client.cancel().await.ok();

    let text = String::from_utf8_lossy(&buffer.lock().expect("lock")).into_owned();
    SINK.with(|sink| sink.borrow_mut().take());
    let refusals: Vec<&str> = text.split("POLICY REFUSED").skip(1).collect();
    assert!(
        refusals
            .iter()
            .any(|record| record.contains("connect") && record.contains("HOST_NOT_ALLOWED")),
        "host refusal missing from the audit: {text}"
    );
    assert!(
        refusals
            .iter()
            .any(|record| record.contains("write_file") && record.contains("PATH_PROTECTED")),
        "path refusal missing from the audit: {text}"
    );
}

/// A call to `stop_service` in an open session.
fn stop_service(name: &str, disable: bool) -> CallToolRequestParams {
    CallToolRequestParams::new("stop_service").with_arguments(args(&serde_json::json!({
        "session_id": HOST,
        "name": name,
        "disable": disable
    })))
}

/// A call to `set_service_start_type` in an open session.
fn set_start_type(name: &str, start_type: &str) -> CallToolRequestParams {
    CallToolRequestParams::new("set_service_start_type").with_arguments(args(&serde_json::json!({
        "session_id": HOST,
        "name": name,
        "start_type": start_type
    })))
}

/// AC-REL17-1: `get_service_config` is read-only, asks no confirmation, and its
/// recorded command reads the start type, the account, the binary path and the
/// recovery actions from CIM and the registry, not from the localized `sc.exe` text
/// (TR-REL-17).
#[tokio::test]
async fn get_service_config_reads_the_service_on_the_host() {
    let harness = connected(Answer::Accept, &[]).await;
    let before = harness.elicitations();
    let result = harness
        .call(
            CallToolRequestParams::new("get_service_config").with_arguments(args(
                &serde_json::json!({ "session_id": HOST, "name": "Spooler" }),
            )),
        )
        .await;
    assert_eq!(
        error_of(&result),
        None,
        "the read must not fail: {:?}",
        result.structured_content
    );
    assert_eq!(
        harness.elicitations(),
        before,
        "a read-only tool asked for confirmation"
    );
    assert!(
        harness.transport.saw("$n = 'Spooler'"),
        "the name never reached the host"
    );
    assert!(harness.transport.saw("Get-CimInstance Win32_Service"));
    assert!(harness.transport.saw("[string]$svc.StartMode"));
    assert!(harness.transport.saw("$svc.StartName"));
    assert!(harness.transport.saw("$svc.PathName"));
    assert!(harness.transport.saw("FailureActions"));
    assert!(harness.transport.saw("[BitConverter]::ToUInt32($fa, 0)"));
    assert!(
        !harness.transport.saw("sc qfailure"),
        "the parse must not read the localized sc.exe text"
    );
    harness.client.cancel().await.ok();
}

/// AC-REL18-1, findings 1/4: `stop_service` waits (default 15 s), refuses a protected
/// dependent before any write, reads the events 7031/7034/7036 by the decoded event
/// name, and returns an error that names the recovery restart when the service runs
/// again (TR-REL-18).
#[tokio::test]
async fn stop_service_reports_a_service_that_runs_again() {
    let harness = connected(Answer::Accept, &[]).await;
    harness.transport.respond(
        "running_again",
        r#"{"name":"Spooler","state":"Running","running_again":true,"stop_error":null,"wait_seconds":15,"disabled":false,"events":[{"id":7031}],"event_count":1}"#,
    );
    let result = harness.call(stop_service("Spooler", false)).await;

    assert!(
        harness.transport.saw("Start-Sleep -Seconds 15"),
        "the default wait never reached the host"
    );
    assert!(
        harness.transport.saw("Id=@(7031,7034,7036)"),
        "the events 7031/7034/7036 are not read"
    );
    assert!(
        !harness.transport.saw("-Force"),
        "the stop must not use -Force"
    );
    assert!(
        harness.transport.saw("(Get-WinrigEventName $_) -eq $n"),
        "the service is not matched by its decoded event name"
    );
    let error = error_of(&result).expect("a refusal when the service runs again");
    assert!(
        error.contains("recovery"),
        "the error must name the recovery restart: {error}"
    );
    assert!(error.contains("Spooler"), "{error}");
    harness.client.cancel().await.ok();
}

/// AC-REL18-2, finding 8: `stop_service(disable=true)` sets the start type `Disabled`
/// after the dependent check and before `Stop-Service`, in one script (TR-REL-18).
#[tokio::test]
async fn stop_service_disable_sets_the_start_type_before_the_stop() {
    let harness = connected(Answer::Accept, &[]).await;
    let result = harness.call(stop_service("Spooler", true)).await;
    assert_eq!(
        error_of(&result),
        None,
        "the stop must not fail: {:?}",
        result.structured_content
    );
    // One script must hold the whole order: dependent check, start-type change, stop.
    let script = harness
        .transport
        .calls
        .lock()
        .expect("lock")
        .iter()
        .find(|call| call.contains("Stop-Service -Name $n"))
        .cloned()
        .expect("the stop script reached the host");
    let dep_at = script
        .find("Get-WinrigDependents $n")
        .expect("dependent check");
    let config_at = script
        .find("sc.exe config $n start= disabled")
        .expect("start-type change");
    let stop_at = script.find("Stop-Service -Name $n").expect("stop");
    assert!(
        dep_at < config_at && config_at < stop_at,
        "the dependent check and the start-type change must precede the stop"
    );
    harness.client.cancel().await.ok();
}

/// finding 6: when the host reports a failed stop, the tool returns an error that
/// carries the half-done state (`start_type_changed`, `previous_start_type`,
/// `stop_error`).
#[tokio::test]
async fn stop_service_reports_a_partial_effect() {
    let harness = connected(Answer::Accept, &[]).await;
    harness.transport.respond(
        "stop_error",
        r#"{"name":"Spooler","state":"Running","state_before":"Running","running_again":false,"stop_error":"Cannot stop service because it has dependent services","start_type_changed":true,"previous_start_type":"Manual","dependents":["SpoolerDep"],"events":[],"event_count":0}"#,
    );
    let result = harness.call(stop_service("Spooler", true)).await;

    let error = error_of(&result).expect("a refusal when the stop failed");
    assert!(error.contains("failed"), "{error}");
    assert!(
        error.contains("SpoolerDep"),
        "the error must name the dependent services: {error}"
    );
    assert_eq!(
        result
            .structured_content
            .as_ref()
            .and_then(|value| value.get("start_type_changed"))
            .and_then(serde_json::Value::as_bool),
        Some(true),
        "the half-done start type must be reported: {:?}",
        result.structured_content
    );
    assert_eq!(
        field(&result, "previous_start_type").as_deref(),
        Some("Manual"),
        "{:?}",
        result.structured_content
    );
    harness.client.cancel().await.ok();
}

/// finding 2: the host resolves the canonical name; the recorded command carries the
/// host-side resolution and does not fall back to a display name.
#[tokio::test]
async fn stop_service_resolves_the_canonical_name_on_the_host() {
    let harness = connected(Answer::Accept, &[]).await;
    // "Server" is the display name of LanmanServer and passes the Rust charset gate,
    // so the host-side resolution must be present in the recorded command.
    let result = harness.call(stop_service("Server", false)).await;
    assert!(
        harness.transport.saw("Resolve-WinrigService 'Server'"),
        "the host does not resolve the canonical name: {:?}",
        result.structured_content
    );
    assert!(
        harness
            .transport
            .saw("the tool does not fall back to a display name"),
        "the host does not refuse a display name"
    );
    assert!(
        harness.transport.saw("$protected -contains $c"),
        "the host does not re-check the protected list on the canonical name"
    );
    harness.client.cancel().await.ok();
}

/// finding 3: a service name with a quote or a control character is refused before any
/// host call, on every modifying path.
#[tokio::test]
async fn invalid_service_names_are_refused_before_the_network() {
    let harness = connected(Answer::Accept, &[]).await;
    for (params, name) in [
        (set_start_type("a\"b", "Disabled"), "a\"b"),
        (stop_service("a\u{1}b", false), "a\u{1}b"),
        (
            CallToolRequestParams::new("restart_service").with_arguments(args(
                &serde_json::json!({ "session_id": HOST, "name": "a/b" }),
            )),
            "a/b",
        ),
    ] {
        let before = harness.transport.calls.lock().expect("lock").len();
        let result = harness.call(params).await;
        let error = error_of(&result).expect("a refusal");
        assert!(
            error.contains("letters, digits"),
            "the refusal must name the allowed set for {name:?}: {error}"
        );
        assert_eq!(
            harness.transport.calls.lock().expect("lock").len(),
            before,
            "the refused name {name:?} reached the host"
        );
    }
    harness.client.cancel().await.ok();
}

/// AC-SEC15-1: without a confirmation channel `set_service_start_type` refuses
/// (fail-closed); the set-type command never reaches the transport (DR-5).
#[tokio::test]
async fn set_service_start_type_without_channel_is_refused() {
    let harness = connected(Answer::NoChannel, &[]).await;
    let result = harness.call(set_start_type("Spooler", "Disabled")).await;

    assert!(
        !harness.transport.saw("sc.exe config"),
        "the set-type command reached the host without a confirmation"
    );
    assert_eq!(
        harness.elicitations(),
        0,
        "the server asked a client that never declared elicitation"
    );
    assert!(
        error_of(&result).is_some_and(|error| error.contains("cannot ask for confirmation")),
        "a client without elicitation must be refused: {:?}",
        result.structured_content
    );
    harness.client.cancel().await.ok();
}

/// AC-SEC15-2: with a confirmation the prompt shows the current and the new start
/// type, and the recorded command sets the type (TR-SEC-15).
#[tokio::test]
async fn set_service_start_type_shows_both_start_types() {
    let harness = connected(Answer::Accept, &[]).await;
    // The pre-confirmation read returns the current start type.
    harness.transport.respond(
        "FailureActionsOnNonCrashFailures",
        r#"{"name":"Spooler","start_type":"Manual","status":"Stopped"}"#,
    );
    let result = harness
        .call(set_start_type("Spooler", "AutomaticDelayed"))
        .await;
    assert_eq!(
        error_of(&result),
        None,
        "the change must not fail: {:?}",
        result.structured_content
    );
    let message = harness.last_confirmation();
    assert!(message.contains("Current start type: Manual"), "{message}");
    assert!(
        message.contains("New start type: AutomaticDelayed"),
        "{message}"
    );
    assert!(
        harness
            .transport
            .saw("sc.exe config $n start= delayed-auto"),
        "the recorded command does not set the new start type"
    );
    harness.client.cancel().await.ok();
}

/// AC-SEC15-2: an unknown start type is refused before any host call.
#[tokio::test]
async fn set_service_start_type_refuses_an_unknown_value() {
    let harness = connected(Answer::Accept, &[]).await;
    let before = harness.transport.calls.lock().expect("lock").len();
    let result = harness.call(set_start_type("Spooler", "Always")).await;
    let error = error_of(&result).expect("a refusal");
    assert!(error.contains("AutomaticDelayed"), "{error}");
    assert_eq!(
        harness.transport.calls.lock().expect("lock").len(),
        before,
        "the refused value reached the host"
    );
    harness.client.cancel().await.ok();
}

/// DR-5: an operator refusal on the verified stop stops nothing and changes no start
/// type on the host.
#[tokio::test]
async fn declined_stop_service_does_not_touch_the_host() {
    let harness = connected(Answer::Decline, &[]).await;
    let result = harness.call(stop_service("Spooler", true)).await;

    assert!(
        !harness.transport.saw("Stop-Service"),
        "declined stop reached the host"
    );
    assert!(
        !harness.transport.saw("sc.exe config"),
        "declined disable reached the host"
    );
    assert_eq!(
        status_of(&result).as_deref(),
        Some("cancelled"),
        "declined stop must answer cancelled: {:?}",
        result.structured_content
    );
    harness.client.cancel().await.ok();
}

/// AC-SEC15-3, Q-20: a service critical for the remote session is refused before any
/// host call, on every modifying path (TR-SEC-15, finding 7).
#[tokio::test]
async fn protected_services_are_refused_before_the_network() {
    let harness = connected(Answer::Accept, &[]).await;
    for (params, needle) in [
        (set_start_type("WinRM", "Disabled"), "winrm"),
        (stop_service("RpcSs", true), "RpCsS"),
        (stop_service("LanmanServer", false), "LANMANSERVER"),
        (
            CallToolRequestParams::new("restart_service").with_arguments(args(
                &serde_json::json!({ "session_id": HOST, "name": "winmgmt" }),
            )),
            "winmgmt",
        ),
    ] {
        let before = harness.transport.calls.lock().expect("lock").len();
        let result = harness.call(params).await;
        let error = error_of(&result).expect("a refusal");
        assert!(
            error.to_lowercase().contains(&needle.to_lowercase()),
            "the refusal must name the service: {error}"
        );
        assert!(
            error.contains("critical"),
            "the refusal must say why: {error}"
        );
        assert_eq!(
            harness.transport.calls.lock().expect("lock").len(),
            before,
            "the refused service reached the host"
        );
    }
    harness.client.cancel().await.ok();
}

// ---------------------------------------------------------------------------
// Confirmation text: the host, the user, the tool, the target and the effect
// ---------------------------------------------------------------------------

/// One `kill_process` call in an open session.
fn kill_process(pid: i64) -> CallToolRequestParams {
    CallToolRequestParams::new("kill_process").with_arguments(args(&serde_json::json!({
        "session_id": HOST,
        "pid": pid
    })))
}

/// One `set_registry` call in an open session.
fn set_registry_call(key: &str, name: &str, data: &str) -> CallToolRequestParams {
    CallToolRequestParams::new("set_registry").with_arguments(args(&serde_json::json!({
        "session_id": HOST,
        "key": key,
        "value_name": name,
        "value_data": data,
        "value_type": "String"
    })))
}

/// One `write_file` call in an open session.
fn write_file_call(path: &str, content: &str, overwrite: bool) -> CallToolRequestParams {
    CallToolRequestParams::new("write_file").with_arguments(args(&serde_json::json!({
        "session_id": HOST,
        "path": path,
        "content": content,
        "overwrite": overwrite
    })))
}

/// One `delete_file` call in an open session.
fn delete_file_call(path: &str) -> CallToolRequestParams {
    CallToolRequestParams::new("delete_file").with_arguments(args(&serde_json::json!({
        "session_id": HOST,
        "path": path
    })))
}

/// Every confirmation carries the header lines (TR-SEC-16, AC-SEC16-1).
fn assert_header(message: &str, tool: &str) {
    assert!(message.contains(&format!("Tool: {tool}")), "{message}");
    assert!(message.contains(&format!("Host: {HOST}")), "{message}");
    assert!(message.contains(&format!("User: {USER}")), "{message}");
}

/// The calls the transport recorded after the given index.
fn calls_from(harness: &Harness, from: usize) -> Vec<String> {
    harness
        .transport
        .calls
        .lock()
        .expect("lock")
        .iter()
        .skip(from)
        .cloned()
        .collect()
}

/// The captured audit text, and it clears the thread sink.
fn take_audit(buffer: &Arc<Mutex<Vec<u8>>>) -> String {
    let text = String::from_utf8_lossy(&buffer.lock().expect("lock")).into_owned();
    SINK.with(|sink| sink.borrow_mut().take());
    text
}

/// AC-SEC16-1, AC-SEC20-1: `flush_dns` names the host, the user and the tool, and
/// the whole prompt is stable English. The exact text is checked, so a change of
/// the wording or a host-localized string fails the test.
#[tokio::test]
async fn flush_dns_confirmation_is_stable_english() {
    let harness = connected(Answer::Accept, &[]).await;
    harness.call(flush_dns()).await;
    let message = harness.last_confirmation();
    assert_eq!(
        message,
        format!(
            "Confirm FLUSH DNS CACHE?\n\nTool: flush_dns\nHost: {HOST}\nUser: {USER}\n\n\
             This clears the whole DNS client cache. You cannot undo it."
        ),
        "the prompt must be the stable English text"
    );
    assert!(
        message.is_ascii(),
        "the prompt must hold no host locale: {message}"
    );
    harness.client.cancel().await.ok();
}

/// AC-SEC17-1: `restart_service` names the service, the plain state before the call
/// and the intended state `Running`.
#[tokio::test]
async fn restart_service_confirmation_shows_the_intended_state() {
    let harness = connected(Answer::Accept, &[]).await;
    harness
        .transport
        .respond("Select-Object -First 1", r#"{"Status":"Stopped"}"#);
    harness
        .call(
            CallToolRequestParams::new("restart_service").with_arguments(args(
                &serde_json::json!({ "session_id": HOST, "name": "Spooler" }),
            )),
        )
        .await;
    let message = harness.last_confirmation();
    assert_header(&message, "restart_service");
    assert!(message.contains("Service: Spooler"), "{message}");
    assert!(message.contains("State before: Stopped"), "{message}");
    assert!(message.contains("Intended state: Running"), "{message}");
    assert!(
        message.contains("This restarts the service. To undo it, stop the service."),
        "{message}"
    );
    harness.client.cancel().await.ok();
}

/// AC-SEC17-1: `stop_service` names the service, the plain state before the call and
/// the intended state `Stopped`.
#[tokio::test]
async fn stop_service_confirmation_shows_the_intended_state() {
    let harness = connected(Answer::Accept, &[]).await;
    harness
        .transport
        .respond("Select-Object -First 1", r#"{"Status":"Running"}"#);
    harness.transport.respond(
        "FailureActionsOnNonCrashFailures",
        r#"{"name":"Spooler","start_type":"Manual","status":"Stopped"}"#,
    );
    harness.call(stop_service("Spooler", false)).await;
    let message = harness.last_confirmation();
    assert_header(&message, "stop_service");
    assert!(message.contains("Service: Spooler"), "{message}");
    assert!(message.contains("State before: Running"), "{message}");
    assert!(message.contains("Intended state: Stopped"), "{message}");
    assert!(message.contains("Current start type: Manual"), "{message}");
    assert!(!message.contains("New start type"), "{message}");
    assert!(
        message.contains("This stops the service. To undo it, start the service."),
        "{message}"
    );
    harness.client.cancel().await.ok();
}

/// MAJOR: `stop_service` takes the current start type from `get_service_config`,
/// which knows `AutomaticDelayed`; only the state comes from the state read. The
/// value reaches the prompt and the recorded stop command.
#[tokio::test]
async fn stop_service_uses_the_configured_start_type() {
    let harness = connected(Answer::Accept, &[]).await;
    harness
        .transport
        .respond("Select-Object -First 1", r#"{"Status":"Running"}"#);
    harness.transport.respond(
        "FailureActionsOnNonCrashFailures",
        r#"{"name":"Spooler","start_type":"AutomaticDelayed","status":"Running"}"#,
    );
    let before = harness.transport.calls.lock().expect("lock").len();
    harness.call(stop_service("Spooler", true)).await;
    let message = harness.last_confirmation();
    assert!(
        message.contains("Current start type: AutomaticDelayed"),
        "{message}"
    );
    assert!(message.contains("New start type: Disabled"), "{message}");
    let calls = calls_from(&harness, before);
    assert!(
        calls
            .iter()
            .any(|call| call.contains("$prev='AutomaticDelayed'")),
        "the stop command does not carry the configured start type: {calls:?}"
    );
    harness.client.cancel().await.ok();
}

/// AC-SEC17-2: the whole `stop_service(disable=true)` prompt is the stable English
/// text with the service, the plain state, the current start type and the new start
/// type `Disabled` (TR-SEC-15).
#[tokio::test]
async fn stop_service_disable_confirmation_is_exact() {
    let harness = connected(Answer::Accept, &[]).await;
    harness
        .transport
        .respond("Select-Object -First 1", r#"{"Status":"Running"}"#);
    harness.transport.respond(
        "FailureActionsOnNonCrashFailures",
        r#"{"name":"Spooler","start_type":"Automatic","status":"Running"}"#,
    );
    harness.call(stop_service("Spooler", true)).await;
    let message = harness.last_confirmation();
    assert_eq!(
        message,
        format!(
            "Confirm STOP SERVICE?\n\nTool: stop_service\nHost: {HOST}\nUser: {USER}\n\
             Service: Spooler\nState before: Running\nCurrent start type: Automatic\n\
             Intended state: Stopped\nNew start type: Disabled\n\n\
             This sets the start type to Disabled, then stops the service. To undo it, set the \
             start type again and start the service."
        ),
        "the prompt must be the stable English text"
    );
    harness.client.cancel().await.ok();
}

/// AC-SEC17-1: `start_service` names the service, the plain state before the call
/// and the intended state `Running`.
#[tokio::test]
async fn start_service_confirmation_shows_the_intended_state() {
    let harness = connected(Answer::Accept, &[]).await;
    harness
        .transport
        .respond("Select-Object -First 1", r#"{"Status":"Stopped"}"#);
    harness
        .call(
            CallToolRequestParams::new("start_service").with_arguments(args(
                &serde_json::json!({ "session_id": HOST, "name": "Spooler" }),
            )),
        )
        .await;
    let message = harness.last_confirmation();
    assert_header(&message, "start_service");
    assert!(message.contains("Service: Spooler"), "{message}");
    assert!(message.contains("State before: Stopped"), "{message}");
    assert!(message.contains("Intended state: Running"), "{message}");
    assert!(
        message.contains("This starts the service. To undo it, stop the service."),
        "{message}"
    );
    harness.client.cancel().await.ok();
}

/// AC-SEC17-1, DR-4: `kill_process` names the PID, the name, the executable path
/// and the start time, and it states that the child processes continue to run. The
/// command line is never read, so a secret in it never reaches the prompt or the
/// audit.
#[tokio::test]
async fn kill_process_confirmation_never_reads_the_command_line() {
    let buffer = capture();
    let harness = connected(Answer::Accept, &[]).await;
    // A host that would return the command line if the read asked for it.
    harness.transport.respond(
        "CommandLine",
        r#"{"Name":"evil.exe","ExecutablePath":"C:\\evil.exe","Started":"2026-01-01T09:00:00Z","CommandLine":"evil.exe -P S3cr3t"}"#,
    );
    harness.transport.respond(
        "Win32_Process",
        r#"{"Name":"evil.exe","ExecutablePath":"C:\\evil.exe","Started":"2026-01-01T09:00:00Z"}"#,
    );
    let before = harness.transport.calls.lock().expect("lock").len();
    harness.call(kill_process(4242)).await;
    let message = harness.last_confirmation();
    assert_header(&message, "kill_process");
    assert!(message.contains("PID: 4242"), "{message}");
    assert!(message.contains("Name: evil.exe"), "{message}");
    assert!(
        message.contains("Executable path: C:\\evil.exe"),
        "{message}"
    );
    assert!(
        message.contains("Started: 2026-01-01T09:00:00Z"),
        "{message}"
    );
    assert!(!message.contains("Command line"), "{message}");
    assert!(
        message.contains("The child processes continue to run."),
        "{message}"
    );
    assert!(
        !message.contains("S3cr3t"),
        "the secret leaked into the prompt: {message}"
    );
    // The pre-read must not select the command line at all, and it must name the
    // fields it needs through -Property.
    let calls = calls_from(&harness, before);
    let pre = calls.first().expect("the pre-read reached the host");
    assert!(
        pre.contains("-Property"),
        "the read does not bound the properties: {pre}"
    );
    assert!(
        pre.contains("ExecutablePath") && pre.contains("CreationDate"),
        "the read does not select the named fields: {pre}"
    );
    assert!(
        calls.iter().all(|call| !call.contains("CommandLine")),
        "the pre-read selected the command line: {calls:?}"
    );
    harness.client.cancel().await.ok();
    let text = take_audit(&buffer);
    assert!(
        !text.contains("S3cr3t"),
        "the secret leaked into the audit: {text}"
    );
}

/// AC-SEC18-1: the whole `set_registry` prompt is the stable English text; the old
/// value appears only as `present (hidden, String)` and the new value only as
/// `hidden`. DR-4: the pre-read returns no data, so neither value reaches the
/// prompt or the audit.
#[tokio::test]
async fn set_registry_confirmation_is_exact_and_hides_both_values() {
    let buffer = capture();
    let harness = connected(Answer::Accept, &[]).await;
    // A host that would return the old data if the read asked for it.
    harness.transport.respond(
        "Select-Object -Property 'Password'",
        r#"{"Password":"OldS3cret"}"#,
    );
    harness
        .transport
        .respond("GetValueNames", r#"{"state":"present","type":"String"}"#);
    let before = harness.transport.calls.lock().expect("lock").len();
    harness
        .call(set_registry_call(
            "HKLM:\\SOFTWARE\\MyApp",
            "Password",
            "NewS3cret",
        ))
        .await;
    let message = harness.last_confirmation();
    assert_eq!(
        message,
        format!(
            "Confirm SET REGISTRY VALUE?\n\nTool: set_registry\nHost: {HOST}\nUser: {USER}\n\
             Key: HKLM:\\SOFTWARE\\MyApp\nValue: Password\nType: String\n\
             Old value: present (hidden, String)\nNew value: hidden\n\n\
             This sets the registry value. To undo it, restore the previous value."
        ),
        "the prompt must be the stable English text"
    );
    assert!(
        !message.contains("OldS3cret"),
        "the old value leaked into the prompt: {message}"
    );
    assert!(
        !message.contains("NewS3cret"),
        "the new value leaked into the prompt: {message}"
    );
    // The pre-read returns only the presence and the type, never the value data.
    let calls = calls_from(&harness, before);
    let pre = calls.first().expect("the pre-read reached the host");
    assert!(
        pre.contains("GetValueNames"),
        "the pre-read checks no presence: {pre}"
    );
    assert!(
        !pre.contains("Select-Object -Property"),
        "the pre-read reads the value data: {pre}"
    );
    harness.client.cancel().await.ok();
    let text = take_audit(&buffer);
    assert!(
        !text.contains("OldS3cret"),
        "the old value leaked into the audit: {text}"
    );
}

/// AC-SEC18-1: an absent old value shows `not present`.
#[tokio::test]
async fn set_registry_confirmation_shows_an_absent_old_value() {
    let harness = connected(Answer::Accept, &[]).await;
    harness
        .transport
        .respond("GetValueNames", r#"{"state":"absent","type":null}"#);
    harness
        .call(set_registry_call("HKLM:\\SOFTWARE\\MyApp", "New", "x"))
        .await;
    let message = harness.last_confirmation();
    assert!(message.contains("Old value: not present"), "{message}");
    harness.client.cancel().await.ok();
}

/// AC-SEC18-1: a read that failed for another reason (access denied) shows
/// `unknown`, not `not present`.
#[tokio::test]
async fn set_registry_confirmation_shows_unknown_for_a_failed_read() {
    let harness = connected(Answer::Accept, &[]).await;
    harness
        .transport
        .respond("GetValueNames", r#"{"state":"unknown","type":null}"#);
    harness
        .call(set_registry_call("HKLM:\\SOFTWARE\\MyApp", "New", "x"))
        .await;
    let message = harness.last_confirmation();
    assert!(message.contains("Old value: unknown"), "{message}");
    assert!(!message.contains("Old value: not present"), "{message}");
    harness.client.cancel().await.ok();
}

/// AC-SEC18-1: `write_file` names the path, the resolved path, the size and the
/// encoding, and shows the content only as `hidden`; the content itself is absent.
#[tokio::test]
async fn write_file_confirmation_hides_the_content() {
    let harness = connected(Answer::Accept, &[("WINRIG_ALLOW_FILE_WRITE", "true")]).await;
    harness.transport.respond(
        "GetUnresolvedProviderPathFromPSPath",
        r#"{"FullName":"C:\\App\\config.json","DotNetFullName":"C:\\App\\config.json","Exists":false,"Roots":{"SystemRoot":"C:\\Windows"}}"#,
    );
    let secret = "TOPSECRET";
    harness
        .call(write_file_call("C:\\App\\config.json", secret, false))
        .await;
    let message = harness.last_confirmation();
    assert_header(&message, "write_file");
    assert!(message.contains("Path: C:\\App\\config.json"), "{message}");
    assert!(
        message.contains("Resolved: C:\\App\\config.json"),
        "{message}"
    );
    assert!(message.contains("Bytes: 9"), "{message}");
    assert!(message.contains("Encoding: utf8"), "{message}");
    assert!(message.contains("Existing file: no"), "{message}");
    assert!(message.contains("Content: hidden"), "{message}");
    assert!(
        !message.contains(secret),
        "the content leaked into the prompt: {message}"
    );
    harness.client.cancel().await.ok();
}

/// AC-SEC17-1: the `write_file` effect line depends on the existence of the file.
#[tokio::test]
async fn write_file_effect_depends_on_existence() {
    let harness = connected(Answer::Accept, &[("WINRIG_ALLOW_FILE_WRITE", "true")]).await;
    harness.transport.respond(
        "GetUnresolvedProviderPathFromPSPath",
        r#"{"FullName":"C:\\App\\new.json","DotNetFullName":"C:\\App\\new.json","Exists":false,"Roots":{"SystemRoot":"C:\\Windows"}}"#,
    );
    harness
        .call(write_file_call("C:\\App\\new.json", "x", false))
        .await;
    let message = harness.last_confirmation();
    assert!(message.contains("Existing file: no"), "{message}");
    assert!(
        message.contains("This creates the file. To undo it, delete the file."),
        "{message}"
    );
    harness.client.cancel().await.ok();

    let harness = connected(Answer::Accept, &[("WINRIG_ALLOW_FILE_WRITE", "true")]).await;
    harness.transport.respond(
        "GetUnresolvedProviderPathFromPSPath",
        r#"{"FullName":"C:\\App\\old.json","DotNetFullName":"C:\\App\\old.json","Exists":true,"Roots":{"SystemRoot":"C:\\Windows"}}"#,
    );
    harness
        .call(write_file_call("C:\\App\\old.json", "x", true))
        .await;
    let message = harness.last_confirmation();
    assert!(message.contains("Existing file: yes"), "{message}");
    assert!(
        message.contains("This replaces the whole file. You cannot undo it"),
        "{message}"
    );
    harness.client.cancel().await.ok();
}

/// AC-SEC17-1: `delete_file` names the path, the resolved path, the size and the
/// modification time, and it states that the deletion is permanent.
#[tokio::test]
async fn delete_file_confirmation_shows_the_path_and_the_metadata() {
    let harness = connected(Answer::Accept, &[]).await;
    harness.transport.respond(
        "PSIsContainer",
        r#"{"FullName":"C:\\App\\old.log","IsDirectory":false,"SizeBytes":123,"Modified":"2026-01-01 00:00:00","Roots":{"SystemRoot":"C:\\Windows"}}"#,
    );
    harness.call(delete_file_call("C:\\App\\old.log")).await;
    let message = harness.last_confirmation();
    assert_header(&message, "delete_file");
    assert!(message.contains("Path: C:\\App\\old.log"), "{message}");
    assert!(message.contains("Resolved: C:\\App\\old.log"), "{message}");
    assert!(message.contains("Size: 123 bytes"), "{message}");
    assert!(
        message.contains("Modified: 2026-01-01 00:00:00"),
        "{message}"
    );
    assert!(
        message.contains("This deletes one file permanently. You cannot undo it."),
        "{message}"
    );
    harness.client.cancel().await.ok();
}

/// AC-SEC17-1: `delete_directory` names the path, the resolved path and the item
/// counts, and it states the second check of the reparse points after the
/// confirmation.
#[tokio::test]
async fn delete_directory_confirmation_shows_the_counts_and_the_reparse_check() {
    let harness = connected(Answer::Accept, &[]).await;
    harness.transport.respond(
        "IsReparsePoint",
        r#"{"FullName":"C:\\App\\logs","IsReparsePoint":false,"NestedReparsePoint":false,"FileCount":3,"DirCount":2,"TotalItems":5,"Roots":{"SystemRoot":"C:\\Windows"}}"#,
    );
    harness
        .call(
            CallToolRequestParams::new("delete_directory").with_arguments(args(
                &serde_json::json!({ "session_id": HOST, "path": "C:\\App\\logs" }),
            )),
        )
        .await;
    let message = harness.last_confirmation();
    assert_header(&message, "delete_directory");
    assert!(message.contains("Path: C:\\App\\logs"), "{message}");
    assert!(message.contains("Resolved: C:\\App\\logs"), "{message}");
    assert!(
        message.contains("Items: 3 files + 2 directories"),
        "{message}"
    );
    assert!(
        message.contains("reparse points again after the confirmation"),
        "{message}"
    );
    harness.client.cancel().await.ok();
}

/// AC-SEC17-2: `set_service_start_type` names the service, the current start type
/// and the new start type, and it names the host, the user and the tool.
#[tokio::test]
async fn set_service_start_type_confirmation_names_the_header() {
    let harness = connected(Answer::Accept, &[]).await;
    harness.transport.respond(
        "FailureActionsOnNonCrashFailures",
        r#"{"name":"Spooler","start_type":"Manual","status":"Stopped"}"#,
    );
    harness
        .call(set_start_type("Spooler", "AutomaticDelayed"))
        .await;
    let message = harness.last_confirmation();
    assert_header(&message, "set_service_start_type");
    assert!(message.contains("Service: Spooler"), "{message}");
    assert!(message.contains("Current start type: Manual"), "{message}");
    assert!(
        message.contains("New start type: AutomaticDelayed"),
        "{message}"
    );
    assert!(message.contains("set the start type again"), "{message}");
    harness.client.cancel().await.ok();
}

/// AC-SEC19-1: a long path is cut in the middle, so the tail stays visible and the
/// dialog structure stays intact.
#[tokio::test]
async fn a_long_path_keeps_its_tail_visible() {
    let harness = connected(Answer::Accept, &[]).await;
    let long = format!("C:\\App\\{}", "d".repeat(300));
    harness.transport.respond(
        "PSIsContainer",
        &format!(
            r#"{{"FullName":"{}","IsDirectory":false,"SizeBytes":1,"Modified":"2026-01-01 00:00:00","Roots":{{"SystemRoot":"C:\\Windows"}}}}"#,
            long.replace('\\', "\\\\")
        ),
    );
    harness.call(delete_file_call("C:\\App\\x.log")).await;
    let message = harness.last_confirmation();
    assert_header(&message, "delete_file");
    assert!(message.contains("Path: C:\\App\\x.log"), "{message}");
    let resolved = message
        .lines()
        .find(|line| line.starts_with("Resolved: "))
        .expect("a resolved line");
    let value = resolved.trim_start_matches("Resolved: ");
    assert_eq!(value.chars().count(), 200, "the field must sit at the cap");
    assert!(value.contains("..."), "the cut carries the marker: {value}");
    assert!(
        value.ends_with(&"d".repeat(40)),
        "the last 40 characters must stay visible: {value}"
    );
    harness.client.cancel().await.ok();
}

/// AC-SEC19-1: a line break inside a field collapses to a space, so the value
/// cannot forge its own dialog line.
#[tokio::test]
async fn a_line_break_in_a_field_does_not_forge_a_line() {
    let harness = connected(Answer::Accept, &[]).await;
    harness
        .transport
        .respond("GetValueNames", r#"{"state":"absent","type":null}"#);
    harness
        .call(set_registry_call(
            "HKLM:\\SOFTWARE\\a\nNew value: evil",
            "v",
            "x",
        ))
        .await;
    let message = harness.last_confirmation();
    assert_header(&message, "set_registry");
    let forged = message
        .lines()
        .filter(|line| *line == "New value: evil")
        .count();
    assert_eq!(forged, 0, "the injected text forged a line: {message}");
    assert_eq!(
        message.matches("New value: hidden").count(),
        1,
        "the genuine hidden marker must stay the only one: {message}"
    );
    harness.client.cancel().await.ok();
}

/// AC-SEC16-1: the host of the prompt is the session host, without the port of a
/// non-default session.
#[tokio::test]
async fn confirmation_host_is_the_session_host_without_the_port() {
    let harness = started(Answer::Accept, &[]).await;
    let connect = harness
        .call(
            CallToolRequestParams::new("connect").with_arguments(args(&serde_json::json!({
                "host": HOST,
                "port": 5986
            }))),
        )
        .await;
    assert_eq!(
        status_of(&connect).as_deref(),
        Some("connected"),
        "{:?}",
        connect.structured_content
    );
    let result = harness
        .call(
            CallToolRequestParams::new("flush_dns").with_arguments(args(&serde_json::json!({
                "session_id": "host1:5986"
            }))),
        )
        .await;
    assert_eq!(error_of(&result), None, "{:?}", result.structured_content);
    let message = harness.last_confirmation();
    assert!(message.contains(&format!("Host: {HOST}\n")), "{message}");
    assert!(!message.contains("Host: host1:5986"), "{message}");
    harness.client.cancel().await.ok();
}

/// DR-5: a call without an open session is refused before the prompt, with the same
/// error `run_ps` gives.
#[tokio::test]
async fn unknown_session_is_refused_before_the_prompt() {
    let harness = started(Answer::Accept, &[]).await;
    let result = harness
        .call(
            CallToolRequestParams::new("flush_dns").with_arguments(args(&serde_json::json!({
                "session_id": "nope"
            }))),
        )
        .await;
    assert_eq!(
        harness.elicitations(),
        0,
        "the server asked about an unknown session"
    );
    assert!(
        error_of(&result).is_some_and(|error| error.contains("Session not found: nope")),
        "{:?}",
        result.structured_content
    );
    harness.client.cancel().await.ok();
}

// ---------------------------------------------------------------------------
// run_command
// ---------------------------------------------------------------------------

/// A call to `run_command` in an open session.
fn run_command_call(command: &str) -> CallToolRequestParams {
    CallToolRequestParams::new("run_command").with_arguments(args(&serde_json::json!({
        "session_id": HOST,
        "command": command
    })))
}

/// Returns what the server advertises over the MCP channel.
async fn tool_names(harness: &Harness) -> Vec<String> {
    harness
        .client
        .list_tools(None)
        .await
        .expect("tools/list")
        .tools
        .iter()
        .map(|tool| tool.name.to_string())
        .collect()
}

/// The base64 of the UTF-16LE form of `text`, as the `run_command` wrapper
/// carries it.
fn utf16_base64(text: &str) -> String {
    let mut bytes = Vec::new();
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    winrig::ps::encode_base64(&bytes)
}

/// TR-EXE-01, AC-EXE-01: `run_command` is absent by default and appears when the
/// operator enables it.
#[tokio::test]
async fn run_command_appears_only_when_enabled() {
    let off = started(Answer::Accept, &[]).await;
    assert!(
        !tool_names(&off)
            .await
            .iter()
            .any(|name| name == "run_command"),
        "run_command must not be advertised while disabled"
    );
    off.client.cancel().await.ok();

    let on = started(Answer::Accept, &[("WINRIG_ALLOW_COMMAND_EXEC", "true")]).await;
    assert!(
        tool_names(&on)
            .await
            .iter()
            .any(|name| name == "run_command"),
        "run_command must appear once enabled"
    );
    on.client.cancel().await.ok();
}

/// TR-EXE-03, AC-EXE-03: without a confirmation channel the command is refused
/// and never reaches the host (DR-5, fail-closed).
#[tokio::test]
async fn run_command_without_channel_is_refused() {
    let harness = connected(Answer::NoChannel, &[("WINRIG_ALLOW_COMMAND_EXEC", "true")]).await;
    let result = harness.call(run_command_call("Get-Service")).await;

    assert!(
        !harness.transport.saw("[ScriptBlock]::Create"),
        "the command ran without a confirmation channel"
    );
    assert_eq!(
        harness.elicitations(),
        0,
        "the server asked a client that never declared elicitation"
    );
    assert!(
        error_of(&result).is_some_and(|error| error.contains("cannot ask for confirmation")),
        "{:?}",
        result.structured_content
    );
    // TR-EXE-03: the refusal points to the documentation section, and it never
    // tells the agent to set the fallback itself.
    let error = error_of(&result).expect("an error");
    assert!(error.contains("documentation"), "{error}");
    assert!(!error.contains("WINRIG_CONFIRM_FALLBACK"), "{error}");
    harness.client.cancel().await.ok();
}

/// TR-SEC-11, AC-EXE-03: with `WINRIG_CONFIRM_FALLBACK=proceed` a client without
/// elicitation runs the command, and the audit marks the absent confirmation.
#[tokio::test]
async fn run_command_runs_with_proceed_and_no_channel() {
    let buffer = capture();
    let harness = connected(
        Answer::NoChannel,
        &[
            ("WINRIG_ALLOW_COMMAND_EXEC", "true"),
            ("WINRIG_CONFIRM_FALLBACK", "proceed"),
        ],
    )
    .await;
    let result = harness.call(run_command_call("Get-Service")).await;

    assert!(
        harness.transport.saw("[ScriptBlock]::Create"),
        "the command did not run under proceed"
    );
    assert_eq!(
        number(&result, "status_code"),
        Some(0),
        "{:?}",
        result.structured_content
    );
    harness.client.cancel().await.ok();

    let text = take_audit(&buffer);
    assert!(
        text.contains("CONFIRMATION UNSUPPORTED") && text.contains("unsupported"),
        "the fallback run is not marked in the audit: {text}"
    );
    // ADR-0013 §22: the event names the session and the host of the fallback run.
    assert!(
        text.contains("session") && text.contains("host") && text.contains(HOST),
        "the fallback event must carry the session and the host: {text}"
    );
}

/// TR-SEC-11: `proceed` never bypasses a failure of the channel itself, where the
/// state of the channel is unknown.
#[tokio::test]
async fn proceed_does_not_bypass_a_channel_error() {
    let harness = connected(
        Answer::Error,
        &[
            ("WINRIG_ALLOW_COMMAND_EXEC", "true"),
            ("WINRIG_CONFIRM_FALLBACK", "proceed"),
        ],
    )
    .await;
    let result = harness.call(run_command_call("Get-Service")).await;

    assert!(
        !harness.transport.saw("[ScriptBlock]::Create"),
        "a command ran after a channel error"
    );
    assert!(
        error_of(&result).is_some(),
        "{:?}",
        result.structured_content
    );
    harness.client.cancel().await.ok();
}

/// TR-SEC-11: `proceed` never bypasses a refusal of the user.
#[tokio::test]
async fn proceed_does_not_bypass_a_user_decline() {
    let harness = connected(
        Answer::Decline,
        &[
            ("WINRIG_ALLOW_COMMAND_EXEC", "true"),
            ("WINRIG_CONFIRM_FALLBACK", "proceed"),
        ],
    )
    .await;
    let result = harness.call(run_command_call("Get-Service")).await;

    assert!(
        !harness.transport.saw("[ScriptBlock]::Create"),
        "a declined command still ran"
    );
    assert_eq!(status_of(&result).as_deref(), Some("cancelled"));
    harness.client.cancel().await.ok();
}

/// TR-SEC-11, TR-REL-08: `proceed` never bypasses a timeout.
#[tokio::test]
async fn proceed_does_not_bypass_a_timeout() {
    let harness = connected(
        Answer::Silent,
        &[
            ("WINRIG_ALLOW_COMMAND_EXEC", "true"),
            ("WINRIG_CONFIRM_FALLBACK", "proceed"),
            ("WINRIG_CONFIRM_TIMEOUT_SECONDS", "1"),
        ],
    )
    .await;
    let result = harness.call(run_command_call("Get-Service")).await;

    assert!(
        !harness.transport.saw("[ScriptBlock]::Create"),
        "a command ran after the confirmation timed out"
    );
    assert_eq!(status_of(&result).as_deref(), Some("timeout"));
    harness.client.cancel().await.ok();
}

/// TR-EXE-02, AC-EXE-02: a command that the list does not cover is refused
/// before the network.
#[tokio::test]
async fn command_outside_the_allowlist_is_refused_before_the_network() {
    let harness = connected(
        Answer::Accept,
        &[
            ("WINRIG_ALLOW_COMMAND_EXEC", "true"),
            ("WINRIG_ALLOWED_COMMANDS", "Get-Service"),
        ],
    )
    .await;
    let before = harness.transport.calls.lock().expect("lock").len();
    let result = harness
        .call(run_command_call("Remove-Item C:\\ -Recurse"))
        .await;

    assert!(
        error_of(&result).is_some(),
        "{:?}",
        result.structured_content
    );
    assert_eq!(
        harness.transport.calls.lock().expect("lock").len(),
        before,
        "the refused command reached the host"
    );
    harness.client.cancel().await.ok();
}

/// TR-EXE-04, TR-SEC-22, AC-EXE-04, AC-SEC22-1: the confirmation shows the full
/// command text, without the 200-character cap.
#[tokio::test]
async fn run_command_confirmation_shows_the_full_text() {
    let harness = connected(Answer::Accept, &[("WINRIG_ALLOW_COMMAND_EXEC", "true")]).await;
    let command = format!(
        "Get-ChildItem C:\\Logs | Where-Object {{ $_.Length -gt 0 }} # {}",
        "x".repeat(300)
    );
    harness.call(run_command_call(&command)).await;
    let message = harness.last_confirmation();

    assert_header(&message, "run_command");
    assert!(
        message.contains(&format!("Command:\n  | {command}")),
        "the full command must appear: {message}"
    );
    assert!(
        !message.contains("..."),
        "the body must not be cut: {message}"
    );
    harness.client.cancel().await.ok();
}

/// AC-SEC21-1: a new modifying tool of ADR-0017 names the host, the identity and
/// the tool, and carries the plain effect line.
#[tokio::test]
async fn new_tool_confirmations_hold_the_w32_fields() {
    let harness = connected(Answer::Accept, &[("WINRIG_ALLOW_COMMAND_EXEC", "true")]).await;
    harness.call(run_command_call("Get-Service")).await;
    let message = harness.last_confirmation();

    assert_header(&message, "run_command");
    assert!(message.contains("Command:\n  | Get-Service"), "{message}");
    assert!(
        message
            .contains("This runs an arbitrary PowerShell command on the host. You cannot undo it."),
        "{message}"
    );
    harness.client.cancel().await.ok();
}

/// DR-4, ADR-0013 §3–4: the audit holds the command text the operator confirmed,
/// not its reversible base64 wrapper.
#[tokio::test]
async fn run_command_does_not_leak_the_encoded_command_to_the_audit() {
    let buffer = capture();
    let harness = connected(Answer::Accept, &[("WINRIG_ALLOW_COMMAND_EXEC", "true")]).await;
    harness.call(run_command_call("Get-Service")).await;
    harness.client.cancel().await.ok();

    let text = take_audit(&buffer);
    assert!(
        text.contains("Get-Service"),
        "the audit must hold the command text: {text}"
    );
    assert!(
        !text.contains(&utf16_base64("Get-Service")),
        "the encoded command leaked into the audit: {text}"
    );
}

/// DR-4: a secret in the command stays masked in the audit, because the session
/// password is always redacted (TR-SEC-02).
#[tokio::test]
async fn run_command_masks_a_secret_in_the_audit() {
    let buffer = capture();
    let harness = connected(Answer::Accept, &[("WINRIG_ALLOW_COMMAND_EXEC", "true")]).await;
    harness
        .call(run_command_call("Write-Output 's3cret'"))
        .await;
    harness.client.cancel().await.ok();

    let text = take_audit(&buffer);
    assert!(
        !text.contains("s3cret"),
        "the secret leaked into the audit: {text}"
    );
    assert!(
        text.contains("***"),
        "the audit must mask the secret: {text}"
    );
}

/// TR-EXE-02, AC-EXE-02: a command inside the allowlist reaches the host through
/// the real handler as the encoded ScriptBlock wrapper.
#[tokio::test]
async fn allowed_command_through_the_handler_reaches_the_transport() {
    let harness = connected(
        Answer::Accept,
        &[
            ("WINRIG_ALLOW_COMMAND_EXEC", "true"),
            ("WINRIG_ALLOWED_COMMANDS", "Get-Service"),
        ],
    )
    .await;
    let result = harness
        .call(run_command_call("Get-Service -Name Spooler"))
        .await;

    assert_eq!(error_of(&result), None, "{:?}", result.structured_content);
    assert!(
        harness.transport.saw("[ScriptBlock]::Create"),
        "the allowed command never reached the host"
    );
    harness.client.cancel().await.ok();
}

/// TR-SEC-11: `proceed` refuses a client that declared elicitation in URL mode
/// only, because it has a channel the server cannot use for a form.
#[tokio::test]
async fn proceed_refuses_a_url_only_elicitation_client() {
    let harness = connected(
        Answer::UrlOnly,
        &[
            ("WINRIG_ALLOW_COMMAND_EXEC", "true"),
            ("WINRIG_CONFIRM_FALLBACK", "proceed"),
        ],
    )
    .await;
    let result = harness.call(run_command_call("Get-Service")).await;

    assert!(
        !harness.transport.saw("[ScriptBlock]::Create"),
        "a url-only client ran a command"
    );
    assert!(
        error_of(&result).is_some(),
        "{:?}",
        result.structured_content
    );
    harness.client.cancel().await.ok();
}

/// TR-EXE-04: a command above the limit is refused before the network, and the
/// refusal reaches the audit through `audit_refusal`.
#[tokio::test]
async fn command_above_the_limit_is_audited_as_a_policy_refusal() {
    let buffer = capture();
    let harness = connected(Answer::Accept, &[("WINRIG_ALLOW_COMMAND_EXEC", "true")]).await;
    let before = harness.transport.calls.lock().expect("lock").len();
    let result = harness.call(run_command_call(&"a".repeat(1000))).await;

    assert!(
        error_of(&result).is_some_and(|error| error.contains("UTF-16 units")),
        "{:?}",
        result.structured_content
    );
    assert_eq!(
        harness.transport.calls.lock().expect("lock").len(),
        before,
        "the over-long command reached the host"
    );
    harness.client.cancel().await.ok();

    let text = take_audit(&buffer);
    assert!(
        text.contains("POLICY REFUSED") && text.contains("COMMAND_TOO_LONG"),
        "the length refusal is not audited: {text}"
    );
}

/// TR-SEC-11, ADR-0013 §21: `proceed` lifts fail-closed for every modifying tool,
/// deletion included, and the audit marks the run.
#[tokio::test]
async fn proceed_runs_a_deleting_tool_and_marks_the_audit() {
    let buffer = capture();
    let harness = connected(Answer::NoChannel, &[("WINRIG_CONFIRM_FALLBACK", "proceed")]).await;
    harness.transport.respond(
        "PSIsContainer",
        r#"{"FullName":"C:\\App\\old.log","IsDirectory":false,"SizeBytes":123,"Modified":"2026-01-01 00:00:00","Roots":{"SystemRoot":"C:\\Windows"}}"#,
    );
    let result = harness.call(delete_file_call("C:\\App\\old.log")).await;

    assert_eq!(error_of(&result), None, "{:?}", result.structured_content);
    assert!(
        harness.transport.saw("Remove-Item -LiteralPath"),
        "the deletion did not run under proceed"
    );
    harness.client.cancel().await.ok();

    let text = take_audit(&buffer);
    assert!(
        text.contains("CONFIRMATION UNSUPPORTED"),
        "the fallback deletion is not marked in the audit: {text}"
    );
}

// ---------------------------------------------------------------------------
// run_script
// ---------------------------------------------------------------------------

/// One `run_script` call in an open session.
fn run_script_call(script: &str) -> CallToolRequestParams {
    CallToolRequestParams::new("run_script").with_arguments(args(&serde_json::json!({
        "session_id": HOST,
        "script": script
    })))
}

/// The staging directory the fake host reports for the temp-directory probe.
const STAGING_DIR: &str = "C:\\Windows\\Temp";

/// Makes the fake host answer the temp-directory probe with the requested
/// `winrig-<suffix>.ps1` name and answer the staging cleanup, so the staging path
/// and the cleanup outcome are deterministic.
fn arm_staging(harness: &Harness) {
    *harness.transport.staging_dir.lock().expect("lock") = Some(STAGING_DIR.to_owned());
    harness
        .transport
        .respond("Test-Path -LiteralPath", "removed");
}

/// TR-EXE-05, AC-EXE-05: `run_script` is absent by default and appears when the
/// operator enables it.
#[tokio::test]
async fn run_script_appears_only_when_enabled() {
    let off = started(Answer::Accept, &[]).await;
    assert!(
        !tool_names(&off)
            .await
            .iter()
            .any(|name| name == "run_script"),
        "run_script must not be advertised while disabled"
    );
    off.client.cancel().await.ok();

    let on = started(Answer::Accept, &[("WINRIG_ALLOW_SCRIPT_EXEC", "true")]).await;
    assert!(
        tool_names(&on)
            .await
            .iter()
            .any(|name| name == "run_script"),
        "run_script must appear once enabled"
    );
    on.client.cancel().await.ok();
}

/// TR-EXE-05, AC-EXE-05: the prefix list `WINRIG_ALLOWED_COMMANDS` does not
/// filter a script, so a script whose text is not in the list still reaches the
/// host.
#[tokio::test]
async fn run_script_ignores_the_command_allowlist() {
    let harness = connected(
        Answer::Accept,
        &[
            ("WINRIG_ALLOW_SCRIPT_EXEC", "true"),
            ("WINRIG_ALLOWED_COMMANDS", "Get-Service"),
        ],
    )
    .await;
    arm_staging(&harness);
    let result = harness
        .call(run_script_call("whoami; Write-Output 'not in the list'"))
        .await;

    assert_eq!(error_of(&result), None, "{:?}", result.structured_content);
    assert!(
        harness.transport.saw("FromBase64String"),
        "the script never reached the host: the allowlist must not filter it"
    );
    harness.client.cancel().await.ok();
}

/// DR-5, TR-EXE-06: without a confirmation channel nothing modifying reaches the
/// host and the tool refuses (fail-closed).
#[tokio::test]
async fn run_script_without_channel_is_refused() {
    let harness = connected(Answer::NoChannel, &[("WINRIG_ALLOW_SCRIPT_EXEC", "true")]).await;
    arm_staging(&harness);
    let result = harness
        .call(run_script_call("Remove-Item C:\\ -Recurse"))
        .await;

    for needle in ["FromBase64String", "[ScriptBlock]::Create", "Remove-Item"] {
        assert!(
            !harness.transport.saw(needle),
            "a modifying command ({needle}) reached the host without a confirmation"
        );
    }
    assert!(
        error_of(&result).is_some_and(|error| error.contains("cannot ask for confirmation")),
        "{:?}",
        result.structured_content
    );
    harness.client.cancel().await.ok();
}

/// TR-EXE-06, AC-EXE-06: a confirmed `run_script` uploads the staging file in
/// chunks, verifies and runs it as a script block and removes it, in that order,
/// and the result carries the cleanup outcome.
#[tokio::test]
async fn run_script_writes_runs_and_deletes_the_temp_file() {
    let harness = connected(Answer::Accept, &[("WINRIG_ALLOW_SCRIPT_EXEC", "true")]).await;
    arm_staging(&harness);
    let before = harness.transport.calls.lock().expect("lock").len();
    let result = harness
        .call(run_script_call("Write-Output 'hi'; Get-Service"))
        .await;

    assert_eq!(error_of(&result), None, "{:?}", result.structured_content);
    assert_eq!(number(&result, "status_code"), Some(0), "{:?}", result);
    assert_eq!(field(&result, "temp_file").as_deref(), Some("removed"));
    assert_eq!(field(&result, "warning"), None);

    let calls = calls_from(&harness, before);
    let chunk = calls.iter().position(|c| c.contains("FromBase64String"));
    let run_at = calls
        .iter()
        .position(|c| c.contains("[ScriptBlock]::Create"));
    let delete = calls
        .iter()
        .position(|c| c.contains("Remove-Item") && c.contains(STAGING_DIR));
    assert!(chunk.is_some(), "the chunk write is missing: {calls:?}");
    assert!(run_at.is_some(), "the run is missing: {calls:?}");
    assert!(delete.is_some(), "the delete is missing: {calls:?}");
    assert!(
        chunk < run_at && run_at < delete,
        "the order must be write, run, delete: {calls:?}"
    );
    harness.client.cancel().await.ok();
}

/// TR-EXE-07, TR-SEC-22, AC-EXE-07, AC-SEC22-1: one confirmation shows the whole
/// script, line by line and without the 200-character cap, and it names the
/// staging path.
#[tokio::test]
async fn run_script_confirmation_shows_the_whole_script() {
    let harness = connected(Answer::Accept, &[("WINRIG_ALLOW_SCRIPT_EXEC", "true")]).await;
    arm_staging(&harness);
    let long_line = format!("Get-ChildItem C:\\Logs # {}", "x".repeat(300));
    let script = format!("$a = 1\n$b = 2\n{long_line}");
    let result = harness.call(run_script_call(&script)).await;
    let message = harness.last_confirmation();

    assert_eq!(
        harness.elicitations(),
        1,
        "run_script must ask one confirmation"
    );
    assert_header(&message, "run_script");
    assert!(
        message.contains(&format!("Temporary path: {STAGING_DIR}\\winrig-")),
        "{message}"
    );
    assert!(message.contains("SHA-256: "), "{message}");
    assert!(
        message.contains("Command allowlist: does not filter a script"),
        "{message}"
    );
    assert!(message.contains("Script:\n  | $a = 1"), "{message}");
    assert!(
        message.contains(&format!("  | {long_line}")),
        "the whole script must appear: {message}"
    );
    assert!(
        !message.contains("..."),
        "the body must not be cut: {message}"
    );
    assert!(
        message.contains(
            "This uploads and runs an arbitrary PowerShell script, then tries to delete the file. \
             You cannot undo it."
        ),
        "{message}"
    );
    assert_eq!(error_of(&result), None, "{:?}", result.structured_content);
    harness.client.cancel().await.ok();
}

/// TR-EXE-06: a probe that returns an unexpected path is refused before the
/// confirmation, and nothing is written.
#[tokio::test]
async fn run_script_refuses_an_unexpected_staging_path() {
    let harness = connected(Answer::Accept, &[("WINRIG_ALLOW_SCRIPT_EXEC", "true")]).await;
    // The host returns a system file, not the requested `winrig-<suffix>.ps1`.
    harness
        .transport
        .respond("[IO.Path]::Combine", "C:\\Windows\\System32\\x.ps1");
    let result = harness.call(run_script_call("Write-Output 1")).await;

    assert_eq!(
        harness.elicitations(),
        0,
        "the tool must refuse before the confirmation"
    );
    assert!(
        !harness.transport.saw("FromBase64String"),
        "nothing must be written"
    );
    assert!(
        error_of(&result).is_some_and(|error| error.contains("unexpected staging path")),
        "{:?}",
        result.structured_content
    );
    harness.client.cancel().await.ok();
}

/// DR-5, TR-EXE-06: a declined confirmation writes nothing to the host.
#[tokio::test]
async fn run_script_decline_writes_nothing() {
    let harness = connected(Answer::Decline, &[("WINRIG_ALLOW_SCRIPT_EXEC", "true")]).await;
    arm_staging(&harness);
    let result = harness.call(run_script_call("Write-Output 1")).await;

    for needle in ["FromBase64String", "[ScriptBlock]::Create", "Remove-Item"] {
        assert!(
            !harness.transport.saw(needle),
            "a declined call still wrote ({needle})"
        );
    }
    assert_eq!(
        status_of(&result).as_deref(),
        Some("cancelled"),
        "{result:?}"
    );
    harness.client.cancel().await.ok();
}

/// DR-4: the audit holds the script text, indented, and the confirmed SHA-256, and
/// no chunk base64 reaches any record.
#[tokio::test]
async fn run_script_audit_holds_the_script_and_the_hash() {
    let buffer = capture();
    let harness = connected(Answer::Accept, &[("WINRIG_ALLOW_SCRIPT_EXEC", "true")]).await;
    arm_staging(&harness);
    let script = "Write-Output 'audit-line'";
    harness.call(run_script_call(script)).await;
    harness.client.cancel().await.ok();

    let text = take_audit(&buffer);
    assert!(
        text.contains("Write-Output 'audit-line'"),
        "the script text must be in the audit: {text}"
    );
    let hash = winrig::ps::script_sha256(script);
    assert!(text.contains(&hash), "the hash must be recorded: {text}");
    let base64 = winrig::ps::encode_base64(script.as_bytes());
    assert!(
        !text.contains(&base64),
        "the chunk base64 leaked into the audit: {text}"
    );
}
