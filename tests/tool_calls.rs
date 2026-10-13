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
    ElicitResult, ElicitationAction, ErrorData as McpError, JsonObject,
};
use rmcp::service::{RequestContext, RoleClient, RunningService};
use winrig::config::{AppConfig, load_config_from};
use winrig::identity::ProfileIdentity;
use winrig::server::WinrigServer;
use winrig::session::{
    RegistryConfig, RemoteOutput, SessionRegistry, SessionTarget, TransportError, WinRmTransport,
};

const HOST: &str = "host1";
const USER: &str = "domain\\alice";
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
}

#[async_trait::async_trait]
impl WinRmTransport for RecordingTransport {
    async fn run_powershell(
        &self,
        _target: &SessionTarget,
        script: &str,
    ) -> Result<RemoteOutput, TransportError> {
        self.calls.lock().expect("lock").push(script.to_owned());
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
        }
    }

    fn get_info(&self) -> ClientConfig {
        let mut info = ClientConfig::default();
        info.capabilities = if self.answer == Answer::NoChannel {
            ClientCapabilities::default()
        } else {
            ClientCapabilities::builder().enable_elicitation().build()
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
