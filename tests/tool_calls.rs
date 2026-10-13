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
}

#[async_trait::async_trait]
impl WinRmTransport for RecordingTransport {
    async fn run_powershell(
        &self,
        _target: &SessionTarget,
        script: &str,
    ) -> Result<RemoteOutput, TransportError> {
        self.calls.lock().expect("lock").push(script.to_owned());
        Ok(RemoteOutput {
            stdout: HOST_STDOUT.as_bytes().to_vec(),
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
}

/// How the test client replies to a confirmation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// User agreed.
    Accept,
    /// Operator refused.
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
}

impl ClientHandler for TestClient {
    async fn create_elicitation(
        &self,
        _params: ElicitRequestParams,
        _context: RequestContext<RoleClient>,
    ) -> Result<ElicitResult, McpError> {
        self.elicitations.fetch_add(1, Ordering::SeqCst);
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
}

impl Harness {
    /// How many times the server asked for confirmation.
    fn elicitations(&self) -> usize {
        self.elicitations.load(Ordering::SeqCst)
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
    let client = TestClient {
        answer,
        elicitations: Arc::clone(&elicitations),
    }
    .serve(client_side)
    .await
    .expect("client handshake");

    Harness {
        client,
        transport,
        elicitations,
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
    // "Nobody to ask", not "asked and timed out": the substring "was not
    // performed" also appears in the timeout message.
    assert!(
        error_of(&result).is_some_and(|error| error.contains("Cannot ask for confirmation")),
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
