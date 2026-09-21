//! Вызовы инструментов через настоящий MCP-канал и канал подтверждения (DR-5).
//!
//! Unit-тесты сервера зовут функции напрямую и поэтому не касаются
//! `WinrigServer::confirm`: elicitation существует только между двумя peer'ами.
//! Здесь клиент и сервер соединены парой транспортов в памяти
//! (`tokio::io::duplex`), Windows-хост заменён записывающим транспортом
//! (AGENTS.md §4), а ветка подтверждения задаётся ответом клиента.
//!
//! Проверяется не только текст ответа инструмента, но и то, дошла ли команда до
//! транспорта: отказ обязан быть fail-closed, а не «ответили cancelled и всё же
//! выполнили».

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
/// Подпись модифицирующей команды `flush_dns` в скрипте, ушедшем на хост.
const MUTATION: &str = "Clear-DnsClientCache";
/// Ровно то, что фиктивный хост печатает на любую команду.
const HOST_STDOUT: &str = "HOST1|Windows|10.0|2026-01-01 00:00:00";

/// Фиктивный Windows-хост: запоминает каждый полученный скрипт.
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
    /// Истина, если хотя бы один скрипт содержит подстроку.
    fn saw(&self, needle: &str) -> bool {
        self.calls
            .lock()
            .expect("lock")
            .iter()
            .any(|call| call.contains(needle))
    }
}

/// Как тестовый клиент отвечает на запрос подтверждения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// Пользователь согласился.
    Accept,
    /// Пользователь отказался.
    Decline,
    /// Пользователь не отвечает никогда — решение остаётся за таймаутом сервера.
    Silent,
    /// Клиент не объявляет elicitation: канала подтверждения нет.
    NoChannel,
}

/// Клиент MCP, чья единственная задача — отвечать на подтверждение заданным
/// образом и считать, сколько раз его об этом попросили.
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
            // Молчание — не ошибка протокола, а неотвечающий оператор: ответ не
            // приходит вовсе.
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

/// Конфигурация с общим секретом и необязательными переопределениями.
fn config(overrides: &[(&str, &str)]) -> AppConfig {
    let owned: Vec<(String, String)> = overrides
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect();
    // `Env` не несёт времени жизни, поэтому замыкание обязано владеть данными.
    let lookup: Box<winrig::config::Env> = Box::new(move |name: &str| {
        if name == "WINRIG_AUTH_TOKEN" {
            return Some("token".to_owned());
        }
        owned
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    });
    load_config_from(lookup.as_ref()).expect("config")
}

/// Связка клиент — сервер — фиктивный хост для одного теста.
struct Harness {
    client: RunningService<RoleClient, TestClient>,
    transport: Arc<RecordingTransport>,
    elicitations: Arc<AtomicUsize>,
}

impl Harness {
    /// Сколько раз сервер запросил подтверждение.
    fn elicitations(&self) -> usize {
        self.elicitations.load(Ordering::SeqCst)
    }

    async fn call(&self, params: CallToolRequestParams) -> CallToolResult {
        self.client.call_tool(params).await.expect("tool call")
    }
}

/// Поднимает сервер и клиента на паре транспортов в памяти и открывает сессию.
///
/// Идентичность берётся из профиля, как в stdio: HTTP-заголовков здесь нет, а
/// проверяется слой инструментов, а не гейт (его закрывает `http_gate.rs`).
async fn connected(answer: Answer, overrides: &[(&str, &str)]) -> Harness {
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

    let harness = Harness {
        client,
        transport,
        elicitations,
    };
    let connect = harness
        .call(
            CallToolRequestParams::new("connect").with_arguments(args(&serde_json::json!({
                "host": HOST
            }))),
        )
        .await;
    assert_eq!(
        status_of(&connect).as_deref(),
        Some("connected"),
        "connect must succeed before the tool under test: {:?}",
        connect.structured_content
    );
    harness
}

/// Превращает JSON-объект в аргументы вызова инструмента.
fn args(value: &serde_json::Value) -> JsonObject {
    value.as_object().cloned().expect("object arguments")
}

/// Значение строкового поля структурированного ответа инструмента.
fn field(result: &CallToolResult, name: &str) -> Option<String> {
    result
        .structured_content
        .as_ref()?
        .get(name)?
        .as_str()
        .map(str::to_owned)
}

/// Значение числового поля структурированного ответа инструмента.
fn number(result: &CallToolResult, name: &str) -> Option<i64> {
    result.structured_content.as_ref()?.get(name)?.as_i64()
}

fn status_of(result: &CallToolResult) -> Option<String> {
    field(result, "status")
}

fn error_of(result: &CallToolResult) -> Option<String> {
    field(result, "error")
}

/// Вызов модифицирующего `flush_dns` в уже открытой сессии.
fn flush_dns() -> CallToolRequestParams {
    CallToolRequestParams::new("flush_dns").with_arguments(args(&serde_json::json!({
        "session_id": HOST
    })))
}

/// AC-REL09-4: чтение не спрашивает подтверждения и доходит до хоста.
///
/// Клиент объявляет elicitation и готов ответить Accept, поэтому «не спросили» —
/// утверждение о сервере, а не о неспособности клиента ответить.
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

/// AC-REL09-1: подтверждённая модификация выполняется.
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
    // Положительный признак: ответ — это результат исполнения на хосте.
    // Конверт отказа таких полей не несёт вовсе, поэтому «нет поля status»
    // проверять незачем.
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

/// AC-REL09-2: отказ оператора не выполняет команду (DR-5).
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

/// AC-REL09-3: без канала подтверждения модификация отказывает (fail-closed).
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
    // Именно «спросить некого», а не «спросили и не дождались»: подстрока
    // «was not performed» есть и в сообщении таймаута.
    assert!(
        error_of(&result).is_some_and(|error| error.contains("Cannot ask for confirmation")),
        "a client without elicitation must be refused for the absent channel: {:?}",
        result.structured_content
    );
    harness.client.cancel().await.ok();
}

/// AC-REL08-1: молчание оператора — отказ по таймауту, а не выполнение.
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
