//! Integration checks of the HTTP gate `/mcp`: the auth middleware in a real
//! axum + rmcp wiring, without network and without a Windows host (AGENTS.md §4).
//!
//! This closes a gap the unit tests cannot see: the middleware really stands in
//! front of the MCP service, and without a secret a request never reaches the tools
//! (DR-1). A second block checks the profile-token path: a request without
//! `X-AD-User` reaches the service, and the `X-AD-*` headers are ignored
//! (ADR-0009 §4, AC-PRF-06/49/51/52/53).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use tower::ServiceExt;
use winrig::auth::{AuthState, BoundProfile, auth_middleware};
use winrig::config::load_config_from;
use winrig::profile;
use winrig::server::WinrigServer;
use winrig::session::{RegistryConfig, SessionRegistry, WinrmTransportImpl};

const TOKEN: &str = "test-shared-secret";

fn base_config() -> Arc<winrig::config::AppConfig> {
    Arc::new(
        load_config_from(&|name| (name == "WINRIG_AUTH_TOKEN").then(|| TOKEN.to_owned()))
            .expect("config"),
    )
}

fn registry() -> Arc<SessionRegistry> {
    Arc::new(SessionRegistry::new(
        Arc::new(WinrmTransportImpl),
        RegistryConfig::default(),
    ))
}

fn router_with(state: AuthState) -> axum::Router {
    let config = base_config();
    let server = WinrigServer::new(registry(), Arc::clone(&config));
    let mcp = StreamableHttpService::new(
        move || Ok(server.clone()),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default().with_sse_keep_alive(None),
    );
    axum::Router::new()
        .nest_service("/mcp", mcp)
        .layer(axum::middleware::from_fn_with_state(state, auth_middleware))
}

fn header_only_state() -> AuthState {
    AuthState {
        mcp_auth_token: Some(Arc::new(TOKEN.to_owned())),
        profile: None,
    }
}

/// A profile in a temporary directory; returns the state and the token.
fn temp_profile_state(name: &str) -> (AuthState, std::path::PathBuf, String) {
    let dir = std::env::temp_dir().join(format!(
        "winrig-gate-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("corp.json");
    let token = profile::create(&path, "corp", "domain\\alice", "s3cret", false).expect("profile");
    let bound = BoundProfile::bind(path.clone(), &token).expect("bind");
    (
        AuthState {
            mcp_auth_token: Some(Arc::new(TOKEN.to_owned())),
            profile: Some(Arc::new(bound)),
        },
        dir,
        token,
    )
}

fn initialize_request() -> Request<Body> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": { "name": "winrig-test", "version": "0.0.0" }
        }
    });
    Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header(header::HOST, "localhost")
        .body(Body::from(body.to_string()))
        .expect("request")
}

async fn status_with(router: axum::Router, headers: &[(&'static str, &str)]) -> StatusCode {
    reply_with(router, headers).await.0
}

/// Status and response body: positive checks assert a concrete success, not "not
/// 401", otherwise 400 or 500 would pass for a win.
async fn reply_with(
    router: axum::Router,
    headers: &[(&'static str, &str)],
) -> (StatusCode, String) {
    let mut request = initialize_request();
    for (name, value) in headers {
        request
            .headers_mut()
            .insert(*name, value.parse().expect("header value"));
    }
    let response = router.oneshot(request).await.expect("response");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// Asserts that the request reached the MCP service and got an answer to `initialize`.
fn assert_initialized(status: StatusCode, body: &str, what: &str) {
    assert_eq!(status, StatusCode::OK, "{what}: body was {body}");
    assert!(
        body.contains("\"protocolVersion\""),
        "{what}: the MCP service did not answer initialize, body was {body}"
    );
}

#[tokio::test]
async fn request_without_token_is_rejected() {
    assert_eq!(
        status_with(router_with(header_only_state()), &[]).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn request_with_wrong_token_is_rejected() {
    assert_eq!(
        status_with(
            router_with(header_only_state()),
            &[
                (header::AUTHORIZATION.as_str(), "Bearer wrong"),
                ("x-ad-user", "alice"),
            ],
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn request_with_token_but_without_user_is_rejected() {
    assert_eq!(
        status_with(
            router_with(header_only_state()),
            &[(header::AUTHORIZATION.as_str(), "Bearer test-shared-secret")],
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn request_with_token_and_user_reaches_the_mcp_service() {
    let (status, body) = reply_with(
        router_with(header_only_state()),
        &[
            (header::AUTHORIZATION.as_str(), "Bearer test-shared-secret"),
            ("x-ad-user", "alice"),
        ],
    )
    .await;
    assert_initialized(status, &body, "shared secret with X-AD-User");
}

#[tokio::test]
async fn x_mcp_token_header_is_accepted() {
    let (status, body) = reply_with(
        router_with(header_only_state()),
        &[("x-mcp-token", TOKEN), ("x-ad-user", "alice")],
    )
    .await;
    assert_initialized(status, &body, "X-MCP-Token with X-AD-User");
}

/// AC-PRF-06: a request by profile token without X-AD-User passes the gate.
#[tokio::test]
async fn profile_token_without_user_reaches_the_service() {
    let (state, dir, token) = temp_profile_state("ok");
    let (status, body) = reply_with(
        router_with(state),
        &[(header::AUTHORIZATION.as_str(), &format!("Bearer {token}"))],
    )
    .await;
    assert_initialized(status, &body, "profile token without X-AD-User");
    std::fs::remove_dir_all(&dir).ok();
}

/// AC-PRF-49: headers without the shared secret give no identity.
#[tokio::test]
async fn headers_without_token_are_rejected_even_with_profile() {
    let (state, dir, _token) = temp_profile_state("headers");
    let status = status_with(
        router_with(state),
        &[("x-ad-user", "bob"), ("x-ad-password", "other")],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    std::fs::remove_dir_all(&dir).ok();
}

/// AC-PRF-40: a wrong profile token is 401.
#[tokio::test]
async fn wrong_profile_token_is_rejected() {
    let (state, dir, _token) = temp_profile_state("wrong");
    let status = status_with(
        router_with(state),
        &[(header::AUTHORIZATION.as_str(), "Bearer not-the-token")],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    std::fs::remove_dir_all(&dir).ok();
}

/// AC-PRF-53: repeated wrong requests cost no more than a constant-time
/// comparison; check that a correct token keeps working after a run of refusals.
#[tokio::test]
async fn profile_token_stays_valid_after_failures() {
    let (state, dir, token) = temp_profile_state("cheap");
    for _ in 0..10 {
        let status = status_with(
            router_with(state.clone()),
            &[(header::AUTHORIZATION.as_str(), "Bearer garbage-token")],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, body) = reply_with(
        router_with(state),
        &[(header::AUTHORIZATION.as_str(), &format!("Bearer {token}"))],
    )
    .await;
    assert_initialized(status, &body, "profile token after a run of failures");
    std::fs::remove_dir_all(&dir).ok();
}

/// AC-PRF-07: the header path stays available next to a profile.
#[tokio::test]
async fn header_path_still_works_with_profile_bound() {
    let (state, dir, _token) = temp_profile_state("both");
    let (status, body) = reply_with(
        router_with(state),
        &[
            (header::AUTHORIZATION.as_str(), "Bearer test-shared-secret"),
            ("x-ad-user", "bob"),
            ("x-ad-password", "other"),
        ],
    )
    .await;
    assert_initialized(status, &body, "header path next to a bound profile");
    std::fs::remove_dir_all(&dir).ok();
}
