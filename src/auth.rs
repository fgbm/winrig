//! The shared secret and the profile token at the boundary: check before trust (DR-1, ADR-0009).
//!
//! Each HTTP request must present one of the secrets: `WINRIG_AUTH_TOKEN` (as
//! `Authorization: Bearer` or `X-MCP-Token`) for the header path, or the profile
//! token that decrypts the profile file. The profile token is checked once: the
//! server remembers its HMAC and compares it in constant time on later requests,
//! without a KDF or decryption (AC-PRF-53). The secret that matches determines the
//! identity (ADR-0009 §4).
//!
//! `X-AD-User` is accepted only on the shared-secret path; a profile token makes
//! the server ignore it. The comparison is constant time. The refusal is 401 both
//! for a wrong profile token and for a corrupt file (the log tells them apart).

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use hkdf::hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::identity::ProfileIdentity;
use crate::profile;

/// Header with the AD user name.
pub const X_AD_USER: &str = "x-ad-user";
/// Header with the AD password (optional).
pub const X_AD_PASSWORD: &str = "x-ad-password";

type HmacSha256 = Hmac<Sha256>;

/// Middleware state: the shared secret and the checked profile token.
#[derive(Clone)]
pub struct AuthState {
    /// Shared secret for the header path; `None` disables that path.
    pub mcp_auth_token: Option<Arc<String>>,
    /// Bound account with the token check value.
    pub profile: Option<Arc<BoundProfile>>,
}

/// The token check value and the decrypted identity, held for the process
/// lifetime.
pub struct BoundProfile {
    /// Location of the profile file.
    pub path: std::path::PathBuf,
    /// HMAC of the first accepted secret, compared in constant time.
    token_mac: [u8; 32],
    /// Decrypted on the first check.
    identity: ProfileIdentity,
}

impl std::fmt::Debug for BoundProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundProfile")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl BoundProfile {
    /// Loads the profile with the presented token and keeps its check value.
    ///
    /// # Errors
    ///
    /// [`ProfileError`] on a wrong token or a corrupt file: the caller decides
    /// whether to end the process (stdio) or answer 401 (HTTP).
    pub fn bind(path: std::path::PathBuf, token: &str) -> Result<Self, profile::ProfileError> {
        let identity = profile::load(&path, token)?;
        Ok(Self {
            path,
            token_mac: token_mac(token),
            identity: ProfileIdentity {
                username: crate::identity::canonical_username(&identity.username),
                password: identity.password,
            },
        })
    }

    /// Compares in constant time against the stored check value.
    #[must_use]
    pub fn token_matches(&self, token: &str) -> bool {
        token_mac(token).ct_eq(&self.token_mac).into()
    }

    /// Who the profile authenticates as.
    #[must_use]
    pub fn identity(&self) -> &ProfileIdentity {
        &self.identity
    }
}

fn token_mac(token: &str) -> [u8; 32] {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(b"winrig-profile-token-check")
        .expect("HMAC accepts any key length");
    mac.update(token.as_bytes());
    mac.finalize().into_bytes().into()
}

fn presented_token(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers.get("x-mcp-token").and_then(|v| v.to_str().ok()) {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_owned());
        }
    }
    let authorization = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, value) = authorization.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_owned());
        }
    }
    None
}

fn token_matches(presented: &str, expected: &str) -> bool {
    presented.as_bytes().ct_eq(expected.as_bytes()).into()
}

/// Rejects a user name with a line break.
///
/// `http::HeaderValue` already rejects CR/LF, so such a header does not pass
/// through `rmcp`; the check guards against non-standard transports that build
/// `Parts` from raw bytes. A name with a line break could forge an audit line
/// (TR-SEC-09).
fn is_safe_username(username: &str) -> bool {
    !username.contains('\r') && !username.contains('\n')
}

/// Authentication middleware for the shared secret or the profile token.
pub async fn auth_middleware(
    State(state): State<AuthState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(presented) = presented_token(request.headers()) else {
        warn_rejection("missing token");
        return reject("Valid bearer token required", true);
    };

    // Profile token: it gives the profile identity.
    if let Some(profile) = state.profile.as_ref()
        && profile.token_matches(&presented)
    {
        let mut request = request;
        request.extensions_mut().insert(profile.identity().clone());
        return next.run(request).await;
    }

    // Shared secret: it requires X-AD-User.
    let Some(expected) = state.mcp_auth_token.as_ref() else {
        warn_rejection("invalid profile token");
        return reject("Valid bearer token required", true);
    };
    if !token_matches(&presented, expected.as_str()) {
        warn_rejection("invalid token");
        return reject("Valid bearer token required", true);
    }
    let headers = request.headers();
    let Some(username) = headers
        .get(X_AD_USER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        warn_rejection("missing X-AD-User");
        return reject("X-AD-User header required", false);
    };
    if !is_safe_username(username) {
        warn_rejection("invalid X-AD-User");
        return reject("Invalid X-AD-User header", false);
    }
    next.run(request).await
}

/// Logs an authentication refusal.
///
/// The token and the headers are never logged: the refusal happens before the
/// identity is trusted, and the presented value may be another user's secret. The
/// reason tells a wrong profile token from a missing secret, to debug the
/// application (AC-PRF-40/41); the client always gets the same 401.
fn warn_rejection(reason: &str) {
    tracing::warn!(target: "winrig::auth", reason, "request rejected before identity is trusted");
}

fn reject(message: &str, challenge: bool) -> Response {
    let body = Body::from(format!("{{\"error\":\"{message}\"}}"));
    let mut response = (StatusCode::UNAUTHORIZED, body).into_response();
    if challenge {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static("Bearer"),
        );
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile;
    use std::fs;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "winrig-auth-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// AC-SEC09-1: a name with a line break is rejected before trust.
    #[test]
    fn crlf_username_is_unsafe() {
        assert!(!is_safe_username("alice\nadmin"));
        assert!(!is_safe_username("alice\r\nadmin"));
        assert!(is_safe_username("domain\\alice"));
    }

    /// AC-PRF-40: a wrong token fails the check.
    #[test]
    fn bound_profile_rejects_wrong_token() {
        let dir = temp_dir("wrong");
        let path = dir.join("corp.json");
        let token =
            profile::create(&path, "corp", "domain\\alice", "s3cret", false).expect("create");
        let bound = BoundProfile::bind(path.clone(), &token).expect("bind");
        assert!(bound.token_matches(&token));
        assert!(!bound.token_matches("other-token"));
        fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-33: a rotation on disk is invisible to a running process until restart.
    #[test]
    fn rotation_on_disk_does_not_affect_bound_profile() {
        let dir = temp_dir("rotate");
        let path = dir.join("corp.json");
        let old = profile::create(&path, "corp", "domain\\alice", "s3cret", false).expect("create");
        let bound = BoundProfile::bind(path.clone(), &old).expect("bind");
        let new = profile::rotate(&path, "s3cret").expect("rotate");
        // The running process keeps accepting the old token.
        assert!(bound.token_matches(&old));
        assert!(!bound.token_matches(&new));
        // Another process accepts the new token.
        let rebound = BoundProfile::bind(path.clone(), &new).expect("rebind");
        assert!(rebound.token_matches(&new));
        fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-34: forgetting the profile on disk is invisible to a running process
    /// until restart; the binding keeps the decrypted identity in memory.
    #[test]
    fn forgetting_on_disk_does_not_affect_bound_profile() {
        let dir = temp_dir("forget");
        let path = dir.join("corp.json");
        let token =
            profile::create(&path, "corp", "domain\\alice", "s3cret", false).expect("create");
        let bound = BoundProfile::bind(path.clone(), &token).expect("bind");
        assert!(profile::forget(&path).expect("forget"));
        // The running process keeps accepting the token and knows the identity.
        assert!(bound.token_matches(&token));
        assert_eq!(bound.identity().username, "domain\\alice");
        // A new process on the same path refuses: the file is gone.
        assert!(BoundProfile::bind(path, &token).is_err());
        fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-41: a corrupt file is a parse error, not a token refusal.
    #[test]
    fn corrupt_profile_is_a_distinct_error() {
        let dir = temp_dir("corrupt");
        let path = dir.join("corp.json");
        let _ = profile::create(&path, "corp", "domain\\alice", "s3cret", false).expect("create");
        fs::write(&path, b"not json").expect("write");
        assert!(matches!(
            BoundProfile::bind(path, "any"),
            Err(profile::ProfileError::Corrupt { .. })
        ));
        fs::remove_dir_all(&dir).ok();
    }
}
