//! Общий секрет и токен профиля на входе: проверка до доверия (DR-1, ADR-0009).
//!
//! Каждый HTTP-запрос обязан предъявить один из секретов:
//! `WINRIG_AUTH_TOKEN` (как `Authorization: Bearer` или `X-MCP-Token`) для пути по
//! заголовкам либо токен профиля, который расшифровывает файл профиля. Токен
//! профиля проверяется один раз: сервер запоминает HMAC токена и на повторных
//! запросах сравнивает его константно по времени, не выполняя KDF и расшифровку
//! (AC-PRF-53). Совпадение секрета определяет идентичность (ADR-0009 §4).
//!
//! `X-AD-User` принимается только на пути общего секрета; при токене профиля он
//! игнорируется. Сравнение — константное по времени. Отказ — 401: как при
//! неверном токене профиля, так и при повреждённом файле (журнал их различает).

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use hkdf::hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::identity::ProfileIdentity;
use crate::profile;

/// Заголовок с именем пользователя AD.
pub const X_AD_USER: &str = "x-ad-user";
/// Заголовок с паролем AD (необязательный).
pub const X_AD_PASSWORD: &str = "x-ad-password";

type HmacSha256 = Hmac<Sha256>;

/// Состояние middleware: общий секрет и проверенный токен профиля.
#[derive(Clone)]
pub struct AuthState {
    /// Общий секрет для пути по заголовкам; `None` отключает этот путь.
    pub mcp_auth_token: Option<Arc<String>>,
    /// Профиль, привязанный к процессу, с проверочным значением токена.
    pub profile: Option<Arc<BoundProfile>>,
}

/// Профиль, привязанный к процессу: путь, проверочное значение токена и
/// расшифрованная идентичность на время жизни процесса.
pub struct BoundProfile {
    /// Путь к файлу профиля.
    pub path: std::path::PathBuf,
    /// HMAC первого успешно предъявленного токена; сравнение постоянное по времени.
    token_mac: [u8; 32],
    /// Идентичность профиля, расшифрованная при первой проверке.
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
    /// Привязывает профиль по предъявленному токену.
    ///
    /// # Errors
    ///
    /// [`ProfileError`] при неверном токене или повреждённом файле: вызывающий
    /// решает, завершать ли процесс (stdio) или ответить 401 (HTTP).
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

    /// Истина, если токен совпадает с проверочным значением.
    #[must_use]
    pub fn token_matches(&self, token: &str) -> bool {
        token_mac(token).ct_eq(&self.token_mac).into()
    }

    /// Идентичность профиля.
    #[must_use]
    pub fn identity(&self) -> &ProfileIdentity {
        &self.identity
    }
}

fn token_mac(token: &str) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(b"winrig-profile-token-check")
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

/// Имя пользователя не содержит переводов строк.
///
/// `http::HeaderValue` уже отвергает CR/LF, поэтому через `rmcp` такой заголовок
/// не проходит; проверка остаётся страховкой от нестандартных транспортов,
/// которые собирают `Parts` из сырых байтов. Имя с переводом строки могло бы
/// подделать строку аудита (TR-SEC-09).
fn is_safe_username(username: &str) -> bool {
    !username.contains('\r') && !username.contains('\n')
}

/// Middleware аутентификации по общему секрету или токену профиля.
pub async fn auth_middleware(
    State(state): State<AuthState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(presented) = presented_token(request.headers()) else {
        warn_rejection("missing token");
        return reject("Valid bearer token required", true);
    };

    // 1. Токен профиля: даёт идентичность профиля.
    if let Some(profile) = state.profile.as_ref()
        && profile.token_matches(&presented)
    {
        let mut request = request;
        request.extensions_mut().insert(profile.identity().clone());
        return next.run(request).await;
    }

    // 2. Общий секрет: требует X-AD-User.
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

/// Пишет отказ аутентификации в журнал.
///
/// Сам токен и заголовки не логируются: отказ происходит до доверия к
/// идентичности, а предъявленное значение может быть чужим секретом. Причина
/// различает неверный токен профиля и отсутствие секрета, чтобы отлаживать
/// приложение (AC-PRF-40/41); клиент во всех случаях получает одинаковый 401.
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

    /// AC-SEC09-1: имя с переводом строки отвергается до доверия.
    #[test]
    fn crlf_username_is_unsafe() {
        assert!(!is_safe_username("alice\nadmin"));
        assert!(!is_safe_username("alice\r\nadmin"));
        assert!(is_safe_username("domain\\alice"));
    }

    /// AC-PRF-40: неверный токен не проходит проверку.
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

    /// AC-PRF-33: ротация на диске не видна работающему процессу до перезапуска.
    #[test]
    fn rotation_on_disk_does_not_affect_bound_profile() {
        let dir = temp_dir("rotate");
        let path = dir.join("corp.json");
        let old = profile::create(&path, "corp", "domain\\alice", "s3cret", false).expect("create");
        let bound = BoundProfile::bind(path.clone(), &old).expect("bind");
        let new = profile::rotate(&path, "s3cret").expect("rotate");
        // Работающий процесс продолжает принимать старый токен.
        assert!(bound.token_matches(&old));
        assert!(!bound.token_matches(&new));
        // Новый процесс принимает новый токен.
        let rebound = BoundProfile::bind(path.clone(), &new).expect("rebind");
        assert!(rebound.token_matches(&new));
        fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-34: удаление профиля на диске не видно работающему процессу до
    /// перезапуска — привязка держит расшифрованную идентичность в памяти.
    #[test]
    fn forgetting_on_disk_does_not_affect_bound_profile() {
        let dir = temp_dir("forget");
        let path = dir.join("corp.json");
        let token =
            profile::create(&path, "corp", "domain\\alice", "s3cret", false).expect("create");
        let bound = BoundProfile::bind(path.clone(), &token).expect("bind");
        assert!(profile::forget(&path).expect("forget"));
        // Работающий процесс продолжает принимать токен и знает идентичность.
        assert!(bound.token_matches(&token));
        assert_eq!(bound.identity().username, "domain\\alice");
        // Новый процесс по тому же пути отказывает: файла нет.
        assert!(BoundProfile::bind(path, &token).is_err());
        fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-41: повреждённый файл — ошибка разбора, не отказ токена.
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
