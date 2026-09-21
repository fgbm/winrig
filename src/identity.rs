//! Извлечение идентичности вызывающего из текущего запроса (DR-2, ADR-0009).
//!
//! В HTTP идентичность определяется предъявленным секретом (ADR-0009 §4):
//! токен профиля даёт идентичность профиля и заголовки `X-AD-*` игнорируются;
//! общий секрет `WINRIG_AUTH_TOKEN` требует `X-AD-User`. Идентичность берётся из
//! `http::request::Parts`, которые streamable-HTTP транспорт `rmcp` кладёт в
//! расширения запроса, и никогда не наследуется из задачи, создавшей сессию.
//!
//! В stdio HTTP-запроса нет, поэтому идентичность берётся из профиля процесса и
//! передаётся серверу как локальная ([`RequestIdentity`] с источником
//! [`IdentitySource::Profile`]).

use http::request::Parts;
use rmcp::model::ErrorData;
use winrm_rs::SecretString;

/// Откуда взята идентичность текущего вызова.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentitySource {
    /// Из заголовков `X-AD-User`/`X-AD-Password` (HTTP, общий секрет).
    Headers,
    /// Из профиля учётной записи (токен профиля или stdio).
    Profile,
}

/// Идентичность вызывающего пользователя.
#[derive(Debug, Clone)]
pub struct RequestIdentity {
    /// Каноническое имя учётной записи.
    pub username: String,
    /// Пароль AD, если он был передан или восстановлен из профиля.
    pub password: Option<SecretString>,
    /// Источник идентичности.
    pub source: IdentitySource,
}

/// Идентичность профиля, положенная middleware в расширения запроса.
///
/// Наличие этой отметки означает, что запрос аутентифицирован токеном профиля;
/// заголовки `X-AD-*` при этом игнорируются (ADR-0009 §4).
#[derive(Debug, Clone)]
pub struct ProfileIdentity {
    /// Каноническое имя учётной записи из профиля.
    pub username: String,
    /// Пароль AD, расшифрованный из профиля и живущий только в памяти.
    pub password: SecretString,
}

fn header<'a>(parts: &'a Parts, name: &str) -> Option<&'a str> {
    parts
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// Читает `http::request::Parts` из контекста запроса.
pub fn request_parts(ctx: &rmcp::service::RequestContext<rmcp::RoleServer>) -> Option<&Parts> {
    ctx.extensions.get::<Parts>()
}

/// Приводит имя учётной записи к канонической форме.
///
/// AD не различает регистр в имени пользователя, а карты кэшей и счётчиков
/// отказов различали бы: `alice` и `ALICE` дали бы разные записи, обойдя
/// блокировку. Имя приводится к нижнему регистру. Та же функция применяется к
/// имени из профиля, чтобы ключ кэша совпадал с ключом для заголовка (AC-PRF-26).
#[must_use]
pub fn canonical_username(value: &str) -> String {
    value.to_ascii_lowercase()
}

/// Возвращает идентичность из заголовков текущего HTTP-запроса.
///
/// Используется HTTP-инструментами: `Parts` кладёт в расширения только
/// streamable-HTTP транспорт. В stdio запроса нет, поэтому сервер использует
/// заранее собранную идентичность профиля (см. `WinrigServer`).
///
/// # Errors
///
/// [`ErrorData`] с `INVALID_PARAMS`, если запрос не несёт `X-AD-User`.
pub fn identity_from_context(
    ctx: &rmcp::service::RequestContext<rmcp::RoleServer>,
) -> Result<RequestIdentity, ErrorData> {
    let parts = request_parts(ctx).ok_or_else(|| {
        ErrorData::invalid_params(
            "No active HTTP request; identity must come from request headers",
            None,
        )
    })?;
    identity_from_parts(parts)
}

/// Возвращает идентичность из расширений запроса или заголовков.///
/// Если middleware отметила запрос идентичностью профиля, она имеет приоритет,
/// а заголовки `X-AD-*` игнорируются с предупреждением (без кэширования и
/// логирования пароля из заголовка). Иначе читается `X-AD-User`; отсутствие
/// заголовков (нет HTTP-запроса) — ошибка MCP.
///
/// # Errors
///
/// [`ErrorData`] с `INVALID_PARAMS`, если запрос не несёт идентичности.
pub fn identity_from_parts(parts: &Parts) -> Result<RequestIdentity, ErrorData> {
    if let Some(profile) = parts.extensions.get::<ProfileIdentity>() {
        if parts.headers.contains_key("x-ad-user") || parts.headers.contains_key("x-ad-password") {
            tracing::warn!(
                target: "winrig::auth",
                "X-AD-* headers ignored: the request is authenticated by a profile token"
            );
        }
        return Ok(RequestIdentity {
            username: profile.username.clone(),
            password: Some(profile.password.clone()),
            source: IdentitySource::Profile,
        });
    }
    let username = header(parts, "x-ad-user")
        .ok_or_else(|| ErrorData::invalid_params("X-AD-User header required", None))?;
    let password = header(parts, "x-ad-password").map(SecretString::from);
    Ok(RequestIdentity {
        username: canonical_username(username),
        password,
        source: IdentitySource::Headers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderValue, Request};

    fn parts_with(headers: &[(&str, &str)]) -> Parts {
        let mut builder = Request::builder().uri("http://localhost/mcp");
        for (name, value) in headers {
            builder = builder.header(*name, HeaderValue::from_str(value).expect("header"));
        }
        builder.body(()).expect("request").into_parts().0
    }

    #[test]
    fn reads_user_and_password() {
        let parts = parts_with(&[("X-AD-User", "alice"), ("X-AD-Password", "s3cret")]);
        let identity = identity_from_parts(&parts).expect("identity");
        assert_eq!(identity.username, "alice");
        assert_eq!(identity.source, IdentitySource::Headers);
        use winrm_rs::ExposeSecret;
        assert_eq!(identity.password.unwrap().expose_secret(), "s3cret");
    }

    #[test]
    fn missing_user_is_rejected() {
        let parts = parts_with(&[("X-AD-Password", "s3cret")]);
        assert!(identity_from_parts(&parts).is_err());
    }

    #[test]
    fn canonical_username_folds_case() {
        assert_eq!(canonical_username("Alice"), "alice");
        assert_eq!(canonical_username("ALICE"), "alice");
        assert_eq!(canonical_username("DOMAIN\\Alice"), "domain\\alice");
    }

    /// AC-PRF-51: при токене профиля заголовки игнорируются, пароль из
    /// заголовка не попадает в идентичность.
    #[test]
    fn profile_identity_wins_over_headers() {
        let mut parts = parts_with(&[("X-AD-User", "bob"), ("X-AD-Password", "other")]);
        parts.extensions.insert(ProfileIdentity {
            username: "domain\\alice".to_owned(),
            password: SecretString::from("s3cret"),
        });
        let identity = identity_from_parts(&parts).expect("identity");
        assert_eq!(identity.username, "domain\\alice");
        assert_eq!(identity.source, IdentitySource::Profile);
        use winrm_rs::ExposeSecret;
        assert_eq!(identity.password.unwrap().expose_secret(), "s3cret");
    }
}
