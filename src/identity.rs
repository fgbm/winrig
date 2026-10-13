//! Extraction of the caller identity from the current request (DR-2, ADR-0009).
//!
//! In HTTP the presented secret determines the identity (ADR-0009 §4): a profile
//! token gives the profile identity and the `X-AD-*` headers are ignored; the
//! shared secret `WINRIG_AUTH_TOKEN` requires `X-AD-User`. The identity comes from
//! the `http::request::Parts` that the `rmcp` streamable-HTTP transport puts into
//! the request extensions, and is never inherited from the task that created the
//! session.
//!
//! stdio has no HTTP request, so the identity comes from the process profile and
//! is passed to the server as local ([`RequestIdentity`] with the
//! [`IdentitySource::Profile`] source).

use http::request::Parts;
use rmcp::model::ErrorData;
use winrm_rs::SecretString;

/// Origin of the identity of the current call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentitySource {
    /// From `X-AD-User`/`X-AD-Password` (HTTP, shared secret).
    Headers,
    /// From the stored account (token or stdio).
    Profile,
}

/// Identity of the calling user.
#[derive(Debug, Clone)]
pub struct RequestIdentity {
    /// Canonical account name.
    pub username: String,
    /// AD secret, given or recovered from the profile.
    pub password: Option<SecretString>,
    /// Where it came from.
    pub source: IdentitySource,
}

/// Placed by the middleware into the request extensions.
///
/// Its presence means the request is authenticated by a profile token; the
/// `X-AD-*` headers are then ignored (ADR-0009 §4).
#[derive(Debug, Clone)]
pub struct ProfileIdentity {
    /// Canonical account name from the profile.
    pub username: String,
    /// AD secret decrypted from the profile, kept only in memory.
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

/// The HTTP parts stored in the context extensions.
pub fn request_parts(ctx: &rmcp::service::RequestContext<rmcp::RoleServer>) -> Option<&Parts> {
    ctx.extensions.get::<Parts>()
}

/// Brings the account name to canonical form.
///
/// AD does not distinguish case in a user name, but the cache and lockout maps
/// would: `alice` and `ALICE` would get separate entries and bypass the lockout.
/// The name is lowercased. The same function applies to the profile name, so the
/// cache key matches the key for a header (AC-PRF-26).
#[must_use]
pub fn canonical_username(value: &str) -> String {
    value.to_ascii_lowercase()
}

/// Returns the identity from the headers of the current HTTP request.
///
/// Used by the HTTP tools: only the streamable-HTTP transport puts `Parts` into
/// the extensions. stdio has no request, so the server uses the identity collected
/// from the profile (see `WinrigServer`).
///
/// # Errors
///
/// [`ErrorData`] with `INVALID_PARAMS` when the request carries no `X-AD-User`.
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

/// Returns the identity from the request extensions or headers.
///
/// When the middleware marked the request with the profile identity, that takes
/// priority and the `X-AD-*` headers are ignored with a warning (the header
/// password is neither cached nor logged). Otherwise `X-AD-User` is read; missing
/// headers (no HTTP request) are an MCP error.
///
/// # Errors
///
/// [`ErrorData`] with `INVALID_PARAMS` when the request carries no identity.
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

    /// AC-PRF-51: with a profile token the headers are ignored, and the header
    /// password never reaches the identity.
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
