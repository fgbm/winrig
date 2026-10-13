//! Pure allow/deny decisions without WinRM (ADR-0003, ADR-0005, DR-6, DR-7).
//!
//! The module does not touch the network or the transport: it normalizes the input and returns a verdict.
//! Port of `agent/policy.py`; path normalization follows `ntpath.normpath`/`ntpath.splitroot` from the CPython
//! standard library, because path protection must fire for any written form.

use crate::config::{MAX_PORT, MIN_PORT};

/// System directories in canonical form (uppercase, single `\`).
const PROTECTED_DIRS: [&str; 6] = [
    "C:\\WINDOWS",
    "C:\\WINDOWS\\SYSTEM32",
    "C:\\PROGRAM FILES",
    "C:\\PROGRAM FILES (X86)",
    "C:\\USERS",
    "C:\\PROGRAMDATA",
];

/// Stripped from the front before normalization.
const DEVICE_PREFIXES: [&str; 3] = ["\\\\?\\", "\\\\.\\", "\\??\\"];
/// Map to a plain UNC path before normalization.
const UNC_PREFIXES: [&str; 2] = ["\\\\?\\UNC\\", "\\??\\UNC\\"];

/// Invalid policy input; the message names the parameter and the expected form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError(String);

impl PolicyError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PolicyError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    pub allow: bool,
    pub reason: String,
    /// Stable machine-readable value such as `OK` or `HOST_NOT_ALLOWED`.
    pub code: &'static str,
}

impl PolicyDecision {
    fn allow(reason: impl Into<String>) -> Self {
        Self {
            allow: true,
            reason: reason.into(),
            code: "OK",
        }
    }

    fn deny(reason: impl Into<String>, code: &'static str) -> Self {
        Self {
            allow: false,
            reason: reason.into(),
            code,
        }
    }
}

fn collapse_backslashes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_backslash = false;
    for c in s.chars() {
        if c == '\\' {
            if !prev_backslash {
                out.push(c);
            }
            prev_backslash = true;
        } else {
            out.push(c);
            prev_backslash = false;
        }
    }
    out
}

/// Path pieces (drive, root, tail), like `ntpath.splitroot`.
fn split_root(path: &str) -> (String, String, String) {
    const SEP: char = '\\';
    let normp: Vec<char> = path.replace('/', "\\").chars().collect();
    match (normp.first(), normp.get(1)) {
        (Some(&SEP), Some(&SEP)) => {
            let head8: String = normp.iter().take(8).collect();
            let start = if head8.to_uppercase() == "\\\\?\\UNC\\" {
                8
            } else {
                2
            };
            let index = (start..normp.len()).find(|&j| normp[j] == SEP);
            let Some(index) = index else {
                return (path.to_owned(), String::new(), String::new());
            };
            let index2 = (index + 1..normp.len()).find(|&j| normp[j] == SEP);
            let Some(index2) = index2 else {
                return (path.to_owned(), String::new(), String::new());
            };
            (
                normp[..index2].iter().collect(),
                normp[index2..=index2].iter().collect(),
                normp[index2 + 1..].iter().collect(),
            )
        }
        (Some(&SEP), _) => (
            String::new(),
            normp[..1].iter().collect(),
            normp[1..].iter().collect(),
        ),
        (_, Some(&':')) => {
            if normp.get(2) == Some(&SEP) {
                (
                    normp[..2].iter().collect(),
                    normp[2..3].iter().collect(),
                    normp[3..].iter().collect(),
                )
            } else {
                (
                    normp[..2].iter().collect(),
                    String::new(),
                    normp[2..].iter().collect(),
                )
            }
        }
        _ => (String::new(), String::new(), path.to_owned()),
    }
}

/// Lexical normalization of a Windows path (`ntpath.normpath`).
fn normpath(path: &str) -> String {
    let replaced = path.replace('/', "\\");
    let (drive, root, tail) = split_root(&replaced);
    let prefix = format!("{drive}{root}");
    let mut comps: Vec<&str> = tail.split('\\').collect();
    let mut i = 0;
    while i < comps.len() {
        if comps[i].is_empty() || comps[i] == "." {
            comps.remove(i);
        } else if comps[i] == ".." {
            if i > 0 && comps[i - 1] != ".." {
                comps.remove(i - 1);
                comps.remove(i - 1);
                i -= 1;
            } else if i == 0 && !root.is_empty() {
                comps.remove(i);
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    if prefix.is_empty() && comps.is_empty() {
        comps.push(".");
    }
    prefix + &comps.join("\\")
}

/// Canonical form for comparison (DR-6): protection must fire for any written form.
///
/// `/` becomes `\`; the `\\?\UNC\` and `\??\UNC\` prefixes are stripped (to a plain UNC
/// `\\server\share`), then `\\?\`, `\\.\` and `\??\`; runs of `\` collapse; `.` and `..`
/// collapse lexically; trailing dots and spaces are dropped from each component (Windows
/// does not distinguish them); a trailing `\` is removed except at a volume root; the
/// result is uppercase. For a UNC `\\server\share` the leading two `\` are kept.
#[must_use]
pub fn normalize_windows_path(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    let mut p = path.replace('/', "\\");
    let upper = p.to_uppercase();
    if UNC_PREFIXES.iter().any(|prefix| upper.starts_with(prefix)) {
        for prefix in UNC_PREFIXES {
            if upper.starts_with(prefix) {
                p = format!("\\\\{}", &p[prefix.len()..]);
                break;
            }
        }
    } else {
        for prefix in DEVICE_PREFIXES {
            if p.starts_with(prefix) {
                p = p[prefix.len()..].to_owned();
                break;
            }
        }
    }
    let is_unc = p.starts_with("\\\\");
    p = collapse_backslashes(&p);
    if is_unc {
        p = format!("\\{p}");
    }
    p = normpath(&p);
    let parts: Vec<String> = p
        .split('\\')
        .map(|part| {
            if part == "." || part == ".." {
                part.to_owned()
            } else {
                part.trim_end_matches([' ', '.']).to_owned()
            }
        })
        .collect();
    p = parts.join("\\");
    if !is_volume_root(&p) {
        p = p.trim_end_matches('\\').to_owned();
    }
    p.to_uppercase()
}

/// `^[A-Z]:\\$` — a volume root.
fn is_volume_root(norm: &str) -> bool {
    let bytes = norm.as_bytes();
    bytes.len() == 3 && bytes[0].is_ascii_uppercase() && bytes[1] == b':' && bytes[2] == b'\\'
}

/// `^VOLUME\{[^}]*\}$` — the volume itself as `Volume{GUID}`.
fn is_volume_guid(norm: &str) -> bool {
    let Some(rest) = norm.strip_prefix("VOLUME{") else {
        return false;
    };
    let Some(inner) = rest.strip_suffix('}') else {
        return false;
    };
    !inner.contains('}')
}

/// `^VOLUME\{[^}]*\}\\$` — the volume root as `Volume{GUID}\`.
fn is_volume_guid_root(norm: &str) -> bool {
    let Some(rest) = norm.strip_prefix("VOLUME{") else {
        return false;
    };
    let Some(inner) = rest.strip_suffix("}\\") else {
        return false;
    };
    !inner.contains('}')
}

/// `^\\\\[^\\]+\\[^\\]+$` — a UNC share root exactly at the share level.
fn is_unc_share_root(norm: &str) -> bool {
    let Some(rest) = norm.strip_prefix("\\\\") else {
        return false;
    };
    let Some((server, share)) = rest.split_once('\\') else {
        return false;
    };
    !server.is_empty() && !share.is_empty() && !share.contains('\\')
}

/// Volume roots, UNC share roots and system directories are protected (DR-6).
///
/// Protected: the roots of any volume (`X:\`), a UNC share root `\\server\share`
/// exactly at the share level (subdirectories inside the share are not protected), a
/// volume root as `\\?\Volume{GUID}\`, and the system directories with their subtrees
/// (ADR-0005 §5, AC-SEC04-1).
#[must_use]
pub fn is_protected_path(path: &str) -> bool {
    let norm = normalize_windows_path(path);
    if norm.is_empty() {
        return false;
    }
    // The administrative share `\\host\C$\...` is the same as `C:\...` (ADR-0015).
    if let Some(local) = admin_share_local(&norm)
        && is_protected_path(&local)
    {
        return true;
    }
    if is_system_share(&norm) {
        return true;
    }
    if is_volume_root(&norm) || is_volume_guid(&norm) || is_volume_guid_root(&norm) {
        return true;
    }
    if is_unc_share_root(&norm) {
        return true;
    }
    PROTECTED_DIRS
        .iter()
        .any(|protected| norm == *protected || norm.starts_with(&format!("{protected}\\")))
}

/// Local form of an administrative share: `\\HOST\C$\REST` → `C:\REST`.
///
/// Takes a normalized path (`normalize_windows_path`). A share `X$` points at the volume
/// root `X:`, so protection checks it as a local path; otherwise `\\localhost\C$\Windows`
/// would slip past the list.
fn admin_share_local(norm: &str) -> Option<String> {
    let rest = norm.strip_prefix("\\\\")?;
    let mut parts = rest.splitn(3, '\\');
    let _server = parts.next()?;
    let share = parts.next()?;
    let mut chars = share.chars();
    let (Some(drive), Some('$'), None) = (chars.next(), chars.next(), chars.next()) else {
        return None;
    };
    if !drive.is_ascii_alphabetic() {
        return None;
    }
    Some(format!("{drive}:\\{}", parts.next().unwrap_or("")))
}

/// True for shares that point inside a system directory: `ADMIN$` is `%SystemRoot%`,
/// `PRINT$` is the driver directory inside it, and `SYSVOL` and `NETLOGON` on a domain
/// controller sit in `%SystemRoot%\SYSVOL`.
///
/// Takes a normalized path. Only the host knows where a share points, but their target
/// is fixed, so all their content is protected.
fn is_system_share(norm: &str) -> bool {
    norm.strip_prefix("\\\\")
        .and_then(|rest| rest.split('\\').nth(1))
        .is_some_and(|share| matches!(share, "ADMIN$" | "PRINT$" | "SYSVOL" | "NETLOGON"))
}

/// Path component in 8.3 form (`PROGRA~1`), if present.
///
/// A short name cannot be compared against the protected path list as a string:
/// `C:\PROGRA~1` is `C:\Program Files`, but only the host can tell. The marker is `~`
/// after at least one character and before a digit.
#[must_use]
pub fn short_name_component(path: &str) -> Option<String> {
    normalize_windows_path(path)
        .split('\\')
        .find(|component| {
            component.char_indices().any(|(index, c)| {
                c == '~'
                    && index > 0
                    && component[index + 1..].starts_with(|next: char| next.is_ascii_digit())
            })
        })
        .map(str::to_owned)
}

/// Refusal for a path with an 8.3 name (ADR-0015, DR-6: "in any written form of the path").
fn refuse_short_name(path: &str, requested: &str, verb: &str) -> Option<PolicyDecision> {
    short_name_component(path).map(|component| {
        PolicyDecision::deny(
            format!(
                "refusing to {verb} {requested:?}: {component} is an 8.3 short name, which cannot \
                 be checked against protected paths; pass the long name"
            ),
            "PATH_PROTECTED",
        )
    })
}

/// `*` matches every host (ADR-0015 §7).
pub const ANY_HOST: &str = "*";

/// True for a loopback literal: `localhost`, an address in `127.0.0.0/8`, or `::1`
/// (also in square brackets).
///
/// DNS is not resolved: a name that only resolves to loopback is not a literal, because
/// the operator does not control the DNS answer (ADR-0015 §6).
fn is_loopback_literal(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let bare = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    bare.parse::<std::net::IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

/// True for a DNS name: labels of `[A-Za-z0-9_-]` separated by dots, none empty.
///
/// `_` is allowed for NetBIOS names; characters that a URL or `winrm-rs` split a string
/// on (`/`, `?`, `#`, `@`, `:`) cannot appear in a name.
fn is_host_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
}

/// True if the string is a host name, an IP address, or an IPv6 address in square brackets.
///
/// The check runs before the allowlist comparison: `winrm-rs` truncates the host at `/`,
/// `@`, `://` and `:port`, and a URL parser at `?` and `#`, so `evil.com/.corp.example`
/// would match the `.corp.example` suffix while the connection went to `evil.com`
/// (ADR-0015 §6).
#[must_use]
pub fn is_valid_host(host: &str) -> bool {
    if let Some(inner) = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        return inner.parse::<std::net::Ipv6Addr>().is_ok();
    }
    host.parse::<std::net::IpAddr>().is_ok() || is_host_name(host)
}

/// One grammar for `WINRIG_ALLOWED_HOSTS` and `setup --allowed-hosts` (ADR-0015 §6–7, §9).
///
/// Comma-separated entries, empty ones skipped; an entry is `*`, a suffix with a leading
/// `.`, or a host name, an IP address, or an IPv6 in brackets. The result is
/// lowercased and trimmed.
///
/// # Errors
///
/// The first entry that does not fit the grammar; the caller names its source (the
/// variable or the flag) in the refusal.
pub fn parse_allowed_hosts(raw: &str) -> Result<Vec<String>, String> {
    let mut entries = Vec::new();
    for item in raw.split(',') {
        let entry = item.trim().to_ascii_lowercase();
        if entry.is_empty() {
            continue;
        }
        let valid = entry == ANY_HOST
            || entry
                .strip_prefix('.')
                .map_or_else(|| is_valid_host(&entry), is_host_name);
        if !valid {
            return Err(item.trim().to_owned());
        }
        entries.push(entry);
    }
    Ok(entries)
}

/// Host list form for the refusal text.
pub const ALLOWED_HOSTS_FORM: &str =
    "a comma-separated list of host names or IPs, '.suffix' entries, or '*' for any host";

/// Allowlist verdict for a host (Q-03, ADR-0015 §6–7).
///
/// A string that is not a name or an IP is never allowed. An empty list allows only
/// loopback literals; `*` allows any host; an entry with a leading `.` is a suffix;
/// otherwise the match is exact and case-insensitive.
#[must_use]
pub fn host_allowed(host: &str, allowed_hosts: &[String]) -> bool {
    // ASCII-only folding: Unicode folding would turn the Kelvin sign U+212A into `k`, and
    // a non-ASCII name would pass the syntax check.
    let candidate = host.trim().to_ascii_lowercase();
    if !is_valid_host(&candidate) {
        return false;
    }
    if allowed_hosts.iter().all(|raw| raw.trim().is_empty()) {
        return is_loopback_literal(&candidate);
    }
    for raw in allowed_hosts {
        let entry = raw.trim().to_lowercase();
        if entry.is_empty() {
            continue;
        }
        if entry == ANY_HOST {
            return true;
        }
        if let Some(apex) = entry.strip_prefix('.') {
            if candidate == apex || candidate.ends_with(&entry) {
                return true;
            }
        } else if candidate == entry {
            return true;
        }
    }
    false
}

/// Range check for the port, then passthrough.
///
/// # Errors
///
/// [`PolicyError`] if the port is outside `MIN_PORT..=MAX_PORT`.
pub fn validate_port(port: Option<i64>) -> Result<Option<i64>, PolicyError> {
    let Some(value) = port else {
        return Ok(None);
    };
    if !(i64::from(MIN_PORT)..=i64::from(MAX_PORT)).contains(&value) {
        return Err(PolicyError::new(format!(
            "port={value} is out of range; expected an integer between {MIN_PORT} and {MAX_PORT}"
        )));
    }
    Ok(Some(value))
}

/// `None` means the TLS check downgrade is acceptable; otherwise the refusal reason.
#[must_use]
pub fn tls_decision(verify_cert: bool, allow_insecure_tls: bool) -> Option<(bool, &'static str)> {
    if !verify_cert && !allow_insecure_tls {
        return Some((
            false,
            "TLS certificate verification is disabled and WINRIG_ALLOW_INSECURE_TLS \
             forbids accepting that connection",
        ));
    }
    None
}

#[must_use]
pub fn decide_host(host: &str, allowed_hosts: &[String]) -> PolicyDecision {
    if host_allowed(host, allowed_hosts) {
        PolicyDecision::allow("host is allowed")
    } else {
        let reason = if !is_valid_host(&host.trim().to_ascii_lowercase()) {
            format!(
                "host {host:?} is not a host name or IP address; pass the bare name or address, \
                 and the port in the port argument"
            )
        } else if allowed_hosts.iter().all(|raw| raw.trim().is_empty()) {
            format!(
                "host {host:?} is not allowed: WINRIG_ALLOWED_HOSTS is empty, which permits only \
                 loopback (localhost, 127.0.0.0/8, ::1); list the hosts, or use * for any host"
            )
        } else {
            format!("host {host:?} is not in WINRIG_ALLOWED_HOSTS")
        };
        PolicyDecision::deny(reason, "HOST_NOT_ALLOWED")
    }
}

#[must_use]
pub fn decide_port(port: Option<i64>) -> PolicyDecision {
    match validate_port(port) {
        Ok(_) => PolicyDecision::allow("port is valid"),
        Err(error) => PolicyDecision::deny(error.to_string(), "PORT_OUT_OF_RANGE"),
    }
}

#[must_use]
pub fn decide_tls(verify_cert: bool, allow_insecure_tls: bool) -> PolicyDecision {
    match tls_decision(verify_cert, allow_insecure_tls) {
        Some((_, reason)) => PolicyDecision::deny(reason, "TLS_VERIFY_NOT_ALLOWED"),
        None => PolicyDecision::allow("TLS policy satisfied"),
    }
}

#[must_use]
pub fn decide_delete_path(path: &str) -> PolicyDecision {
    if let Some(refusal) = refuse_short_name(path, path, "delete") {
        return refusal;
    }
    if is_protected_path(path) {
        PolicyDecision::deny(
            format!("refusing to delete protected path: {path:?}"),
            "PATH_PROTECTED",
        )
    } else {
        PolicyDecision::allow("path is not protected")
    }
}

/// File write verdict: a protected path is refused before the network (TR-FS-02).
///
/// The list is the same as for delete: being able to overwrite a system file is no
/// different in effect from being able to delete it.
#[must_use]
pub fn decide_write_path(path: &str) -> PolicyDecision {
    if let Some(refusal) = refuse_short_name(path, path, "write to") {
        return refusal;
    }
    if is_protected_path(path) {
        PolicyDecision::deny(
            format!("refusing to write to protected path: {path:?}"),
            "PATH_PROTECTED",
        )
    } else {
        PolicyDecision::allow("path is not protected")
    }
}

/// Overwrite verdict: an existing file is replaced only with the flag (TR-FS-03).
///
/// The decision is separate from the tool because otherwise it cannot be tested: the
/// write path goes through confirmation and a `RequestContext` that the tests do not
/// build.
#[must_use]
pub fn decide_overwrite(path: &str, exists: bool, overwrite: bool) -> PolicyDecision {
    if exists && !overwrite {
        PolicyDecision::deny(
            format!("{path} already exists; pass overwrite=true to replace it"),
            "FILE_EXISTS",
        )
    } else {
        PolicyDecision::allow("target may be written")
    }
}

/// Fail-closed: an unreadable answer is a refusal reason, not "safe by default".
fn scan_object(raw: &str) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let value: serde_json::Value = serde_json::from_str(raw.trim())
        .map_err(|error| format!("Pre-scan returned an unreadable result: {error}"))?;
    match value {
        serde_json::Value::Object(object) => Ok(object),
        _ => Err("Pre-scan returned a non-object result.".to_owned()),
    }
}

/// Non-empty string field of the scan.
fn required_str(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<String, String> {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("Pre-scan result is missing {key}."))
}

fn required_bool(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<bool, String> {
    object
        .get(key)
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| format!("Pre-scan result is missing {key}."))
}

/// Protected system roots on the actual volume (TR-FS-06, ADR-0015 §10–12).
///
/// The lexical `PROTECTED_DIRS` list knows only `C:`; these roots name the actual system
/// location, on whatever volume it sits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostRoots {
    /// Pairs of (name, path on the host).
    roots: Vec<(String, String)>,
}

impl HostRoots {
    /// Order of the roots as the scan returns them (`ps::HOST_ROOTS`).
    const NAMES: [&'static str; 5] = [
        "SystemRoot",
        "ProgramFiles",
        "ProgramFilesX86",
        "ProgramData",
        "Users",
    ];

    /// An empty optional root is skipped: `ProgramFiles(x86)` is legitimately absent on a
    /// 32-bit system. An empty or missing `SystemRoot` is a refusal, because the check
    /// would lose its main root (ADR-0015 §11).
    fn from_scan(object: &serde_json::Map<String, serde_json::Value>) -> Result<Self, String> {
        let roots = object
            .get("Roots")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| "Pre-scan result is missing Roots.".to_owned())?;
        let mut out = Vec::new();
        for name in Self::NAMES {
            let value = roots
                .get(name)
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty());
            match value {
                Some(path) => out.push((name.to_owned(), path.to_owned())),
                None if name == "SystemRoot" => {
                    return Err(
                        "Pre-scan result has no SystemRoot, so the protected system location on \
                         the host is unknown."
                            .to_owned(),
                    );
                }
                None => {}
            }
        }
        Ok(Self { roots: out })
    }

    /// Root holding the path: `(name, root path)`.
    #[must_use]
    pub fn containing(&self, path: &str) -> Option<(&str, &str)> {
        let norm = normalize_windows_path(path);
        if norm.is_empty() {
            return None;
        }
        // The administrative share is checked as a local path (ADR-0015).
        let norm = admin_share_local(&norm).unwrap_or(norm);
        self.roots.iter().find_map(|(name, root)| {
            let root_norm = normalize_windows_path(root);
            if root_norm.is_empty() {
                return None;
            }
            let prefix = if root_norm.ends_with('\\') {
                root_norm.clone()
            } else {
                format!("{root_norm}\\")
            };
            (norm == root_norm || norm.starts_with(&prefix))
                .then_some((name.as_str(), root.as_str()))
        })
    }
}

/// Refusal if the host-resolved path is lexically protected or lies inside a host root
/// (DR-6, TR-FS-06).
fn refuse_resolved(
    resolved: &str,
    roots: &HostRoots,
    requested: &str,
    verb: &str,
) -> Option<PolicyDecision> {
    if let Some(refusal) = refuse_short_name(resolved, requested, verb) {
        return Some(refusal);
    }
    if is_protected_path(resolved) {
        return Some(PolicyDecision::deny(
            format!(
                "refusing to {verb} a protected path (resolved by the host to {resolved}): {requested}"
            ),
            "PATH_PROTECTED",
        ));
    }
    roots.containing(resolved).map(|(name, root)| {
        PolicyDecision::deny(
            format!(
                "refusing to {verb} a protected path (resolved by the host to {resolved}, inside \
                 the {name} root {root}): {requested}"
            ),
            "PATH_PROTECTED",
        )
    })
}

/// Result of the pre-scan of a directory to delete, from the host.
///
/// `full_name` is the path as the Windows host resolved it: only the host expands 8.3
/// short names and maps a reparse point to its real target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteScan {
    /// Canonical path returned by the host.
    pub full_name: String,
    /// Directory is a junction or a symlink.
    pub is_reparse_point: bool,
    /// Items found in the subtree, files and directories together.
    pub total_items: i64,
    pub file_count: i64,
    pub dir_count: i64,
    /// Whether the subtree contains a reparse point.
    ///
    /// `Remove-Item -Recurse` in Windows PowerShell 5.1 can traverse a junction and delete
    /// its target, so a nested point is as much a refusal reason as a root one (DR-6).
    pub nested_reparse_point: bool,
    /// Protected host locations (TR-SEC-04, ADR-0015 §10).
    pub roots: HostRoots,
}

impl DeleteScan {
    /// # Errors
    ///
    /// Error text if the answer is not a JSON object or lacks the mandatory protective
    /// fields `FullName`, `IsReparsePoint`, `TotalItems`, `NestedReparsePoint`, and
    /// `Roots` with a non-empty `SystemRoot`. A missing protective field is not "safe by
    /// default" but an unreadable scan, so the caller must refuse (ADR-0005 §5,
    /// fail-closed).
    pub fn from_json(raw: &str) -> Result<Self, String> {
        let object = scan_object(raw)?;
        let full_name = required_str(&object, "FullName")?;
        let is_reparse_point = required_bool(&object, "IsReparsePoint")?;
        let total_items = object
            .get("TotalItems")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| "Pre-scan result is missing TotalItems.".to_owned())?;
        let nested_reparse_point = required_bool(&object, "NestedReparsePoint")?;
        let roots = HostRoots::from_scan(&object)?;
        Ok(Self {
            full_name,
            is_reparse_point,
            total_items,
            file_count: object
                .get("FileCount")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0),
            dir_count: object
                .get("DirCount")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0),
            nested_reparse_point,
            roots,
        })
    }
}

/// Result of the pre-scan of a single file, from the host.
///
/// Needed to refuse before sending the delete if the path resolved to a protected one or
/// turned out to be a directory (DR-6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileScan {
    /// Canonical path returned by the host.
    pub full_name: String,
    pub is_directory: bool,
    /// Protected host locations (TR-SEC-04, ADR-0015 §10).
    pub roots: HostRoots,
}

impl FileScan {
    ///
    /// # Errors
    ///
    /// Error text if the answer is not a JSON object or lacks the mandatory fields
    /// `FullName`, `IsDirectory`, and `Roots` with a non-empty `SystemRoot`.
    pub fn from_json(raw: &str) -> Result<Self, String> {
        let object = scan_object(raw)?;
        Ok(Self {
            full_name: required_str(&object, "FullName")?,
            is_directory: required_bool(&object, "IsDirectory")?,
            roots: HostRoots::from_scan(&object)?,
        })
    }
}

/// Result of the scan of a write target, from the host (TR-FS-06).
///
/// The path is resolved twice because the write uses two mechanisms: .NET (`[IO.File]`)
/// writes the chunks and resolves a relative path from the process current directory,
/// while `Move-Item` replaces the target and resolves it from the PowerShell location.
/// Both are checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteScan {
    /// Path as PowerShell resolves it for `-LiteralPath`.
    pub full_name: String,
    /// Path as .NET (`[IO.Path]::GetFullPath`) resolves it.
    pub dotnet_full_name: String,
    pub exists: bool,
    pub roots: HostRoots,
}

impl WriteScan {
    ///
    /// # Errors
    ///
    /// Error text if `FullName`, `DotNetFullName`, `Exists`, or `Roots` with a non-empty
    /// `SystemRoot` is missing (fail-closed).
    pub fn from_json(raw: &str) -> Result<Self, String> {
        let object = scan_object(raw)?;
        Ok(Self {
            full_name: required_str(&object, "FullName")?,
            dotnet_full_name: required_str(&object, "DotNetFullName")?,
            exists: required_bool(&object, "Exists")?,
            roots: HostRoots::from_scan(&object)?,
        })
    }
}

/// Write scan verdict: a protected path in either of the two resolutions, then the
/// overwrite rule (TR-FS-03, TR-FS-06).
#[must_use]
pub fn decide_write_scan(scan: &WriteScan, requested: &str, overwrite: bool) -> PolicyDecision {
    for resolved in [&scan.full_name, &scan.dotnet_full_name] {
        if let Some(refusal) = refuse_resolved(resolved, &scan.roots, requested, "write to") {
            return refusal;
        }
    }
    decide_overwrite(requested, scan.exists, overwrite)
}

/// Verdict on the single-file scan result (DR-6).
#[must_use]
pub fn decide_file_delete(scan: &FileScan, requested: &str) -> PolicyDecision {
    if scan.is_directory {
        return PolicyDecision::deny(
            format!(
                "refusing to delete a directory with delete_file (use delete_directory): {requested}"
            ),
            "PATH_IS_DIRECTORY",
        );
    }
    if let Some(refusal) = refuse_resolved(&scan.full_name, &scan.roots, requested, "delete") {
        return refusal;
    }
    PolicyDecision::allow("file delete scan is safe")
}

/// Verdict on the pre-scan result (DR-6, ADR-0005 §5).
///
/// Checks the host canonical path (`FullName`) against the lexical list and the host roots,
/// the reparse point, and the safety item cap. Any failed check is a refusal.
#[must_use]
pub fn decide_delete_scan(scan: &DeleteScan, requested: &str, cap: i64) -> PolicyDecision {
    if let Some(refusal) = refuse_resolved(&scan.full_name, &scan.roots, requested, "delete") {
        return refusal;
    }
    if scan.is_reparse_point {
        return PolicyDecision::deny(
            format!("refusing to delete a reparse point (junction/symlink): {requested}"),
            "PATH_REPARSE_POINT",
        );
    }
    if scan.nested_reparse_point {
        return PolicyDecision::deny(
            format!(
                "refusing to delete: the subtree contains a reparse point (junction/symlink): {requested}"
            ),
            "NESTED_REPARSE_POINT",
        );
    }
    if scan.total_items > cap {
        return PolicyDecision::deny(
            format!(
                "directory contains {}+ items — exceeds safety cap of {cap}. Review the scan and set max_items higher if you are sure.",
                scan.total_items
            ),
            "TOO_MANY_ITEMS",
        );
    }
    PolicyDecision::allow("delete scan is safe")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn normalize_basic_forms() {
        let cases = [
            ("C:/Windows", "C:\\WINDOWS"),
            ("c:\\windows\\", "C:\\WINDOWS"),
            ("C:\\\\App\\\\logs", "C:\\APP\\LOGS"),
            ("\\\\?\\C:\\", "C:\\"),
            ("\\\\?\\C:\\Program Files", "C:\\PROGRAM FILES"),
            ("\\\\.\\C:\\Windows", "C:\\WINDOWS"),
            ("\\??\\C:\\", "C:\\"),
            ("\\??\\C:\\Windows", "C:\\WINDOWS"),
            ("\\??\\UNC\\server\\share", "\\\\SERVER\\SHARE"),
            ("F:\\", "F:\\"),
            ("\\\\server\\share", "\\\\SERVER\\SHARE"),
            ("\\\\server\\share\\", "\\\\SERVER\\SHARE"),
        ];
        for (raw, expected) in cases {
            assert_eq!(normalize_windows_path(raw), expected, "raw={raw:?}");
        }
    }

    #[test]
    fn normalize_preserves_unc_leading_double_backslash() {
        assert!(normalize_windows_path("//server/share").starts_with("\\\\"));
    }

    #[test]
    fn normalize_edge_forms() {
        let cases = [
            ("\\\\?\\UNC\\server\\share", "\\\\SERVER\\SHARE"),
            (
                "\\\\?\\UNC\\server\\share\\folder",
                "\\\\SERVER\\SHARE\\FOLDER",
            ),
            ("C:\\App\\..\\Windows", "C:\\WINDOWS"),
            ("C:\\Windows.", "C:\\WINDOWS"),
            ("C:\\Windows ", "C:\\WINDOWS"),
            ("C:\\Windows\\System32\\..\\..\\Windows", "C:\\WINDOWS"),
        ];
        for (raw, expected) in cases {
            assert_eq!(normalize_windows_path(raw), expected, "raw={raw:?}");
        }
    }

    #[test]
    fn protected_true_bypass_forms() {
        for path in [
            "\\\\?\\UNC\\server\\share",
            "\\\\?\\UNC\\server\\share\\",
            "C:\\App\\..\\Windows",
            "C:\\Windows.",
            "C:\\Windows ",
            "C:\\Windows\\System32\\..\\..\\Windows",
        ] {
            assert!(is_protected_path(path), "path={path:?}");
        }
    }

    #[test]
    fn protected_false_regression_forms() {
        for path in [
            "\\\\?\\UNC\\server\\share\\folder",
            "C:\\App\\logs",
            "\\\\server\\share\\folder",
        ] {
            assert!(!is_protected_path(path), "path={path:?}");
        }
    }

    #[test]
    fn protected_true_forms() {
        for path in [
            "C:/Windows",
            "c:\\windows\\",
            "\\\\?\\C:\\",
            "\\??\\C:\\",
            "\\??\\C:\\Windows",
            "F:\\",
            "C:\\Windows\\System32\\drivers",
            "\\\\?\\C:\\Program Files",
            "C:\\Users\\admin",
            "C:\\ProgramData",
            "Z:\\",
            "\\\\server\\share",
            "\\\\server\\share\\",
            "\\\\?\\Volume{12345678-1234-1234-1234-123456789abc}\\",
            "\\\\?\\Volume{12345678-1234-1234-1234-123456789abc}",
        ] {
            assert!(is_protected_path(path), "path={path:?}");
        }
    }

    #[test]
    fn protected_false_forms() {
        for path in [
            "C:\\App\\logs",
            "\\\\server\\share\\data",
            "\\\\server\\share\\data\\sub",
            "D:\\sites\\app",
            "\\\\?\\Volume{12345678-1234-1234-1234-123456789abc}\\folder",
            "\\??\\Volume{12345678-1234-1234-1234-123456789abc}\\folder",
        ] {
            assert!(!is_protected_path(path), "path={path:?}");
        }
    }

    #[test]
    fn volume_guid_root_protected_but_subdirs_not() {
        let root = "\\\\?\\Volume{12345678-1234-1234-1234-123456789abc}\\";
        assert!(is_protected_path(root));
        assert!(!is_protected_path(&format!("{root}folder")));
    }

    #[test]
    fn unc_share_root_protected_but_subdirs_not() {
        assert!(is_protected_path("\\\\server\\share"));
        assert!(is_protected_path("\\\\server\\share\\"));
        assert!(!is_protected_path("\\\\server\\share\\folder"));
    }

    #[test]
    fn protected_path_covers_subtree() {
        assert!(is_protected_path("C:\\Windows\\System32\\config\\SAM"));
    }

    /// AC-SEC05-1: an empty list allows only loopback literals; a name that only resolves
    /// to loopback is not a literal (TR-SEC-14).
    #[test]
    fn empty_allowlist_admits_only_loopback_literals() {
        for host in [
            "localhost",
            "LOCALHOST",
            " localhost ",
            "127.0.0.1",
            "127.1.2.3",
            "::1",
            "[::1]",
        ] {
            assert!(host_allowed(host, &[]), "loopback {host:?} must pass");
        }
        for host in [
            "anything.example.com",
            "localhost.example.com",
            "localhost.",
            "127.0.0.1.evil.com",
            "128.0.0.1",
            "10.0.0.1",
            "::2",
            "0.0.0.0",
            "",
        ] {
            assert!(!host_allowed(host, &[]), "{host:?} must be refused");
        }
    }

    /// AC-SEC05-4: the `*` entry allows any host, but only as its own entry (TR-SEC-14).
    #[test]
    fn star_admits_any_host() {
        assert!(host_allowed("anything.example.com", &hosts(&["*"])));
        assert!(host_allowed("10.0.0.1", &hosts(&["host1", "*"])));
        assert!(!host_allowed("web.example.com", &hosts(&["*.example.com"])));
    }

    /// AC-SEC05-5: a host that is not a name or an IP is refused with any list. `winrm-rs`
    /// truncates the string at `/`, `@`, `://` and `:port`, and a URL parser at `?` and
    /// `#`, so `evil.com/.corp.example` passed the suffix check and went to `evil.com`
    /// (ADR-0015).
    #[test]
    fn malformed_host_is_refused_by_any_allowlist() {
        for host in [
            "evil.com/.corp.example",
            "evil.com?.corp.example",
            "evil.com#.corp.example",
            "x.corp.example@evil.com",
            "http://evil.com",
            "evil.com:5985",
            "evil .corp.example",
            "evil.com\\.corp.example",
            "\u{212A}.corp.example",
            "evil.com%2f.corp.example",
            "a..corp.example",
            ".corp.example",
            "[evil.com]",
            "",
        ] {
            for list in [hosts(&[".corp.example"]), hosts(&["*"]), Vec::new()] {
                assert!(!host_allowed(host, &list), "{host:?} with {list:?}");
            }
            assert!(
                decide_host(host, &hosts(&["*"]))
                    .reason
                    .contains("not a host name or IP address"),
                "{host:?}"
            );
        }
        for host in [
            "web-01",
            "web.corp.example",
            "host_1",
            "10.0.0.1",
            "fe80::1",
            "[fe80::1]",
        ] {
            assert!(host_allowed(host, &hosts(&["*"])), "{host:?}");
        }
    }

    /// AC-SEC05-6: one list grammar for the variable and the `setup` flag.
    #[test]
    fn allowed_hosts_grammar() {
        assert_eq!(
            parse_allowed_hosts(" Host1 , .Corp.Example,,127.0.0.1,[::1],* ").expect("valid"),
            ["host1", ".corp.example", "127.0.0.1", "[::1]", "*"]
        );
        assert!(parse_allowed_hosts(" , ").expect("valid").is_empty());
        for bad in [
            "*.corp.example",
            "host one",
            "host\\x",
            ".",
            "..corp",
            "evil.com/.corp",
            "a:80",
        ] {
            assert_eq!(
                parse_allowed_hosts(&format!("ok,{bad}")),
                Err(bad.to_owned()),
                "{bad}"
            );
        }
    }

    /// A non-empty list does not add loopback: the operator listed the hosts himself.
    #[test]
    fn explicit_list_does_not_add_loopback() {
        assert!(!host_allowed("localhost", &hosts(&["web-server-01"])));
    }

    #[test]
    fn host_allowed_variants() {
        assert!(host_allowed("Web-Server-01", &hosts(&["web-server-01"])));
        assert!(host_allowed("web-server-01", &hosts(&["Web-Server-01"])));
        assert!(!host_allowed("other-host", &hosts(&["web-server-01"])));
        assert!(host_allowed("host.example.com", &hosts(&[".example.com"])));
        assert!(host_allowed("example.com", &hosts(&[".example.com"])));
        assert!(!host_allowed("notexample.com", &hosts(&[".example.com"])));
        assert!(host_allowed("  host1  ", &hosts(&["host1"])));
    }

    #[test]
    fn validate_port_range_and_passthrough() {
        for raw in [0, -1, 65536] {
            let error = validate_port(Some(raw)).expect_err("out of range");
            assert!(error.to_string().to_lowercase().contains("port"));
        }
        for raw in [1, 5985, 65535] {
            assert_eq!(validate_port(Some(raw)).expect("valid"), Some(raw));
        }
        assert_eq!(validate_port(None).expect("none"), None);
    }

    #[test]
    fn tls_decisions() {
        assert!(tls_decision(false, false).is_some());
        assert!(tls_decision(false, true).is_none());
        assert!(tls_decision(true, false).is_none());
    }

    /// TR-FS-02: write is guarded by the same list as delete. A tool that can overwrite a
    /// system file is equal to delete.
    #[test]
    fn write_is_refused_on_protected_paths() {
        for path in [
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\",
            "c:/windows/system32/config",
        ] {
            let decision = decide_write_path(path);
            assert!(!decision.allow, "must refuse {path}");
            assert_eq!(decision.code, "PATH_PROTECTED");
        }
        let decision = decide_write_path("C:\\Temp\\report.txt");
        assert!(decision.allow);
        assert_eq!(decision.code, "OK");
    }

    /// TR-FS-03: an existing file is replaced only with an explicit flag, while creating a
    /// new one needs nothing.
    #[test]
    fn overwrite_is_required_only_for_an_existing_file() {
        let denied = decide_overwrite("C:\\a.txt", true, false);
        assert!(!denied.allow);
        assert_eq!(denied.code, "FILE_EXISTS");
        assert!(
            denied.reason.contains("overwrite=true"),
            "{}",
            denied.reason
        );
        assert!(denied.reason.contains("C:\\a.txt"), "{}", denied.reason);

        assert!(decide_overwrite("C:\\a.txt", true, true).allow);
        assert!(decide_overwrite("C:\\a.txt", false, false).allow);
        assert!(decide_overwrite("C:\\a.txt", false, true).allow);
    }

    /// TR-FS-02: the refusal names writing, not deleting — otherwise the agent thinks it
    /// called the wrong tool.
    #[test]
    fn write_refusal_names_writing() {
        let decision = decide_write_path("C:\\Windows\\System32");
        assert!(
            decision.reason.contains("write"),
            "reason must name writing: {}",
            decision.reason
        );
        assert!(!decision.reason.contains("delete"), "{}", decision.reason);
    }

    #[test]
    fn decision_wrappers() {
        let denied = decide_host("evil", &hosts(&["good"]));
        assert!(!denied.allow);
        assert_eq!(denied.code, "HOST_NOT_ALLOWED");
        assert!(!denied.reason.is_empty());

        let allowed = decide_host("good", &hosts(&["good"]));
        assert!(allowed.allow);
        assert_eq!(allowed.code, "OK");

        assert_eq!(decide_port(Some(0)).code, "PORT_OUT_OF_RANGE");
        assert!(decide_port(Some(5985)).allow);

        assert_eq!(decide_tls(false, false).code, "TLS_VERIFY_NOT_ALLOWED");
        assert!(decide_tls(true, false).allow);

        assert_eq!(decide_delete_path("C:\\Windows").code, "PATH_PROTECTED");
        assert!(decide_delete_path("C:\\App\\logs").allow);
    }

    #[test]
    fn delete_scan_parses_host_json() {
        let scan = DeleteScan::from_json(
            r#"{"FullName":"C:\\App\\link","IsReparsePoint":true,"FileCount":2,"DirCount":1,"TotalItems":3,"NestedReparsePoint":false,"Roots":{"SystemRoot":"C:\\Windows"}}"#,
        )
        .expect("valid scan");
        assert_eq!(scan.full_name, "C:\\App\\link");
        assert!(scan.is_reparse_point);
        assert_eq!(scan.total_items, 3);
    }

    #[test]
    fn delete_scan_rejects_unreadable_json() {
        assert!(DeleteScan::from_json("not json").is_err());
        assert!(DeleteScan::from_json(r#"{"IsReparsePoint":false}"#).is_err());
        assert!(DeleteScan::from_json(r#"{"FullName":""}"#).is_err());
        // Fail-closed: a missing protective field is not "safe by default".
        assert!(DeleteScan::from_json(r#"{"FullName":"C:\\App"}"#).is_err());
        assert!(DeleteScan::from_json(r#"{"FullName":"C:\\App","TotalItems":1}"#).is_err());
        assert!(DeleteScan::from_json(r#"{"FullName":"C:\\App","IsReparsePoint":false}"#).is_err());
    }

    #[test]
    fn delete_scan_refuses_reparse_point() {
        // DR-6/AC-SEC04-2: a junction to a protected directory must not be deleted.
        let scan = DeleteScan {
            full_name: "C:\\App\\link".to_owned(),
            is_reparse_point: true,
            total_items: 1,
            file_count: 1,
            dir_count: 0,
            nested_reparse_point: false,
            roots: HostRoots::default(),
        };
        let decision = decide_delete_scan(&scan, "C:\\App\\link", 5000);
        assert!(!decision.allow);
        assert_eq!(decision.code, "PATH_REPARSE_POINT");
    }

    #[test]
    fn delete_scan_refuses_host_resolved_protected_path() {
        // The lexical form is not protected, but the host resolved the path into the system.
        let scan = DeleteScan {
            full_name: "C:\\Windows\\System32".to_owned(),
            is_reparse_point: false,
            total_items: 1,
            file_count: 1,
            dir_count: 0,
            nested_reparse_point: false,
            roots: HostRoots::default(),
        };
        let decision = decide_delete_scan(&scan, "C:\\App\\shortcut", 5000);
        assert!(!decision.allow);
        assert_eq!(decision.code, "PATH_PROTECTED");
    }

    #[test]
    fn delete_scan_refuses_over_cap() {
        let scan = DeleteScan {
            full_name: "C:\\App\\logs".to_owned(),
            is_reparse_point: false,
            total_items: 5001,
            file_count: 5000,
            dir_count: 1,
            nested_reparse_point: false,
            roots: HostRoots::default(),
        };
        let decision = decide_delete_scan(&scan, "C:\\App\\logs", 5000);
        assert!(!decision.allow);
        assert_eq!(decision.code, "TOO_MANY_ITEMS");
    }

    #[test]
    fn delete_scan_allows_ordinary_directory() {
        let scan = DeleteScan {
            full_name: "C:\\App\\logs".to_owned(),
            is_reparse_point: false,
            total_items: 10,
            file_count: 9,
            dir_count: 1,
            nested_reparse_point: false,
            roots: HostRoots::default(),
        };
        assert!(decide_delete_scan(&scan, "C:\\App\\logs", 5000).allow);
    }

    #[test]
    fn delete_scan_refuses_nested_reparse_point() {
        // The root is an ordinary directory, but a junction sits inside: a recursive delete
        // could escape into the target. DR-6 requires a refusal.
        let scan = DeleteScan {
            full_name: "C:\\App\\logs".to_owned(),
            is_reparse_point: false,
            total_items: 10,
            file_count: 9,
            dir_count: 1,
            nested_reparse_point: true,
            roots: HostRoots::default(),
        };
        let decision = decide_delete_scan(&scan, "C:\\App\\logs", 5000);
        assert!(!decision.allow);
        assert_eq!(decision.code, "NESTED_REPARSE_POINT");
    }

    #[test]
    fn delete_scan_requires_nested_reparse_field() {
        // Fail-closed: a scan without the nested-point marker is not readable.
        assert!(
            DeleteScan::from_json(
                r#"{"FullName":"C:\\App","IsReparsePoint":false,"TotalItems":1}"#
            )
            .is_err()
        );
        let scan = DeleteScan::from_json(
            r#"{"FullName":"C:\\App","IsReparsePoint":false,"TotalItems":1,"NestedReparsePoint":false,"Roots":{"SystemRoot":"C:\\Windows"}}"#,
        )
        .expect("valid scan");
        assert!(!scan.nested_reparse_point);
    }

    #[test]
    fn file_scan_parses_and_rejects_missing_fields() {
        let scan = FileScan::from_json(r#"{"FullName":"C:\\App\\a.txt","IsDirectory":false,"Roots":{"SystemRoot":"C:\\Windows"}}"#)
            .expect("valid scan");
        assert_eq!(scan.full_name, "C:\\App\\a.txt");
        assert!(!scan.is_directory);
        assert!(FileScan::from_json("not json").is_err());
        assert!(FileScan::from_json(r#"{"FullName":"C:\\a"}"#).is_err());
        assert!(FileScan::from_json(r#"{"FullName":"","IsDirectory":false}"#).is_err());
    }

    #[test]
    fn file_delete_refuses_directory_and_protected_path() {
        let directory = FileScan {
            full_name: "C:\\App\\logs".to_owned(),
            is_directory: true,
            roots: HostRoots::default(),
        };
        assert_eq!(
            decide_file_delete(&directory, "C:\\App\\logs").code,
            "PATH_IS_DIRECTORY"
        );

        let protected = FileScan {
            full_name: "C:\\Windows\\System32\\drivers\\etc\\hosts".to_owned(),
            is_directory: false,
            roots: HostRoots::default(),
        };
        assert_eq!(
            decide_file_delete(&protected, "C:\\App\\shortcut").code,
            "PATH_PROTECTED"
        );

        let ordinary = FileScan {
            full_name: "C:\\App\\a.txt".to_owned(),
            is_directory: false,
            roots: HostRoots::default(),
        };
        assert!(decide_file_delete(&ordinary, "C:\\App\\a.txt").allow);
    }

    fn roots(pairs: &[(&str, &str)]) -> HostRoots {
        HostRoots {
            roots: pairs
                .iter()
                .map(|(name, path)| ((*name).to_owned(), (*path).to_owned()))
                .collect(),
        }
    }

    /// AC-FS-07: the roots are read from the scan; an empty optional one is skipped, while
    /// an empty or missing `SystemRoot` is a refusal (ADR-0015 §11).
    #[test]
    fn host_roots_parse_and_require_system_root() {
        let scan = FileScan::from_json(
            r#"{"FullName":"D:\\App\\a.txt","IsDirectory":false,"Roots":{"SystemRoot":"D:\\Windows","ProgramFiles":"D:\\Program Files","ProgramFilesX86":null,"ProgramData":"","Users":"D:\\Users"}}"#,
        )
        .expect("valid scan");
        assert_eq!(
            scan.roots,
            roots(&[
                ("SystemRoot", "D:\\Windows"),
                ("ProgramFiles", "D:\\Program Files"),
                ("Users", "D:\\Users"),
            ])
        );
        for broken in [
            r#"{"FullName":"D:\\a","IsDirectory":false}"#,
            r#"{"FullName":"D:\\a","IsDirectory":false,"Roots":{}}"#,
            r#"{"FullName":"D:\\a","IsDirectory":false,"Roots":{"SystemRoot":""}}"#,
            r#"{"FullName":"D:\\a","IsDirectory":false,"Roots":{"SystemRoot":null,"ProgramFiles":"D:\\Program Files"}}"#,
        ] {
            assert!(FileScan::from_json(broken).is_err(), "{broken}");
        }
    }

    /// AC-FS-07: a system on `D:` is protected by its actual location, although the lexical
    /// list knows only `C:`.
    #[test]
    fn host_roots_cover_the_actual_system_location() {
        let system = roots(&[
            ("SystemRoot", "D:\\Windows"),
            ("ProgramData", "D:\\ProgramData"),
            ("Users", "D:\\Users"),
        ]);
        assert_eq!(
            system.containing("d:/windows/system32/drivers/etc/hosts"),
            Some(("SystemRoot", "D:\\Windows"))
        );
        assert_eq!(
            system.containing("D:\\Windows"),
            Some(("SystemRoot", "D:\\Windows"))
        );
        assert_eq!(
            system.containing("D:\\Users\\alice\\notes.txt"),
            Some(("Users", "D:\\Users"))
        );
        assert_eq!(system.containing("D:\\WindowsApps\\x"), None);
        assert_eq!(system.containing("D:\\App\\x"), None);
        assert_eq!(system.containing(""), None);
    }

    /// AC-SEC04-6: a path with an 8.3 name cannot be compared with the list as a string
    /// (`C:\PROGRA~1` is `C:\Program Files`), so write and delete refuse it — both
    /// lexically and after the host resolves it (ADR-0015).
    #[test]
    fn short_names_are_refused_for_write_and_delete() {
        for path in [
            "C:\\PROGRA~1\\app\\x.dll",
            "d:/progra~2/x",
            "C:\\Users\\ALICE~1\\a.txt",
        ] {
            assert_eq!(decide_write_path(path).code, "PATH_PROTECTED", "{path}");
            assert_eq!(decide_delete_path(path).code, "PATH_PROTECTED", "{path}");
            assert!(decide_write_path(path).reason.contains("8.3"), "{path}");
        }
        for path in [
            "C:\\App\\backup~old.txt",
            "C:\\App\\~1",
            "C:\\App\\x~y1.txt",
        ] {
            assert!(decide_write_path(path).allow, "{path}");
        }
        let resolved = FileScan {
            full_name: "D:\\PROGRA~1\\x.dll".to_owned(),
            is_directory: false,
            roots: roots(&[("SystemRoot", "D:\\Windows")]),
        };
        assert_eq!(
            decide_file_delete(&resolved, "x.dll").code,
            "PATH_PROTECTED"
        );
        let write = write_scan("D:\\App\\x", "D:\\PROGRA~1\\x", false);
        assert_eq!(decide_write_scan(&write, "x", false).code, "PATH_PROTECTED");
    }

    /// AC-SEC04-7: the administrative share `\\host\C$\...` is protected as `C:\...`.
    #[test]
    fn admin_share_is_checked_as_its_local_path() {
        for path in [
            "\\\\localhost\\C$\\Windows\\System32\\x.dll",
            "\\\\127.0.0.1\\c$\\program files\\x",
            "//server/C$/Users/alice/a.txt",
        ] {
            assert!(is_protected_path(path), "{path}");
            assert_eq!(decide_write_path(path).code, "PATH_PROTECTED", "{path}");
        }
        // `ADMIN$` is `%SystemRoot%`, `PRINT$` sits inside it.
        for path in [
            "\\\\localhost\\ADMIN$\\System32\\x.dll",
            "\\\\host\\admin$",
            "//host/PRINT$/x64/x.dll",
            "\\\\dc01\\SYSVOL\\corp.example\\scripts\\logon.ps1",
            "\\\\dc01\\netlogon\\logon.bat",
        ] {
            assert!(is_protected_path(path), "{path}");
            assert_eq!(decide_delete_path(path).code, "PATH_PROTECTED", "{path}");
        }
        assert!(!is_protected_path("\\\\server\\C$\\App\\x"));
        assert!(!is_protected_path("\\\\server\\share\\Windows\\x"));
        let system = roots(&[("SystemRoot", "D:\\Windows")]);
        assert_eq!(
            system.containing("\\\\localhost\\D$\\Windows\\Temp"),
            Some(("SystemRoot", "D:\\Windows"))
        );
    }

    /// AC-SEC04-5: delete refuses a path inside a host root.
    #[test]
    fn delete_scans_refuse_paths_inside_host_roots() {
        let system = roots(&[("SystemRoot", "D:\\Windows")]);
        let file = FileScan {
            full_name: "D:\\Windows\\System32\\kernel32.dll".to_owned(),
            is_directory: false,
            roots: system.clone(),
        };
        let decision = decide_file_delete(&file, "D:\\Windows\\System32\\kernel32.dll");
        assert_eq!(decision.code, "PATH_PROTECTED");
        assert!(
            decision.reason.contains("SystemRoot"),
            "{}",
            decision.reason
        );

        let directory = DeleteScan {
            full_name: "D:\\Windows\\Temp".to_owned(),
            is_reparse_point: false,
            total_items: 1,
            file_count: 1,
            dir_count: 0,
            nested_reparse_point: false,
            roots: system,
        };
        assert_eq!(
            decide_delete_scan(&directory, "D:\\Windows\\Temp", 5000).code,
            "PATH_PROTECTED"
        );
    }

    fn write_scan(full: &str, dotnet: &str, exists: bool) -> WriteScan {
        WriteScan {
            full_name: full.to_owned(),
            dotnet_full_name: dotnet.to_owned(),
            exists,
            roots: roots(&[
                ("SystemRoot", "D:\\Windows"),
                ("ProgramFiles", "D:\\Program Files"),
            ]),
        }
    }

    /// AC-FS-07: write is refused if either of the two path resolutions lands in a host
    /// root, while an ordinary path passes to the overwrite rule.
    #[test]
    fn write_scan_checks_both_resolutions_and_then_overwrite() {
        let inside_ps = write_scan("D:\\Windows\\x.ps1", "D:\\App\\x.ps1", false);
        assert_eq!(
            decide_write_scan(&inside_ps, "x.ps1", false).code,
            "PATH_PROTECTED"
        );
        let inside_net = write_scan("D:\\App\\x.ps1", "D:\\Program Files\\x.ps1", false);
        assert_eq!(
            decide_write_scan(&inside_net, "x.ps1", false).code,
            "PATH_PROTECTED"
        );
        let lexical = write_scan("C:\\Windows\\x.ps1", "C:\\Windows\\x.ps1", false);
        assert_eq!(
            decide_write_scan(&lexical, "x.ps1", false).code,
            "PATH_PROTECTED"
        );

        let fresh = write_scan("D:\\App\\x.ps1", "D:\\App\\x.ps1", false);
        assert!(decide_write_scan(&fresh, "D:\\App\\x.ps1", false).allow);
        let existing = write_scan("D:\\App\\x.ps1", "D:\\App\\x.ps1", true);
        assert_eq!(
            decide_write_scan(&existing, "D:\\App\\x.ps1", false).code,
            "FILE_EXISTS"
        );
        assert!(decide_write_scan(&existing, "D:\\App\\x.ps1", true).allow);
    }

    #[test]
    fn write_scan_parses_and_fails_closed() {
        let scan = WriteScan::from_json(
            r#"{"FullName":"D:\\App\\x","DotNetFullName":"D:\\App\\x","Exists":true,"Roots":{"SystemRoot":"D:\\Windows"}}"#,
        )
        .expect("valid scan");
        assert!(scan.exists);
        assert_eq!(scan.dotnet_full_name, "D:\\App\\x");
        for broken in [
            "not json",
            r#"{"FullName":"D:\\App\\x","Exists":true,"Roots":{"SystemRoot":"D:\\Windows"}}"#,
            r#"{"FullName":"D:\\App\\x","DotNetFullName":"D:\\App\\x","Roots":{"SystemRoot":"D:\\Windows"}}"#,
            r#"{"FullName":"D:\\App\\x","DotNetFullName":"D:\\App\\x","Exists":false}"#,
        ] {
            assert!(WriteScan::from_json(broken).is_err(), "{broken}");
        }
    }
}
