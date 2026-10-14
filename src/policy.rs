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
    /// The operator allowlist entry that permitted an otherwise protected target
    /// (ADR-0017 §39). `None` for every other decision.
    pub matched: Option<String>,
    /// The category of a protected target for the confirmation warning line
    /// (ADR-0017 §36). `None` for every other decision.
    pub class: Option<&'static str>,
}

impl PolicyDecision {
    fn allow(reason: impl Into<String>) -> Self {
        Self {
            allow: true,
            reason: reason.into(),
            code: "OK",
            matched: None,
            class: None,
        }
    }

    fn deny(reason: impl Into<String>, code: &'static str) -> Self {
        Self {
            allow: false,
            reason: reason.into(),
            code,
            matched: None,
            class: None,
        }
    }

    /// Records the allowlist entry that lifted a protected-path refusal (ADR-0017 §39).
    fn allowed_by(mut self, entry: String, class: Option<&'static str>) -> Self {
        self.matched = Some(entry);
        self.class = class;
        self
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
                "the tool refuses to {verb} {requested:?}: {component} is an 8.3 short name, and the \
                 tool cannot check a short name against the protected paths. Pass the long name."
            ),
            "PATH_PROTECTED",
        )
    })
}

/// Refusal for a device volume or GLOBALROOT path (ADR-0015).
///
/// `\\?\Volume{GUID}\...` and `\\?\GLOBALROOT` (any device prefix) do not reduce to a
/// volume letter, so the lexical list cannot see the system inside them. The write and
/// the delete refuse them in any written form.
fn refuse_device_volume(path: &str, requested: &str, verb: &str) -> Option<PolicyDecision> {
    is_device_volume_path(path).then(|| {
        PolicyDecision::deny(
            format!(
                "the tool refuses to {verb} {requested:?}: the path names a device volume or \
                 GLOBALROOT, and the tool cannot compare it with the protected paths. Pass a drive \
                 path such as C:\\..."
            ),
            "PATH_PROTECTED",
        )
    })
}

/// True for `\\?\Volume{...}`, `\\?\GLOBALROOT` and `\\.\GLOBALROOT` (with `\??\` accepted).
///
/// The path is trimmed and its separators are folded first, because the device prefix is
/// what hides the volume from the lexical list.
#[must_use]
pub fn is_device_volume_path(path: &str) -> bool {
    let p = path.trim().replace('/', "\\");
    for prefix in DEVICE_PREFIXES {
        let Some(head) = p.get(..prefix.len()) else {
            continue;
        };
        if !head.eq_ignore_ascii_case(prefix) {
            continue;
        }
        let rest = p[prefix.len()..].to_ascii_lowercase();
        if rest.starts_with("volume{") || rest.starts_with("globalroot") {
            return true;
        }
    }
    false
}

/// Form of the write allowlist for the refusal text (DR-8).
pub const WRITE_ALLOW_PATHS_FORM: &str = "a comma-separated list of absolute directory paths, each a drive path such as C:\\Logs or a UNC share such as \\\\server\\share, without a wildcard, an 8.3 component or a '..' component";

/// One grammar for `WINRIG_WRITE_ALLOW_PATHS` (ADR-0017 §7, §11, DR-8).
///
/// Comma-separated directory entries, empty ones skipped. An entry must be an
/// absolute path with a drive or a UNC `\\server\share` root. A relative path, a bare
/// drive letter (`C:`), a UNC server without a share, a wildcard, a control character,
/// an 8.3 component and a `..` component refuse the start. A system directory and a
/// volume root are lawful entries, because the operator takes that risk (ADR-0017 §11).
///
/// # Errors
///
/// The first entry that is not an absolute directory path; the caller names the
/// variable.
pub fn parse_write_allow_paths(raw: &str) -> Result<Vec<String>, String> {
    let mut entries = Vec::new();
    for item in raw.split(',') {
        let entry = item.trim();
        if entry.is_empty() {
            continue;
        }
        if !is_write_allow_entry(entry) {
            return Err(entry.to_owned());
        }
        entries.push(entry.to_owned());
    }
    Ok(entries)
}

/// A raw component of `..` in the entry, which could climb above its own start.
fn has_parent_component(path: &str) -> bool {
    path.replace('/', "\\")
        .split('\\')
        .any(|component| component == "..")
}

/// True for an absolute directory path: `X:\...` or `\\server\share...`.
///
/// The entry is normalized first, so `/` and the `\\?\` prefix are accepted and the
/// wildcard check runs on the stripped form. A bare drive letter such as `C:`
/// normalizes without a separator and is refused, a UNC entry needs a server and a
/// share, an 8.3 component cannot be compared against the list, a `..` component
/// could climb above the entry's own start, and a component with a trailing dot or
/// space is ambiguous.
fn is_write_allow_entry(entry: &str) -> bool {
    if short_name_component(entry).is_some()
        || has_parent_component(entry)
        || has_ambiguous_component(entry)
    {
        return false;
    }
    let norm = normalize_windows_path(entry);
    if norm.is_empty() || norm.chars().any(|c| c.is_control() || c == '*' || c == '?') {
        return false;
    }
    let bytes = norm.as_bytes();
    let drive =
        bytes.len() >= 3 && bytes[0].is_ascii_uppercase() && bytes[1] == b':' && bytes[2] == b'\\';
    if drive {
        return true;
    }
    // A UNC entry needs a server and a share; `\\fs01` alone is not a directory.
    let Some(rest) = norm.strip_prefix("\\\\") else {
        return false;
    };
    let mut parts = rest.split('\\');
    let server = parts.next().unwrap_or_default();
    let share = parts.next().unwrap_or_default();
    !server.is_empty() && !share.is_empty()
}

/// True when every character folds to a single character under simple case mapping.
///
/// `normalize_windows_path` uses the full Unicode upper case, which expands some
/// characters (`ß` → `SS`, the ligature `ﬃ` → `FFI`). NTFS folds a character to one
/// character, so `Straße` and `Strasse` are different files. An entry that needs an
/// expansion must not match, or the allowlist would be wider than the file system.
fn allow_case_safe(path: &str) -> bool {
    path.chars().all(|c| c.to_uppercase().count() == 1)
}

/// True when a component of `path` ends with a dot or a space, after the device prefix.
///
/// Only the `\\?\` form keeps a trailing dot or space; the Win32 form strips it, so a
/// target with one is ambiguous. The allowlist refuses such a target rather than guess.
fn has_ambiguous_component(path: &str) -> bool {
    let p = path.replace('/', "\\");
    let mut rest = p.as_str();
    for prefix in DEVICE_PREFIXES {
        if p.get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
        {
            rest = p.get(prefix.len()..).unwrap_or_default();
            break;
        }
    }
    rest.split('\\').any(|component| {
        !component.is_empty()
            && component != "."
            && component != ".."
            && (component.ends_with('.') || component.ends_with(' '))
    })
}

/// The allowlist entry that covers `path`, if any (ADR-0017 §7).
///
/// Both sides are normalized with `normalize_windows_path`, so the comparison folds
/// the case, the separators and the trailing dots and spaces. The match is a prefix at
/// a path-component boundary: `C:\Logs` covers `C:\Logs\x`, does not cover `C:\Logs2\x`,
/// and does not cover `C:\Logs` itself. A file operation acts on a strict descendant of
/// its entry; only a root entry (a volume root or a UNC share root) covers itself. A
/// component that collapses to more than one character under case folding, or that ends
/// with a dot or a space, is not covered (the comparison must not be wider than NTFS).
#[must_use]
pub fn write_path_allowed(path: &str, allowed: &[String]) -> Option<String> {
    if !allow_case_safe(path) || has_ambiguous_component(path) {
        return None;
    }
    let norm = normalize_windows_path(path);
    if norm.is_empty() {
        return None;
    }
    allowed.iter().find_map(|raw| {
        if !allow_case_safe(raw) || has_ambiguous_component(raw) {
            return None;
        }
        let entry = normalize_windows_path(raw);
        if entry.is_empty() {
            return None;
        }
        let prefix = if entry.ends_with('\\') {
            entry.clone()
        } else {
            format!("{entry}\\")
        };
        let root = is_volume_root(&entry) || is_unc_share_root(&entry);
        (norm.starts_with(&prefix) || (root && norm == entry)).then(|| raw.trim().to_owned())
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
            "the request disables the TLS certificate check and WINRIG_ALLOW_INSECURE_TLS \
             does not allow this connection",
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

/// Form of the command allowlist for the refusal text.
pub const ALLOWED_COMMANDS_FORM: &str = "a comma-separated list of command prefixes";

/// One grammar for `WINRIG_ALLOWED_COMMANDS` (ADR-0013 §13).
///
/// Comma-separated entries, empty ones skipped. An entry that holds a control
/// character can never match one command line, so the parser refuses it.
///
/// # Errors
///
/// The first entry that holds a control character; the caller names the variable.
pub fn parse_allowed_commands(raw: &str) -> Result<Vec<String>, String> {
    let mut entries = Vec::new();
    for item in raw.split(',') {
        let entry = item.trim();
        if entry.is_empty() {
            continue;
        }
        if entry.chars().any(char::is_control) {
            return Err(entry.to_owned());
        }
        entries.push(entry.to_owned());
    }
    Ok(entries)
}

/// Allowlist verdict for one command (TR-EXE-02, ADR-0013 §13).
///
/// An empty list admits any command. A non-empty list admits a command that
/// begins with one entry, after a trim and an ASCII case fold, because PowerShell
/// resolves a command name without case. The list is not a boundary: a leading
/// `&`, `.` or `powershell -c`, an alias, a call operator and an encoded command
/// all start with text the list need not contain, and a script written with
/// `write_file` and then started defeats it (ADR-0013 §18). It protects against an
/// accidental command, not against intent.
#[must_use]
pub fn command_allowed(command: &str, allowed_commands: &[String]) -> bool {
    if allowed_commands.is_empty() {
        return true;
    }
    let candidate = command.trim().to_ascii_lowercase();
    allowed_commands.iter().any(|entry| {
        let entry = entry.trim().to_ascii_lowercase();
        !entry.is_empty() && candidate.starts_with(&entry)
    })
}

/// The refusal never echoes the command text, because a command can carry a secret
/// and the reason reaches the audit (DR-4).
#[must_use]
pub fn decide_command(command: &str, allowed_commands: &[String]) -> PolicyDecision {
    if command_allowed(command, allowed_commands) {
        PolicyDecision::allow("command is allowed")
    } else {
        PolicyDecision::deny(
            "the command is not in WINRIG_ALLOWED_COMMANDS; add a prefix, or leave the list \
             empty to allow any command"
                .to_owned(),
            "COMMAND_NOT_ALLOWED",
        )
    }
}

/// Length verdict for one command, in UTF-16 units, against the WinRS budget
/// (TR-REL-10, TR-EXE-04).
///
/// The unit count matches `ps::command_line_chars`, which encodes the script as
/// UTF-16LE, so the limit and the check count the same units.
#[must_use]
pub fn decide_command_length(command: &str, max_units: usize) -> PolicyDecision {
    let units = command.encode_utf16().count();
    if units > max_units {
        PolicyDecision::deny(
            format!(
                "the command is {units} UTF-16 units, above the limit of {max_units}; the encoded \
                 wrapper must fit one WinRS command line. Shorten the command, or write it with \
                 write_file and run it by path"
            ),
            "COMMAND_TOO_LONG",
        )
    } else {
        PolicyDecision::allow("command fits one WinRS command line")
    }
}

/// Size verdict for one script, in bytes, against the write budget (TR-EXE-06).
///
/// The script travels to the host in the same chunks as `write_file`, so it obeys
/// the same `WINRIG_MAX_WRITE_BYTES` limit. The refusal reaches the audit before
/// the network and names the limit.
#[must_use]
pub fn decide_script_size(bytes: usize, max_bytes: usize) -> PolicyDecision {
    if bytes > max_bytes {
        PolicyDecision::deny(
            format!(
                "the script is {bytes} bytes, above the limit of {max_bytes}; raise \
                 WINRIG_MAX_WRITE_BYTES or shorten the script"
            ),
            "SCRIPT_TOO_LONG",
        )
    } else {
        PolicyDecision::allow("script fits the write budget")
    }
}

/// The lexical verdict of `delete_directory`, before the network (DR-6).
///
/// A recursive deletion does not consult the operator allowlist: DR-6 keeps its
/// refusals of a volume root, a system directory and a reparse point in full
/// (ADR-0017 §13). A device volume or GLOBALROOT path is refused: the lexical list
/// cannot see the system inside it.
#[must_use]
pub fn decide_delete_path(path: &str) -> PolicyDecision {
    if let Some(refusal) = refuse_device_volume(path, path, "delete") {
        return refusal;
    }
    if let Some(refusal) = refuse_short_name(path, path, "delete") {
        return refusal;
    }
    if is_protected_path(path) {
        PolicyDecision::deny(
            format!("the tool refuses to delete a protected path: {path:?}"),
            "PATH_PROTECTED",
        )
    } else {
        PolicyDecision::allow("path is not protected")
    }
}

/// File write verdict on the requested path, before the network (TR-FS-02,
/// TR-FS-07).
///
/// The list is the same as for delete: being able to overwrite a system file is no
/// different in effect from being able to delete it. An operator allowlist entry
/// that covers the path lifts the refusal (ADR-0017 §9).
#[must_use]
pub fn decide_write_path(path: &str, allowed: &[String]) -> PolicyDecision {
    decide_write_boundary(
        path,
        &[path],
        &HostRoots::default(),
        None,
        false,
        "write to",
        allowed,
    )
}

/// The lexical verdict of `delete_file` on the requested path, before the network
/// (ADR-0017 §9).
///
/// `delete_file` consults the allowlist; `delete_directory` does not
/// ([`decide_delete_path`]).
#[must_use]
pub fn decide_delete_file_path(path: &str, allowed: &[String]) -> PolicyDecision {
    decide_write_boundary(
        path,
        &[path],
        &HostRoots::default(),
        None,
        false,
        "delete",
        allowed,
    )
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

/// These values belong to devices, not files, in every directory (TR-FS-10).
///
/// A file name equal to one of these, with or without an extension, is refused: the
/// host would ignore the part after it and reach the device instead (for example
/// `NUL.txt` writes into the null device).
pub const RESERVED_NAMES: [&str; 32] = [
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "CONIN$",
    "CONOUT$",
    "COM0",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "COM\u{00b9}",
    "COM\u{00b2}",
    "COM\u{00b3}",
    "LPT0",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
    "LPT\u{00b9}",
    "LPT\u{00b2}",
    "LPT\u{00b3}",
];

/// A value such as `CON` or `COM1` names a device in every directory, with or
/// without an extension (TR-FS-10).
///
/// The base before the first dot is compared after its trailing spaces are dropped,
/// because Win32 ignores them: `NUL .txt` reaches the null device.
#[must_use]
pub fn is_reserved_new_name(name: &str) -> bool {
    let base = name.split('.').next().unwrap_or(name).trim_end();
    RESERVED_NAMES
        .iter()
        .any(|reserved| reserved.eq_ignore_ascii_case(base))
}

/// The refusal text of `rename_file` states this grammar (DR-8).
pub const NEW_NAME_FORM: &str = "one file name without a directory separator, a reserved device name (CON, NUL, COM1, ...), a trailing dot or space, or any of < > : \" / \\ | ? *";

/// Verdict on the new name of `rename_file` (TR-FS-10, ADR-0017 §19).
///
/// The tool changes the last path component, so the name must be a name and not a
/// path: a separator, a `.`/`..` component, a device name, an invalid character, a
/// trailing dot or space, and a wildcard are all refused before the network.
#[must_use]
pub fn decide_new_name(name: &str) -> PolicyDecision {
    if name.is_empty() {
        return PolicyDecision::deny(
            "the new name is empty; pass one file name".to_owned(),
            "RENAME_NAME_INVALID",
        );
    }
    let invalid_char = name.chars().any(|c| {
        c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
    });
    if name == "." || name == ".." || invalid_char || name.ends_with(['.', ' ']) {
        return PolicyDecision::deny(
            format!("the new name {name:?} is not valid; expected {NEW_NAME_FORM}"),
            "RENAME_NAME_INVALID",
        );
    }
    if short_name_component(name).is_some() {
        return PolicyDecision::deny(
            format!(
                "the new name {name:?} has an 8.3 component; pass the long name so it can be \
                 compared against the protected paths"
            ),
            "RENAME_NAME_INVALID",
        );
    }
    if is_reserved_new_name(name) {
        return PolicyDecision::deny(
            format!("the new name {name:?} is a reserved device name; expected {NEW_NAME_FORM}"),
            "RENAME_NAME_INVALID",
        );
    }
    PolicyDecision::allow("the new name is one valid file name")
}

/// The volume a path sits on: `C:` for a drive path, `\\SERVER\SHARE` for a UNC path.
///
/// The value is the normalized, case-folded root, so two paths on one volume compare
/// equal (ADR-0017 §18). A relative path and a bare drive letter give `None`, and the
/// caller then treats the move as cross-volume.
#[must_use]
pub fn volume_of(path: &str) -> Option<String> {
    let norm = normalize_windows_path(path);
    let bytes = norm.as_bytes();
    if bytes.len() >= 3 && bytes[0].is_ascii_uppercase() && bytes[1] == b':' && bytes[2] == b'\\' {
        return Some(norm[..2].to_owned());
    }
    let rest = norm.strip_prefix("\\\\")?;
    let mut parts = rest.split('\\');
    let server = parts.next().unwrap_or_default();
    let share = parts.next().unwrap_or_default();
    (!server.is_empty() && !share.is_empty()).then(|| format!("\\\\{server}\\{share}"))
}

/// Two paths on one drive or on one UNC share sit on one volume; an undetermined
/// volume is never equal to another (ADR-0017 §18).
#[must_use]
pub fn same_volume(source: &str, target: &str) -> bool {
    match (volume_of(source), volume_of(target)) {
        (Some(from), Some(to)) => from == to,
        _ => false,
    }
}

/// Verdict on the volume relation of `move_file` (TR-FS-10, ADR-0017 §18).
///
/// One volume renames the object. Across volumes a file is copied and then deleted;
/// a directory is refused, because the implied recursive delete falls under DR-6 and
/// a partial move would leave two trees. The operator copies the directory and deletes
/// the source with two calls.
#[must_use]
pub fn decide_move_volume(source: &str, target: &str, is_directory: bool) -> PolicyDecision {
    let same = same_volume(source, target);
    if is_directory && !same {
        return PolicyDecision::deny(
            "the tool refuses a cross-volume move of a directory: the implied recursive delete \
             falls under DR-6 (ADR-0017 §18). Copy the directory and delete the source with two \
             calls."
                .to_owned(),
            "CROSS_VOLUME_MOVE",
        );
    }
    if same {
        PolicyDecision::allow("the move stays on one volume and renames the object")
    } else {
        PolicyDecision::allow("the move crosses volumes and copies then deletes the source")
    }
}

/// Verdict on a `create_directory` target (TR-FS-11, ADR-0017 §20).
///
/// An existing file or directory is refused with a clear message: the tool creates
/// only a missing directory. Otherwise the final path and the shallowest absent level
/// (`top_missing`) pass the write boundary, because every created level must lie
/// inside it. The strict-descendant rule of the boundary applies to the shallowest
/// level, so a created ancestor outside an allowlist entry is refused.
#[must_use]
pub fn decide_create_directory(
    scan: &WriteScan,
    requested: &str,
    top_missing: Option<&str>,
    allowed: &[String],
) -> PolicyDecision {
    if scan.exists {
        let kind = if scan.is_directory {
            "directory"
        } else {
            "file"
        };
        return PolicyDecision::deny(
            format!(
                "the {kind} {requested} already exists; create_directory creates only a missing \
                 directory"
            ),
            "TARGET_EXISTS",
        );
    }
    let boundary = decide_write_boundary(
        requested,
        &[&scan.full_name, &scan.dotnet_full_name],
        &scan.roots,
        scan.link_type.as_deref(),
        false,
        "create a directory at",
        allowed,
    );
    if !boundary.allow {
        return boundary;
    }
    let Some(top) = top_missing.filter(|top| *top != requested) else {
        return boundary;
    };
    let top_decision = boundary_decide(
        top,
        &[top],
        &scan.roots,
        None,
        false,
        "create a directory at",
        allowed,
    );
    if !top_decision.allow {
        return top_decision;
    }
    match (&boundary.matched, &top_decision.matched) {
        (None, Some(entry)) => PolicyDecision::allow("the created levels are inside the allowlist")
            .allowed_by(entry.clone(), top_decision.class),
        _ => boundary,
    }
}

/// True when two paths name the same object in a different case, so a move is a
/// case-only rename and needs two steps (TR-FS-10).
///
/// The comparison uses the normalized paths, so `a.txt` and `A.TXT` are one object;
/// the raw strings must differ, or it is the same path and not a rename.
#[must_use]
pub fn is_case_only_change(source: &str, target: &str) -> bool {
    let from = normalize_windows_path(source);
    let to = normalize_windows_path(target);
    !from.is_empty() && from == to && source != target
}

/// Verdict on the relation of a file-operation source and target (TR-FS-09/10).
///
/// A copy or a move onto the same path, into the source's own subtree, or (for a
/// directory) out of the target's subtree would recurse or overwrite the source in a
/// way the run-time checks cannot make safe. The comparison uses the normalized and
/// case-folded paths.
#[must_use]
pub fn decide_path_relation(source: &str, target: &str, is_directory: bool) -> PolicyDecision {
    let from = normalize_windows_path(source);
    let to = normalize_windows_path(target);
    if from.is_empty() || to.is_empty() {
        return PolicyDecision::allow("the relation cannot be decided from an empty path");
    }
    if from == to {
        return PolicyDecision::deny(
            "the tool refuses the operation: the source and the target are the same path"
                .to_owned(),
            "SAME_PATH",
        );
    }
    if to.starts_with(&format!("{from}\\")) {
        return PolicyDecision::deny(
            "the tool refuses the operation: the target is inside the source".to_owned(),
            "TARGET_INSIDE_SOURCE",
        );
    }
    if is_directory && from.starts_with(&format!("{to}\\")) {
        return PolicyDecision::deny(
            "the tool refuses the operation: the source is inside the target".to_owned(),
            "SOURCE_INSIDE_TARGET",
        );
    }
    PolicyDecision::allow("the source and the target are separate")
}

/// Result of the pre-scan of a source of a file operation, from the host (ADR-0017
/// §16–20).
///
/// The counts describe a directory source for the prompt; a file source reports one
/// file and its length in `byte_count`. `nested_link` marks a symbolic link or a
/// junction anywhere in the subtree, which a recursive copy would follow. `truncated`
/// marks a tree larger than the scan cap, so the counts are lower bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceScan {
    /// Canonical path returned by the host.
    pub full_name: String,
    pub is_directory: bool,
    /// `LinkType` of the final component (ADR-0017 §10).
    pub link_type: Option<String>,
    /// The subtree holds a symbolic link or a junction (ADR-0017 §17).
    pub nested_link: bool,
    /// The scan hit the item cap, so the counts are lower bounds.
    pub truncated: bool,
    /// The walk of a directory source reported an error, so the tree is not fully
    /// readable and a recursive copy would be partial.
    pub unreadable: bool,
    pub file_count: i64,
    pub dir_count: i64,
    /// Sum of the file lengths under the source, or the length of a file source.
    pub byte_count: i64,
    pub roots: HostRoots,
}

impl SourceScan {
    ///
    /// # Errors
    ///
    /// Error text if the answer is not a JSON object or lacks the mandatory fields
    /// `FullName`, `IsDirectory`, `NestedLink`, `Truncated`, `Unreadable`, and `Roots`
    /// with a non-empty `SystemRoot` (fail-closed). `LinkType` is optional.
    pub fn from_json(raw: &str) -> Result<Self, String> {
        let object = scan_object(raw)?;
        Ok(Self {
            full_name: required_str(&object, "FullName")?,
            is_directory: required_bool(&object, "IsDirectory")?,
            link_type: optional_str(&object, "LinkType"),
            nested_link: required_bool(&object, "NestedLink")?,
            truncated: required_bool(&object, "Truncated")?,
            unreadable: required_bool(&object, "Unreadable")?,
            file_count: object
                .get("FileCount")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0),
            dir_count: object
                .get("DirCount")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0),
            byte_count: object
                .get("ByteCount")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0),
            roots: HostRoots::from_scan(&object)?,
        })
    }
}

/// Verdict on the source of a file operation (TR-FS-09, TR-FS-10).
///
/// A copy reads the source, so a source under a protected root is allowed (§16). The
/// source is still refused when it is a device volume path, an 8.3 name or a name
/// surrogate, because the tool would act on the link target. A directory source that
/// holds a name surrogate is refused when the operation recurses (`reject_nested_link`),
/// because a recursive copy would follow it. A move or a rename removes the source, so
/// `removes_source` makes the source obey the write boundary and its allowlist.
#[must_use]
pub fn decide_file_op_source(
    scan: &SourceScan,
    requested: &str,
    removes_source: bool,
    reject_nested_link: bool,
    allowed: &[String],
) -> PolicyDecision {
    let verb = if removes_source { "move" } else { "copy" };
    for candidate in std::iter::once(requested).chain([scan.full_name.as_str()]) {
        if let Some(refusal) = refuse_device_volume(candidate, requested, verb) {
            return refusal;
        }
        if let Some(refusal) = refuse_short_name(candidate, requested, verb) {
            return refusal;
        }
    }
    if is_name_surrogate(scan.link_type.as_deref()) {
        return PolicyDecision::deny(
            format!(
                "the tool refuses to {verb} {requested:?}: the source is a symbolic link or a \
                 junction, and the operation would act on its target. Pass the real source path."
            ),
            "PATH_REPARSE_POINT",
        );
    }
    if reject_nested_link && scan.is_directory && scan.nested_link {
        return PolicyDecision::deny(
            format!(
                "the tool refuses to {verb} {requested:?}: the source tree contains a symbolic \
                 link or a junction, and a recursive copy would follow it. Remove the link, or use \
                 run_command."
            ),
            "NESTED_REPARSE_POINT",
        );
    }
    if reject_nested_link && scan.is_directory && scan.unreadable {
        return PolicyDecision::deny(
            format!(
                "the tool refuses to {verb} {requested:?}: the source tree is not fully readable, \
                 and a recursive copy would be partial. Check the access rights, or use \
                 run_command."
            ),
            "SOURCE_UNREADABLE",
        );
    }
    if removes_source {
        return boundary_decide(
            requested,
            &[&scan.full_name],
            &scan.roots,
            None,
            false,
            verb,
            allowed,
        );
    }
    PolicyDecision::allow("the source is read-only")
}

/// Overwrite verdict of a file operation target (TR-FS-08, ADR-0017 §15).
///
/// A missing target is allowed. A directory source never replaces an existing target:
/// the operator deletes it first with `delete_directory`, which carries the DR-6
/// protection. A file target exists only with `overwrite`.
#[must_use]
pub fn decide_file_op_overwrite(
    path: &str,
    exists: bool,
    source_is_directory: bool,
    overwrite: bool,
) -> PolicyDecision {
    if !exists {
        return PolicyDecision::allow("the target does not exist");
    }
    if source_is_directory {
        return PolicyDecision::deny(
            format!(
                "the tool refuses {path:?}: the target already exists and a directory copy does \
                 not replace an existing target. Delete the target first with delete_directory."
            ),
            "FILE_EXISTS",
        );
    }
    if !overwrite {
        return PolicyDecision::deny(
            format!("{path} already exists; pass overwrite=true to replace it"),
            "FILE_EXISTS",
        );
    }
    PolicyDecision::allow("the target may be replaced")
}

/// Verdict on the target of `copy_file`, `move_file` or `create_directory`
/// (TR-FS-08, ADR-0017 §15–16).
///
/// The target obeys the write boundary and the operator allowlist, exactly as
/// `write_file`; the entry that permitted a protected target travels on the decision
/// for the warning line and the audit. An existing directory target is refused by the
/// boundary, and an existing file target is refused without `overwrite`.
#[must_use]
pub fn decide_file_op_target(
    scan: &WriteScan,
    requested: &str,
    source_is_directory: bool,
    overwrite: bool,
    verb: &str,
    allowed: &[String],
) -> PolicyDecision {
    let boundary = decide_write_boundary(
        requested,
        &[&scan.full_name, &scan.dotnet_full_name],
        &scan.roots,
        scan.link_type.as_deref(),
        scan.is_directory,
        verb,
        allowed,
    );
    if !boundary.allow {
        return boundary;
    }
    let decision = decide_file_op_overwrite(requested, scan.exists, source_is_directory, overwrite);
    if !decision.allow {
        return decision;
    }
    match boundary.matched {
        Some(entry) => decision.allowed_by(entry, boundary.class),
        None => decision,
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

/// A missing, `null` or empty value gives `None` (a target that is not a link reports
/// no `LinkType`).
fn optional_str(object: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
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
/// The host reads the roots from its own system variables (`%SystemRoot%` and
/// similar), so the roots name the actual system location, on whatever volume it
/// sits. The lexical `PROTECTED_DIRS` list knows only `C:`.
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
        // The lexical check has no host resolution, so it does not name one.
        let reason = if resolved == requested {
            format!("the tool refuses to {verb} a protected path: {requested:?}")
        } else {
            format!(
                "the tool refuses to {verb} a protected path (the host resolved it to {resolved}): {requested}"
            )
        };
        return Some(PolicyDecision::deny(reason, "PATH_PROTECTED"));
    }
    roots.containing(resolved).map(|(name, root)| {
        PolicyDecision::deny(
            format!(
                "the tool refuses to {verb} a protected path (the host resolved it to {resolved}, \
                 inside the {name} root {root}): {requested}"
            ),
            "PATH_PROTECTED",
        )
    })
}

/// True for a name surrogate: a symbolic link or a junction (ADR-0017 §10).
///
/// `LinkType` is `SymbolicLink` or `Junction` for a name surrogate; PowerShell 5.1
/// exposes it on every file system item. A reparse point that is not a link (a
/// deduplicated file, a OneDrive placeholder, an HSM stub) reports no `LinkType`, so it
/// stays writable. A missing `LinkType` is read as "not a link": the reparse-tag
/// name-surrogate bit `0x20000000` needs the raw tag, which no managed API exposes.
#[must_use]
pub fn is_name_surrogate(link_type: Option<&str>) -> bool {
    link_type.is_some_and(|kind| {
        kind.eq_ignore_ascii_case("symboliclink") || kind.eq_ignore_ascii_case("junction")
    })
}

/// The confirmation warning sentence of a protected write target (ADR-0017 §36).
///
/// `None` when the target is not protected. A volume root (including a volume GUID and
/// an administrative share that maps to one) gives `the target is a volume root`; a
/// system directory, an administrative share and a system share inside one give
/// `the target lies in a system directory`; a plain UNC share root gives
/// `the target is a share root`.
#[must_use]
pub fn protected_target_class(path: &str, roots: &HostRoots) -> Option<&'static str> {
    let norm = normalize_windows_path(path);
    if norm.is_empty() {
        return None;
    }
    let norm = admin_share_local(&norm).unwrap_or(norm);
    if is_volume_root(&norm) || is_volume_guid(&norm) || is_volume_guid_root(&norm) {
        return Some("the target is a volume root");
    }
    let system = is_system_share(&norm)
        || PROTECTED_DIRS
            .iter()
            .any(|dir| norm == *dir || norm.starts_with(&format!("{dir}\\")))
        || roots.containing(&norm).is_some();
    if system {
        return Some("the target lies in a system directory");
    }
    is_unc_share_root(&norm).then_some("the target is a share root")
}

/// One write-side boundary entry point for every write-side file tool (ADR-0017
/// §7–13, TR-FS-07).
///
/// The allowlist never lifts the bypass protections: a device volume or GLOBALROOT
/// path, an 8.3 component in any resolution (TR-SEC-04), a name surrogate (a symbolic
/// link or a junction), and an existing directory target. A name surrogate is refused
/// because the operation would act on its target, which no entry can cover (§10).
/// Otherwise `resolutions` are the requested form plus each host-resolved form: a
/// protected resolution must be covered by an allowlist entry, and that entry is
/// reported in `matched` with the protected `class` for the warning line (§8, §39).
/// `roots` are the protected host locations, empty before the scan so only the lexical
/// list applies. Every write-side file tool calls this one entry point.
#[must_use]
pub fn decide_write_boundary(
    requested: &str,
    resolutions: &[&str],
    roots: &HostRoots,
    link_type: Option<&str>,
    is_directory: bool,
    verb: &str,
    allowed: &[String],
) -> PolicyDecision {
    boundary_decide(
        requested,
        resolutions,
        roots,
        link_type,
        is_directory,
        verb,
        allowed,
    )
}

/// The shared body of [`decide_write_boundary`] with the directory rule as a flag.
///
/// The write-side tools (`write_file`, the target of a copy or a move) refuse a
/// directory target; a move checks its source, which may be a directory, so it calls
/// this function with `reject_directory` false.
fn boundary_decide(
    requested: &str,
    resolutions: &[&str],
    roots: &HostRoots,
    link_type: Option<&str>,
    reject_directory: bool,
    verb: &str,
    allowed: &[String],
) -> PolicyDecision {
    for candidate in std::iter::once(requested).chain(resolutions.iter().copied()) {
        if let Some(refusal) = refuse_device_volume(candidate, requested, verb) {
            return refusal;
        }
        if let Some(refusal) = refuse_short_name(candidate, requested, verb) {
            return refusal;
        }
    }
    if is_name_surrogate(link_type) {
        return PolicyDecision::deny(
            format!(
                "the tool refuses to {verb} {requested:?}: the target is a symbolic link or a \
                 junction, and the operation would act on its target. Pass the real target path."
            ),
            "PATH_REPARSE_POINT",
        );
    }
    if reject_directory {
        return PolicyDecision::deny(
            format!(
                "the tool refuses to {verb} {requested:?}: the target is a directory. Pass a file \
                 path."
            ),
            "PATH_IS_DIRECTORY",
        );
    }
    let mut refusal = None;
    let mut matched = None;
    let mut class = None;
    for resolved in resolutions {
        if refuse_resolved(resolved, roots, requested, verb).is_none() {
            continue;
        }
        match write_path_allowed(resolved, allowed) {
            Some(entry) => {
                if matched.is_none() {
                    matched = Some(entry);
                }
                if class.is_none() {
                    class = protected_target_class(resolved, roots);
                }
            }
            None if refusal.is_none() => {
                refusal = refuse_resolved(resolved, roots, requested, verb);
            }
            None => {}
        }
    }
    match refusal {
        Some(decision) => decision,
        None => match matched {
            Some(entry) => PolicyDecision::allow("path is inside the operator allowlist")
                .allowed_by(entry, class),
            None => PolicyDecision::allow("path is not protected"),
        },
    }
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
    /// `LinkType` of the final component: `SymbolicLink`, `Junction` or `None`
    /// (ADR-0017 §10).
    pub link_type: Option<String>,
    /// Protected host locations (TR-SEC-04, ADR-0015 §10).
    pub roots: HostRoots,
}

impl FileScan {
    ///
    /// # Errors
    ///
    /// Error text if the answer is not a JSON object or lacks the mandatory fields
    /// `FullName`, `IsDirectory`, and `Roots` with a non-empty `SystemRoot`.
    /// `LinkType` is optional: a reparse point that is not a link reports `null`.
    pub fn from_json(raw: &str) -> Result<Self, String> {
        let object = scan_object(raw)?;
        Ok(Self {
            full_name: required_str(&object, "FullName")?,
            is_directory: required_bool(&object, "IsDirectory")?,
            link_type: optional_str(&object, "LinkType"),
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
    /// The path as .NET (`[IO.Path]::GetFullPath`) resolves it.
    pub dotnet_full_name: String,
    pub exists: bool,
    pub is_directory: bool,
    /// `LinkType` of the final component: `SymbolicLink`, `Junction` or `None`
    /// (ADR-0017 §10).
    pub link_type: Option<String>,
    pub roots: HostRoots,
}

impl WriteScan {
    ///
    /// # Errors
    ///
    /// Error text if `FullName`, `DotNetFullName`, `Exists`, `IsDirectory`, or `Roots`
    /// with a non-empty `SystemRoot` is missing (fail-closed). `LinkType` is optional:
    /// a reparse point that is not a link reports `null`.
    pub fn from_json(raw: &str) -> Result<Self, String> {
        let object = scan_object(raw)?;
        Ok(Self {
            full_name: required_str(&object, "FullName")?,
            dotnet_full_name: required_str(&object, "DotNetFullName")?,
            exists: required_bool(&object, "Exists")?,
            is_directory: required_bool(&object, "IsDirectory")?,
            link_type: optional_str(&object, "LinkType"),
            roots: HostRoots::from_scan(&object)?,
        })
    }
}

/// Services critical for the remote session (TR-SEC-15, Q-20).
///
/// A stop or a start-type change on one of these can end the session or break the
/// Service Control Manager: `WinRM` carries the session itself, `RpcSs` and
/// `DcomLaunch` sit below the Service Control Manager, `LanmanServer` carries the
/// administrative shares and `Winmgmt` answers the CIM reads. The match is on the
/// service name, which the tools accept, not the display name, whose text is
/// locale-dependent.
pub const PROTECTED_SERVICES: [&str; 5] =
    ["WinRM", "RpcSs", "DcomLaunch", "LanmanServer", "Winmgmt"];

/// Characters allowed in a service name (TR-SEC-15, finding 3).
///
/// A conservative set: ASCII letters, digits, `_`, `-`, `.` and space. A quote, a
/// backslash, a slash, a control character and every other character are refused
/// before the network, so the name cannot reach WQL or a PowerShell string as code.
#[must_use]
pub fn is_valid_service_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' '))
}

/// Verdict for the target of `stop_service`, `restart_service` and
/// `set_service_start_type` (TR-SEC-15, AC-SEC15-3).
///
/// This is the first gate, on the Rust side. The host resolver repeats the protected
/// check on the canonical name, because `ServiceController` also accepts a display
/// name. A name outside [`is_valid_service_name`] is refused here: a quote, a
/// backslash or a wildcard could reach a service past an exact-name check.
#[must_use]
pub fn decide_service_target(name: &str) -> PolicyDecision {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return PolicyDecision::deny("the service name is empty".to_owned(), "SERVICE_NAME_EMPTY");
    }
    if !is_valid_service_name(trimmed) {
        return PolicyDecision::deny(
            format!(
                "the tool refuses the service name {name:?}: a name may hold only letters, digits, \
                 '_', '-', '.' and space"
            ),
            "SERVICE_NAME_INVALID",
        );
    }
    if let Some(protected) = PROTECTED_SERVICES
        .iter()
        .find(|service| service.eq_ignore_ascii_case(trimmed))
    {
        return PolicyDecision::deny(
            format!(
                "the tool refuses to change the service {protected:?}: it is critical for the \
                 remote session"
            ),
            "SERVICE_PROTECTED",
        );
    }
    PolicyDecision::allow("service is not protected")
}

/// Write scan verdict: a protected path in either of the two resolutions, then the
/// overwrite rule (TR-FS-03, TR-FS-06, TR-FS-07).
///
/// An operator allowlist entry that covers a protected resolution lifts that
/// refusal; the marker travels on the decision for the audit and the warning line
/// (ADR-0017 §9, §36, §39).
#[must_use]
pub fn decide_write_scan(
    scan: &WriteScan,
    requested: &str,
    overwrite: bool,
    allowed: &[String],
) -> PolicyDecision {
    let boundary = decide_write_boundary(
        requested,
        &[&scan.full_name, &scan.dotnet_full_name],
        &scan.roots,
        scan.link_type.as_deref(),
        scan.is_directory,
        "write to",
        allowed,
    );
    if !boundary.allow {
        return boundary;
    }
    let decision = decide_overwrite(requested, scan.exists, overwrite);
    if !decision.allow {
        return decision;
    }
    match boundary.matched {
        Some(entry) => decision.allowed_by(entry, boundary.class),
        None => decision,
    }
}

/// Verdict on the single-file scan result (DR-6, TR-FS-07).
#[must_use]
pub fn decide_file_delete(scan: &FileScan, requested: &str, allowed: &[String]) -> PolicyDecision {
    if scan.is_directory {
        return PolicyDecision::deny(
            format!(
                "the tool refuses to delete a directory with delete_file (use delete_directory): {requested}"
            ),
            "PATH_IS_DIRECTORY",
        );
    }
    decide_write_boundary(
        requested,
        &[&scan.full_name],
        &scan.roots,
        scan.link_type.as_deref(),
        false,
        "delete",
        allowed,
    )
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
            format!("the tool refuses to delete a reparse point (junction/symlink): {requested}"),
            "PATH_REPARSE_POINT",
        );
    }
    if scan.nested_reparse_point {
        return PolicyDecision::deny(
            format!(
                "the tool refuses to delete: the subtree contains a reparse point (junction/symlink): {requested}"
            ),
            "NESTED_REPARSE_POINT",
        );
    }
    if scan.total_items > cap {
        return PolicyDecision::deny(
            format!(
                "the directory contains {}+ items, above the safety cap of {cap}. Review the scan and raise max_items if the count is correct.",
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

    /// A non-empty list does not add loopback: the operator listed the hosts explicitly.
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

    fn commands(list: &[&str]) -> Vec<String> {
        list.iter().map(|entry| (*entry).to_owned()).collect()
    }

    /// TR-EXE-02, AC-EXE-02: an empty list admits any command, and a non-empty
    /// list refuses a command that does not begin with an entry.
    #[test]
    fn command_outside_the_allowlist_is_refused() {
        let allowed = commands(&["Get-Service", "ipconfig"]);
        assert!(command_allowed("Get-Service -Name Spooler", &allowed));
        assert!(command_allowed("ipconfig /all", &allowed));
        // A prefix matches without case and without leading spaces.
        assert!(command_allowed("  get-service", &allowed));
        assert!(!command_allowed("Remove-Item C:\\ -Recurse", &allowed));
        assert!(!command_allowed("Write-Output Get-Service", &allowed));
        assert!(!decide_command("whoami", &allowed).allow);
        assert!(decide_command("ipconfig", &allowed).allow);
        assert_eq!(
            decide_command("whoami", &allowed).code,
            "COMMAND_NOT_ALLOWED"
        );
        // An empty list admits any command, including a long one.
        assert!(command_allowed("anything at all", &[]));
        assert!(decide_command("anything at all", &[]).allow);
    }

    /// TR-EXE-02: the list is a prefix, not a boundary. Any text after an allowed
    /// prefix runs, so the list protects against an accidental command, not against
    /// intent (ADR-0013 §18). This is a documented property, not a defect.
    #[test]
    fn text_after_an_allowed_prefix_still_runs() {
        let allowed = commands(&["Get-Service"]);
        assert!(command_allowed("Get-Service; Remove-Item C:\\x", &allowed));
        assert!(command_allowed("Get-Service | Out-File C:\\x", &allowed));
        assert!(command_allowed("Get-Service\nRemove-Item C:\\x", &allowed));
        assert!(command_allowed("Get-Service$(Remove-Item C:\\x)", &allowed));
        // An entry of `&` or `.` alone admits everything.
        assert!(command_allowed("& 'C:\\evil.ps1'", &commands(&["&"])));
        assert!(command_allowed(". C:\\evil.ps1", &commands(&["."])));
    }

    /// TR-EXE-04: the length verdict counts UTF-16 units and names the limit.
    #[test]
    fn command_length_is_counted_in_utf16_units() {
        assert!(decide_command_length("whoami", 10).allow);
        let decision = decide_command_length("whoami", 5);
        assert!(!decision.allow);
        assert_eq!(decision.code, "COMMAND_TOO_LONG");
        assert!(
            decision.reason.contains("UTF-16 units"),
            "{}",
            decision.reason
        );
        // A non-ASCII character is one UTF-16 unit, so it counts like an ASCII one.
        assert!(decide_command_length("ыыыыы", 5).allow);
        assert!(!decide_command_length("ыыыыыы", 5).allow);
    }

    /// TR-EXE-02: the refusal does not echo the command, so a secret in a refused
    /// command cannot reach the audit (DR-4).
    #[test]
    fn command_refusal_does_not_echo_the_command() {
        let secret = "P@ssw0rd-in-the-command";
        let decision = decide_command(&format!("run {secret}"), &commands(&["ipconfig"]));
        assert!(!decision.allow);
        assert!(!decision.reason.contains(secret), "{}", decision.reason);
    }

    /// The command grammar trims empty entries and refuses a control character.
    #[test]
    fn allowed_commands_grammar() {
        assert_eq!(
            parse_allowed_commands(" Get-Service ,, ipconfig ").expect("valid"),
            ["Get-Service", "ipconfig"]
        );
        assert!(parse_allowed_commands(" , ").expect("valid").is_empty());
        assert_eq!(
            parse_allowed_commands("ok,bad\nentry"),
            Err("bad\nentry".to_owned())
        );
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
            let decision = decide_write_path(path, &[]);
            assert!(!decision.allow, "must refuse {path}");
            assert_eq!(decision.code, "PATH_PROTECTED");
        }
        let decision = decide_write_path("C:\\Temp\\report.txt", &[]);
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
        let decision = decide_write_path("C:\\Windows\\System32", &[]);
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
        let scan = FileScan::from_json(r#"{"FullName":"C:\\App\\a.txt","IsDirectory":false,"LinkType":null,"Roots":{"SystemRoot":"C:\\Windows"}}"#)
            .expect("valid scan");
        assert_eq!(scan.full_name, "C:\\App\\a.txt");
        assert!(!scan.is_directory);
        assert_eq!(scan.link_type, None);
        assert!(
            FileScan::from_json(
                r#"{"FullName":"C:\\App\\a.txt","IsDirectory":false,"LinkType":"Junction","Roots":{"SystemRoot":"C:\\Windows"}}"#
            )
            .expect("valid scan")
            .link_type
            .as_deref()
            == Some("Junction")
        );
        assert!(FileScan::from_json("not json").is_err());
        assert!(FileScan::from_json(r#"{"FullName":"C:\\a"}"#).is_err());
        assert!(FileScan::from_json(r#"{"FullName":"","IsDirectory":false}"#).is_err());
        // Fail-closed: the directory flag is a protective field; the link type is
        // optional, because a reparse point that is not a link reports null.
        assert!(
            FileScan::from_json(r#"{"FullName":"C:\\a.txt","Roots":{"SystemRoot":"C:\\Windows"}}"#)
                .is_err()
        );
        assert!(
            FileScan::from_json(
                r#"{"FullName":"C:\\a.txt","IsDirectory":false,"Roots":{"SystemRoot":"C:\\Windows"}}"#
            )
            .is_ok()
        );
    }

    #[test]
    fn file_delete_refuses_directory_and_protected_path() {
        let directory = FileScan {
            full_name: "C:\\App\\logs".to_owned(),
            is_directory: true,
            link_type: None,
            roots: HostRoots::default(),
        };
        assert_eq!(
            decide_file_delete(&directory, "C:\\App\\logs", &[]).code,
            "PATH_IS_DIRECTORY"
        );

        let protected = FileScan {
            full_name: "C:\\Windows\\System32\\drivers\\etc\\hosts".to_owned(),
            is_directory: false,
            link_type: None,
            roots: HostRoots::default(),
        };
        assert_eq!(
            decide_file_delete(&protected, "C:\\App\\shortcut", &[]).code,
            "PATH_PROTECTED"
        );

        let ordinary = FileScan {
            full_name: "C:\\App\\a.txt".to_owned(),
            is_directory: false,
            link_type: None,
            roots: HostRoots::default(),
        };
        assert!(decide_file_delete(&ordinary, "C:\\App\\a.txt", &[]).allow);
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
            r#"{"FullName":"D:\\App\\a.txt","IsDirectory":false,"IsReparsePoint":false,"Roots":{"SystemRoot":"D:\\Windows","ProgramFiles":"D:\\Program Files","ProgramFilesX86":null,"ProgramData":"","Users":"D:\\Users"}}"#,
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
            assert_eq!(
                decide_write_path(path, &[]).code,
                "PATH_PROTECTED",
                "{path}"
            );
            assert_eq!(decide_delete_path(path).code, "PATH_PROTECTED", "{path}");
            assert!(
                decide_write_path(path, &[]).reason.contains("8.3"),
                "{path}"
            );
        }
        for path in [
            "C:\\App\\backup~old.txt",
            "C:\\App\\~1",
            "C:\\App\\x~y1.txt",
        ] {
            assert!(decide_write_path(path, &[]).allow, "{path}");
        }
        let resolved = FileScan {
            full_name: "D:\\PROGRA~1\\x.dll".to_owned(),
            is_directory: false,
            link_type: None,
            roots: roots(&[("SystemRoot", "D:\\Windows")]),
        };
        assert_eq!(
            decide_file_delete(&resolved, "x.dll", &[]).code,
            "PATH_PROTECTED"
        );
        let write = write_scan("D:\\App\\x", "D:\\PROGRA~1\\x", false);
        assert_eq!(
            decide_write_scan(&write, "x", false, &[]).code,
            "PATH_PROTECTED"
        );
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
            assert_eq!(
                decide_write_path(path, &[]).code,
                "PATH_PROTECTED",
                "{path}"
            );
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
            link_type: None,
            roots: system.clone(),
        };
        let decision = decide_file_delete(&file, "D:\\Windows\\System32\\kernel32.dll", &[]);
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
            is_directory: false,
            link_type: None,
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
            decide_write_scan(&inside_ps, "x.ps1", false, &[]).code,
            "PATH_PROTECTED"
        );
        let inside_net = write_scan("D:\\App\\x.ps1", "D:\\Program Files\\x.ps1", false);
        assert_eq!(
            decide_write_scan(&inside_net, "x.ps1", false, &[]).code,
            "PATH_PROTECTED"
        );
        let lexical = write_scan("C:\\Windows\\x.ps1", "C:\\Windows\\x.ps1", false);
        assert_eq!(
            decide_write_scan(&lexical, "x.ps1", false, &[]).code,
            "PATH_PROTECTED"
        );

        let fresh = write_scan("D:\\App\\x.ps1", "D:\\App\\x.ps1", false);
        assert!(decide_write_scan(&fresh, "D:\\App\\x.ps1", false, &[]).allow);
        let existing = write_scan("D:\\App\\x.ps1", "D:\\App\\x.ps1", true);
        assert_eq!(
            decide_write_scan(&existing, "D:\\App\\x.ps1", false, &[]).code,
            "FILE_EXISTS"
        );
        assert!(decide_write_scan(&existing, "D:\\App\\x.ps1", true, &[]).allow);
    }

    #[test]
    fn write_scan_parses_and_fails_closed() {
        let scan = WriteScan::from_json(
            r#"{"FullName":"D:\\App\\x","DotNetFullName":"D:\\App\\x","Exists":true,"IsDirectory":false,"LinkType":null,"Roots":{"SystemRoot":"D:\\Windows"}}"#,
        )
        .expect("valid scan");
        assert!(scan.exists);
        assert_eq!(scan.link_type, None);
        assert_eq!(scan.dotnet_full_name, "D:\\App\\x");
        for broken in [
            "not json",
            r#"{"FullName":"D:\\App\\x","Exists":true,"Roots":{"SystemRoot":"D:\\Windows"}}"#,
            r#"{"FullName":"D:\\App\\x","DotNetFullName":"D:\\App\\x","Roots":{"SystemRoot":"D:\\Windows"}}"#,
            r#"{"FullName":"D:\\App\\x","DotNetFullName":"D:\\App\\x","Exists":false}"#,
            // Fail-closed: the directory flag is a protective field; `LinkType` is
            // optional, because a reparse point that is not a link reports null.
            r#"{"FullName":"D:\\App\\x","DotNetFullName":"D:\\App\\x","Exists":false,"Roots":{"SystemRoot":"D:\\Windows"}}"#,
        ] {
            assert!(WriteScan::from_json(broken).is_err(), "{broken}");
        }
    }

    /// AC-SEC15-3, Q-20: the service target of `stop_service`, `restart_service` and
    /// `set_service_start_type` is refused when it is critical for the remote session,
    /// case-insensitively; a name outside the allowed charset is refused too, so a
    /// wildcard or a display name never reaches the host (TR-SEC-15).
    #[test]
    fn protected_service_target_is_refused() {
        for name in [
            "WinRM",
            "winrm",
            "  RpCsS ",
            "LANMANSERVER",
            "DcomLaunch",
            "winmgmt",
        ] {
            let decision = decide_service_target(name);
            assert!(!decision.allow, "must refuse {name:?}");
            assert_eq!(decision.code, "SERVICE_PROTECTED", "{name:?}");
            assert!(decision.reason.contains("critical"), "{name:?}");
        }
        for name in [
            "LanmanS*",
            "WinR?",
            "Svc[1]",
            "spooler*",
            "a\"b",
            "a\\b",
            "a/b",
            "a'b",
            "a\u{1}b",
            "Windows Remote Management (WS-Management)",
        ] {
            let decision = decide_service_target(name);
            assert!(!decision.allow, "must refuse {name:?}");
            assert_eq!(decision.code, "SERVICE_NAME_INVALID", "{name:?}");
        }
        assert_eq!(decide_service_target("   ").code, "SERVICE_NAME_EMPTY");
        for name in [
            "Spooler",
            "My Service",
            "wuauserv",
            "WinRMHelper",
            "a.b-c_d",
        ] {
            assert!(decide_service_target(name).allow, "must allow {name:?}");
            assert!(is_valid_service_name(name), "must allow {name:?}");
        }
        // A plain-word display name such as "Server" is a valid name, so the host
        // resolver, not the Rust gate, must refuse it; a display name with a bracket
        // fails the charset here.
        assert!(is_valid_service_name("Server"));
        assert!(!is_valid_service_name(
            "Windows Remote Management (WS-Management)"
        ));
    }

    fn paths(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    /// DR-8, ADR-0017 §7/§11: the allowlist grammar accepts an absolute drive or
    /// UNC directory and refuses a relative path, a bare drive letter, a wildcard
    /// and a control character. A system directory and a volume root are lawful.
    #[test]
    fn write_allow_paths_grammar() {
        assert_eq!(
            parse_write_allow_paths(" C:\\ProgramData\\Vendor ,, D:/Apps ").expect("valid"),
            ["C:\\ProgramData\\Vendor", "D:/Apps"]
        );
        assert!(parse_write_allow_paths(" , ").expect("valid").is_empty());
        for good in [
            "C:\\",
            "C:\\ProgramData\\Vendor",
            "\\\\server\\share",
            "\\\\?\\C:\\Logs",
        ] {
            assert_eq!(
                parse_write_allow_paths(good),
                Ok(vec![good.to_owned()]),
                "{good}"
            );
        }
        for bad in [
            "relative\\path",
            "..\\escape",
            "C:",
            "\\.\\nope",
            "*.log",
            "C:\\Logs\\*.log",
            "C:\\Logs\\a?b",
            // UNC entries need a server and a share; `\\fs01` alone is not a directory.
            "\\\\fs01",
            "\\\\fs01\\",
            // An 8.3 component cannot be compared against the list.
            "C:\\PROGRA~1",
            // A `..` component could climb above the entry's own start.
            "C:\\Vendor\\..\\..",
            "C:\\Vendor\\..\\Other",
            // A component with a trailing dot or space is ambiguous. A trailing
            // space at the very end of an entry is trimmed, so the marker must sit
            // inside the path.
            "C:\\Logs.",
            "C:\\Logs \\sub",
            "C:\\Logs.\\sub",
        ] {
            assert_eq!(
                parse_write_allow_paths(&format!("C:\\Valid,{bad}")),
                Err(bad.to_owned()),
                "{bad}"
            );
        }
        assert_eq!(
            parse_write_allow_paths("C:\\Valid,C:\\Logs\nx"),
            Err("C:\\Logs\nx".to_owned())
        );
    }

    /// AC-FS-08: an operator entry lifts the protected refusal for the write-side
    /// tools, and the decision carries the entry and the warning sentence.
    #[test]
    fn write_allow_paths_lift_the_refusal() {
        let allowed = paths(&["C:\\ProgramData\\Vendor"]);
        let target = "C:\\ProgramData\\Vendor\\db.sqlite";
        let scan = WriteScan {
            full_name: target.to_owned(),
            dotnet_full_name: target.to_owned(),
            exists: false,
            is_directory: false,
            link_type: None,
            roots: roots(&[("ProgramData", "C:\\ProgramData")]),
        };
        let decision = decide_write_scan(&scan, target, false, &allowed);
        assert!(decision.allow, "{}", decision.reason);
        assert_eq!(decision.matched.as_deref(), Some("C:\\ProgramData\\Vendor"));
        assert_eq!(
            decision.class,
            Some("the target lies in a system directory")
        );

        // Without the entry the same target is refused, and the refusal names the
        // code (TR-OBS-03).
        let refused = decide_write_scan(&scan, target, false, &[]);
        assert!(!refused.allow);
        assert_eq!(refused.code, "PATH_PROTECTED");
        assert!(refused.matched.is_none());

        // The lexical pre-network check lifts with the same entry.
        let lexical = decide_write_path(target, &allowed);
        assert!(lexical.allow);
        assert_eq!(lexical.matched.as_deref(), Some("C:\\ProgramData\\Vendor"));

        // A `..` that escapes the entry is refused: the normalization collapses it
        // before the match.
        let escape = decide_write_path("C:\\ProgramData\\Vendor\\..\\..\\Windows\\x", &allowed);
        assert!(!escape.allow);
        assert_eq!(escape.code, "PATH_PROTECTED");

        // A volume root is a lawful entry, covers itself and warns with its own
        // sentence.
        let root = paths(&["C:\\"]);
        let scan = WriteScan {
            full_name: "C:\\".to_owned(),
            dotnet_full_name: "C:\\".to_owned(),
            exists: false,
            is_directory: false,
            link_type: None,
            roots: HostRoots::default(),
        };
        let decision = decide_write_scan(&scan, "C:\\", false, &root);
        assert!(decision.allow, "{}", decision.reason);
        assert_eq!(decision.class, Some("the target is a volume root"));

        // A UNC share root names its own class; a root entry covers itself.
        let share = paths(&["\\\\server\\share"]);
        let scan = WriteScan {
            full_name: "\\\\server\\share".to_owned(),
            dotnet_full_name: "\\\\server\\share".to_owned(),
            exists: false,
            is_directory: false,
            link_type: None,
            roots: HostRoots::default(),
        };
        let decision = decide_write_scan(&scan, "\\\\server\\share", false, &share);
        assert!(decision.allow, "{}", decision.reason);
        assert_eq!(decision.class, Some("the target is a share root"));

        // `delete_file` consults the allowlist too (ADR-0017 §9).
        let file = FileScan {
            full_name: target.to_owned(),
            is_directory: false,
            link_type: None,
            roots: roots(&[("ProgramData", "C:\\ProgramData")]),
        };
        assert!(decide_file_delete(&file, target, &allowed).allow);
        assert_eq!(
            decide_file_delete(&file, target, &[]).code,
            "PATH_PROTECTED"
        );
    }

    /// AC-FS-08: the match folds the case, honors a component boundary, and
    /// normalizes the separators, the `..` component, the `\\?\` prefix and the ADS
    /// suffix.
    #[test]
    fn write_allow_paths_match_by_component_and_case() {
        let allowed = paths(&["C:\\Logs"]);
        assert_eq!(
            write_path_allowed("c:/logs/a.txt", &allowed).as_deref(),
            Some("C:\\Logs")
        );
        assert!(
            write_path_allowed("C:\\Logs2\\a.txt", &allowed).is_none(),
            "a component boundary must separate Logs from Logs2"
        );
        assert!(write_path_allowed("C:\\Logs\\sub\\..\\a.txt", &allowed).is_some());
        // `..` collapses first, so a target cannot escape the entry through it.
        assert!(write_path_allowed("C:\\Logs\\..\\Windows\\x", &allowed).is_none());
        assert!(write_path_allowed("\\\\?\\C:\\Logs\\a.txt", &allowed).is_some());
        assert!(
            write_path_allowed("C:\\Logs.txt:stream", &allowed).is_none(),
            "an alternate data stream is not inside the directory"
        );
        assert!(
            write_path_allowed("\\\\server\\share\\a", &paths(&["\\\\server\\share"])).is_some()
        );
    }

    /// Item 2c: a file operation acts on a strict descendant, so the entry itself is
    /// not covered. Only a volume root covers itself.
    #[test]
    fn write_allow_paths_require_a_strict_descendant() {
        let allowed = paths(&["C:\\Logs"]);
        assert!(
            write_path_allowed("C:\\Logs", &allowed).is_none(),
            "the entry itself is not a strict descendant"
        );
        assert!(write_path_allowed("C:\\Logs\\", &allowed).is_none());
        assert!(write_path_allowed("C:\\Logs\\a", &allowed).is_some());
        // Root entries `C:\` and `\\server\share` cover themselves.
        let root = paths(&["C:\\"]);
        assert!(write_path_allowed("C:\\", &root).is_some());
        assert!(write_path_allowed("C:\\Windows\\x", &root).is_some());
    }

    /// Item 2a: the case fold is per character, like NTFS. A character that expands
    /// under upper casing must not match.
    #[test]
    fn write_allow_case_folding_is_not_wider_than_ntfs() {
        // `ß` upper-cases to `SS`, and the `ﬃ` ligature to `FFI`.
        assert!(write_path_allowed("C:\\Straße\\a", &paths(&["C:\\Straße"])).is_none());
        assert!(write_path_allowed("C:\\Strasse\\a", &paths(&["C:\\Straße"])).is_none());
        assert!(write_path_allowed("C:\\Oﬃce\\a", &paths(&["C:\\Oﬃce"])).is_none());
        // A plain ASCII entry still matches without case.
        assert!(write_path_allowed("c:\\logs\\a", &paths(&["C:\\Logs"])).is_some());
    }

    /// Item 2b: only the `\\?\` form keeps a trailing dot or space, so a component
    /// with one is ambiguous and is not covered.
    #[test]
    fn write_allow_rejects_ambiguous_components() {
        let allowed = paths(&["C:\\Logs"]);
        assert!(write_path_allowed("C:\\Logs.\\a", &allowed).is_none());
        assert!(write_path_allowed("C:\\Logs \\a", &allowed).is_none());
        assert!(write_path_allowed("\\\\?\\C:\\Logs.\\a", &allowed).is_none());
        assert!(write_path_allowed("\\\\?\\C:\\Logs \\a", &allowed).is_none());
        // A normal component with a dot in the middle is fine.
        assert!(write_path_allowed("C:\\Logs\\a.b", &allowed).is_some());
    }

    /// AC-FS-09: the allowlist does not lift the 8.3 refusal, in any resolution of
    /// any write-side tool.
    #[test]
    fn short_name_stays_refused_with_an_allow_entry() {
        let allowed = paths(&["C:\\Program Files"]);
        let decision = decide_write_path("C:\\PROGRA~1\\App\\x.dll", &allowed);
        assert!(!decision.allow);
        assert_eq!(decision.code, "PATH_PROTECTED");
        assert!(decision.reason.contains("8.3"), "{}", decision.reason);

        let scan = WriteScan {
            full_name: "C:\\PROGRA~1\\App\\x.dll".to_owned(),
            dotnet_full_name: "C:\\PROGRA~1\\App\\x.dll".to_owned(),
            exists: false,
            is_directory: false,
            link_type: None,
            roots: HostRoots::default(),
        };
        assert_eq!(
            decide_write_scan(&scan, "x.dll", false, &allowed).code,
            "PATH_PROTECTED"
        );

        let file = FileScan {
            full_name: "C:\\PROGRA~1\\x.dll".to_owned(),
            is_directory: false,
            link_type: None,
            roots: HostRoots::default(),
        };
        assert_eq!(
            decide_file_delete(&file, "x.dll", &allowed).code,
            "PATH_PROTECTED"
        );
    }

    /// Item 1, AC-FS-09: the allowlist does not lift the name-surrogate refusal (a
    /// symbolic link or a junction), but a reparse point that is not a link stays
    /// writable.
    #[test]
    fn name_surrogate_stays_refused_with_an_allow_entry() {
        let allowed = paths(&["C:\\ProgramData\\Vendor"]);
        let target = "C:\\ProgramData\\Vendor\\link.txt";

        for link in ["SymbolicLink", "Junction"] {
            let scan = WriteScan {
                full_name: target.to_owned(),
                dotnet_full_name: target.to_owned(),
                exists: true,
                is_directory: false,
                link_type: Some(link.to_owned()),
                roots: roots(&[("ProgramData", "C:\\ProgramData")]),
            };
            let decision = decide_write_scan(&scan, target, true, &allowed);
            assert!(!decision.allow, "{link} must be refused");
            assert_eq!(decision.code, "PATH_REPARSE_POINT");
            assert!(
                decision.reason.contains("symbolic link or a junction"),
                "{}",
                decision.reason
            );

            let file = FileScan {
                full_name: target.to_owned(),
                is_directory: false,
                link_type: Some(link.to_owned()),
                roots: roots(&[("ProgramData", "C:\\ProgramData")]),
            };
            assert_eq!(
                decide_file_delete(&file, target, &allowed).code,
                "PATH_REPARSE_POINT"
            );
        }

        // A deduplicated file, a OneDrive placeholder and an HSM stub report no link
        // type, so the allowlist still covers them.
        let dedup = WriteScan {
            full_name: target.to_owned(),
            dotnet_full_name: target.to_owned(),
            exists: true,
            is_directory: false,
            link_type: None,
            roots: roots(&[("ProgramData", "C:\\ProgramData")]),
        };
        assert!(decide_write_scan(&dedup, target, true, &allowed).allow);
        assert!(!is_name_surrogate(None));
        assert!(!is_name_surrogate(Some("HardLink")));
        assert!(is_name_surrogate(Some("symboliclink")));
        assert!(is_name_surrogate(Some("JUNCTION")));
    }

    /// Item 1: an existing directory target is refused before the network, with or
    /// without an allowlist entry.
    #[test]
    fn directory_target_is_refused_with_an_allow_entry() {
        let allowed = paths(&["C:\\ProgramData\\Vendor"]);
        let target = "C:\\ProgramData\\Vendor\\sub";
        let scan = WriteScan {
            full_name: target.to_owned(),
            dotnet_full_name: target.to_owned(),
            exists: true,
            is_directory: true,
            link_type: None,
            roots: roots(&[("ProgramData", "C:\\ProgramData")]),
        };
        let decision = decide_write_scan(&scan, target, false, &allowed);
        assert!(!decision.allow);
        assert_eq!(decision.code, "PATH_IS_DIRECTORY");
    }

    /// ADR-0017 §8, item 5: an entry must cover every protected resolution. One
    /// covered resolution does not excuse a second protected resolution that no entry
    /// covers.
    #[test]
    fn mixed_resolution_protected_is_refused_even_when_covered() {
        let allowed = paths(&["C:\\ProgramData\\Vendor"]);
        let requested = "C:\\ProgramData\\Vendor\\db.sqlite";
        let scan = WriteScan {
            full_name: requested.to_owned(),
            dotnet_full_name: "C:\\Windows\\System32\\db.sqlite".to_owned(),
            exists: false,
            is_directory: false,
            link_type: None,
            roots: roots(&[("ProgramData", "C:\\ProgramData")]),
        };
        let decision = decide_write_scan(&scan, requested, false, &allowed);
        assert!(!decision.allow, "{}", decision.reason);
        assert_eq!(decision.code, "PATH_PROTECTED");
    }

    /// Item 8: a device volume or GLOBALROOT path is refused lexically, for the
    /// write and for the recursive delete, because the list cannot see the system
    /// inside it.
    #[test]
    fn device_volume_paths_are_refused() {
        for path in [
            "\\\\?\\Volume{12345678-1234-1234-1234-123456789abc}\\Windows\\x.dll",
            "\\\\?\\Volume{12345678-1234-1234-1234-123456789abc}",
            "\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1\\Windows\\x.dll",
            "\\\\.\\GLOBALROOT\\Device\\HarddiskVolume1\\x.dll",
            "\\??\\GLOBALROOT\\Device\\x",
        ] {
            assert!(is_device_volume_path(path), "{path}");
            assert_eq!(
                decide_write_path(path, &[]).code,
                "PATH_PROTECTED",
                "{path}"
            );
            assert_eq!(decide_delete_path(path).code, "PATH_PROTECTED", "{path}");
        }
        // Every candidate refuses this path, allowlist or not.
        let allowed = paths(&["C:\\"]);
        assert!(
            !decide_write_path(
                "\\\\?\\Volume{12345678-1234-1234-1234-123456789abc}\\Windows\\x.dll",
                &allowed
            )
            .allow
        );
    }

    /// ADR-0017 §13: the recursive deletion does not consult the allowlist, so
    /// DR-6 keeps its refusals in full.
    #[test]
    fn delete_directory_does_not_consult_the_allowlist() {
        let scan = DeleteScan {
            full_name: "C:\\ProgramData\\Vendor".to_owned(),
            is_reparse_point: false,
            total_items: 1,
            file_count: 1,
            dir_count: 0,
            nested_reparse_point: false,
            roots: HostRoots::default(),
        };
        assert_eq!(
            decide_delete_scan(&scan, "C:\\ProgramData\\Vendor", 5000).code,
            "PATH_PROTECTED"
        );
    }

    fn win_scan(full: &str, exists: bool, is_directory: bool) -> WriteScan {
        WriteScan {
            full_name: full.to_owned(),
            dotnet_full_name: full.to_owned(),
            exists,
            is_directory,
            link_type: None,
            roots: HostRoots::default(),
        }
    }

    fn source_scan(full: &str, is_directory: bool) -> SourceScan {
        SourceScan {
            full_name: full.to_owned(),
            is_directory,
            link_type: None,
            nested_link: false,
            truncated: false,
            unreadable: false,
            file_count: 3,
            dir_count: 2,
            byte_count: 100,
            roots: HostRoots::default(),
        }
    }

    /// AC-FS-10: an existing file target needs `overwrite`; a second copy without the
    /// flag is refused `FILE_EXISTS`, and with the flag it passes.
    #[test]
    fn copy_refuses_an_existing_target_without_overwrite() {
        let target = "D:\\Backup\\a.txt";
        let scan = win_scan(target, true, false);
        let refused = decide_file_op_target(&scan, target, false, false, "copy to", &[]);
        assert!(!refused.allow, "{}", refused.reason);
        assert_eq!(refused.code, "FILE_EXISTS");
        assert!(decide_file_op_target(&scan, target, false, true, "copy to", &[]).allow);
        // No flag is needed when the target path is free.
        let missing = win_scan(target, false, false);
        assert!(decide_file_op_target(&missing, target, true, false, "copy to", &[]).allow);
    }

    /// AC-FS-10, ADR-0017 §15: an existing directory target is refused in all cases,
    /// with or without `overwrite`, because the boundary rejects a directory target.
    #[test]
    fn copy_refuses_a_directory_overwrite_before_the_network() {
        let target = "D:\\Backup\\logs";
        let scan = win_scan(target, true, true);
        for overwrite in [false, true] {
            let decision = decide_file_op_target(&scan, target, true, overwrite, "copy to", &[]);
            assert!(!decision.allow, "overwrite={overwrite}");
            assert_eq!(decision.code, "PATH_IS_DIRECTORY");
        }
    }

    /// TR-FS-09, ADR-0017 §16: a copy reads the source, so a source under a protected
    /// root is allowed, while the target still needs the allowlist.
    #[test]
    fn copy_source_may_be_under_a_protected_root() {
        let source = "C:\\Windows\\Logs\\app.log";
        let scan = source_scan(source, false);
        assert!(
            decide_file_op_source(&scan, source, false, false, &[]).allow,
            "a read-only source under a protected root must be allowed"
        );

        let target = "C:\\ProgramData\\Vendor\\app.log";
        let protected = roots(&[("ProgramData", "C:\\ProgramData")]);
        let scan = win_scan(target, false, false);
        let scan = WriteScan {
            roots: protected,
            ..scan
        };
        assert_eq!(
            decide_file_op_target(&scan, target, false, false, "copy to", &[]).code,
            "PATH_PROTECTED"
        );
        assert!(
            decide_file_op_target(
                &scan,
                target,
                false,
                false,
                "copy to",
                &paths(&["C:\\ProgramData\\Vendor"])
            )
            .allow
        );
    }

    /// TR-FS-09, ADR-0017 §17: a directory source that holds a name surrogate is
    /// refused, because `Copy-Item -Recurse` would follow it; a move that does not
    /// recurse is not blocked by a nested link.
    #[test]
    fn copy_source_tree_with_a_nested_link_is_refused() {
        let source = "D:\\Data\\tree";
        let linked = SourceScan {
            nested_link: true,
            ..source_scan(source, true)
        };
        assert_eq!(
            decide_file_op_source(&linked, source, false, true, &[]).code,
            "NESTED_REPARSE_POINT"
        );
        assert!(decide_file_op_source(&linked, source, false, false, &[]).allow);

        let link = SourceScan {
            link_type: Some("Junction".to_owned()),
            is_directory: false,
            ..source_scan(source, false)
        };
        assert_eq!(
            decide_file_op_source(&link, source, false, true, &[]).code,
            "PATH_REPARSE_POINT"
        );
    }

    /// TR-FS-09, item 2: a recursive copy refuses a directory source whose tree is not
    /// fully readable; a move that does not recurse is not blocked by it.
    #[test]
    fn copy_source_tree_that_is_unreadable_is_refused() {
        let source = "D:\\Data\\tree";
        let unreadable = SourceScan {
            unreadable: true,
            ..source_scan(source, true)
        };
        let refused = decide_file_op_source(&unreadable, source, false, true, &[]);
        assert!(!refused.allow, "{}", refused.reason);
        assert_eq!(refused.code, "SOURCE_UNREADABLE");
        assert!(decide_file_op_source(&unreadable, source, false, false, &[]).allow);
    }

    /// TR-FS-10, item 4: a case-only change names the same object, so it is a rename
    /// and not the same path.
    #[test]
    fn case_only_change_is_detected() {
        assert!(is_case_only_change("D:\\Data\\a.txt", "D:\\Data\\A.txt"));
        assert!(is_case_only_change("D:\\Data\\A.TXT", "D:\\Data\\a.txt"));
        assert!(!is_case_only_change("D:\\Data\\a.txt", "D:\\Data\\a.txt"));
        assert!(!is_case_only_change("D:\\Data\\a.txt", "D:\\Data\\b.txt"));
        assert!(!is_case_only_change("D:\\Data\\a.txt", "D:\\Other\\A.txt"));
        assert!(!is_case_only_change("", "D:\\Data\\a.txt"));
    }

    /// AC-FS-11, ADR-0017 §18: one volume renames; across volumes a file is copied
    /// and deleted, and a directory is refused.
    #[test]
    fn move_volume_decides_rename_copy_delete_and_refuses_a_directory() {
        assert!(decide_move_volume("C:\\a.txt", "C:\\b.txt", false).allow);
        assert!(decide_move_volume("C:\\a.txt", "D:\\b.txt", false).allow);
        assert_eq!(
            decide_move_volume("C:\\dir", "D:\\dir", true).code,
            "CROSS_VOLUME_MOVE"
        );
        assert!(decide_move_volume("C:\\dir", "C:\\dir2", true).allow);
        assert!(
            decide_move_volume("\\\\srv\\share1\\a.txt", "\\\\srv\\share1\\b.txt", false).allow
        );
        assert!(!same_volume("\\\\srv\\share1\\a", "\\\\srv\\share2\\b"));
        assert_eq!(volume_of("c:/logs/a").as_deref(), Some("C:"));
        assert_eq!(volume_of("C:"), None);
    }

    /// TR-FS-10, ADR-0017 §19: a new name is one file name, not a path. A separator,
    /// a `.`/`..` component, a reserved device name, a trailing dot or space and an
    /// invalid character are refused.
    #[test]
    fn new_name_refuses_a_separator_reserved_name_and_trailing_dot() {
        assert!(decide_new_name("app.log").allow);
        for bad in [
            "sub\\app.log",
            "sub/app.log",
            "..",
            ".",
            "NUL",
            "con.txt",
            "COM1",
            "COM0",
            "LPT0",
            "CONIN$",
            "CONOUT$",
            "NUL .txt",
            "COM\u{00b9}",
            "LPT\u{00b3}.log",
            "app.log.",
            "app.log ",
            "a:b",
            "a*b",
            "a\u{1}b",
            "",
        ] {
            let decision = decide_new_name(bad);
            assert!(!decision.allow, "{bad:?} must be refused");
            assert_eq!(decision.code, "RENAME_NAME_INVALID", "{bad:?}");
        }
    }

    /// TR-FS-09/10: a copy or a move onto the same path, into the source's subtree,
    /// or out of the target's subtree is refused before the network.
    #[test]
    fn path_relation_refuses_recursion_and_the_same_path() {
        assert_eq!(
            decide_path_relation("D:\\a", "D:\\a", true).code,
            "SAME_PATH"
        );
        assert_eq!(
            decide_path_relation("D:\\a", "D:\\a\\b", true).code,
            "TARGET_INSIDE_SOURCE"
        );
        assert_eq!(
            decide_path_relation("D:\\a\\b", "D:\\a", true).code,
            "SOURCE_INSIDE_TARGET"
        );
        assert!(decide_path_relation("D:\\a", "D:\\b", true).allow);
        // A file source cannot contain a target, but the same path is still refused.
        assert_eq!(
            decide_path_relation("D:\\a.txt", "D:\\a.txt", false).code,
            "SAME_PATH"
        );
        assert!(decide_path_relation("c:\\A", "D:\\a", true).allow);
        assert_eq!(
            decide_path_relation("c:\\A", "C:\\a\\b", true).code,
            "TARGET_INSIDE_SOURCE"
        );
    }

    /// TR-FS-11, ADR-0017 §20: a create checks the shallowest absent level under the
    /// strict-descendant rule, and an existing target is refused with a clear message.
    #[test]
    fn create_directory_refuses_a_missing_ancestor_outside_the_entry() {
        let requested = "C:\\ProgramData\\X\\Y\\a";
        let scan = WriteScan {
            full_name: requested.to_owned(),
            dotnet_full_name: requested.to_owned(),
            exists: false,
            is_directory: false,
            link_type: None,
            roots: roots(&[("ProgramData", "C:\\ProgramData")]),
        };
        // The entry covers the final path but not the shallowest absent level
        // `C:\ProgramData\X`, so the create is refused.
        let decision = decide_create_directory(
            &scan,
            requested,
            Some("C:\\ProgramData\\X"),
            &paths(&["C:\\ProgramData\\X\\Y"]),
        );
        assert!(!decision.allow, "{}", decision.reason);
        assert_eq!(decision.code, "PATH_PROTECTED");
        // An entry that covers the shallowest level also covers the whole chain.
        let decision = decide_create_directory(
            &scan,
            requested,
            Some("C:\\ProgramData\\X"),
            &paths(&["C:\\ProgramData"]),
        );
        assert!(decision.allow, "{}", decision.reason);
        // An existing target is refused with a message that names the tool.
        let existing = WriteScan {
            exists: true,
            is_directory: true,
            ..scan
        };
        let decision = decide_create_directory(&existing, requested, None, &[]);
        assert!(!decision.allow);
        assert_eq!(decision.code, "TARGET_EXISTS");
        assert!(
            decision.reason.contains("already exists"),
            "{}",
            decision.reason
        );
    }

    /// TR-FS-10, item 6: a move or a rename removes its source from a protected place,
    /// so a protected source without an allowlist entry is refused.
    #[test]
    fn move_source_under_a_protected_root_needs_the_allowlist() {
        let source = "C:\\Windows\\System32\\x.dll";
        let scan = SourceScan {
            roots: roots(&[("SystemRoot", "C:\\Windows")]),
            ..source_scan(source, false)
        };
        let refused = decide_file_op_source(&scan, source, true, false, &[]);
        assert!(!refused.allow, "{}", refused.reason);
        assert_eq!(refused.code, "PATH_PROTECTED");
        assert!(
            decide_file_op_source(
                &scan,
                source,
                true,
                false,
                &paths(&["C:\\Windows\\System32"])
            )
            .allow
        );
        // A copy only reads the source, so the same path is allowed without an entry.
        assert!(decide_file_op_source(&scan, source, false, false, &[]).allow);
    }
}
