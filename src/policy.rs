//! Чистые решения «можно/нельзя» без WinRM (ADR-0003, ADR-0005, DR-6, DR-7).
//!
//! Модуль не касается сети и транспорта: он нормализует вход и выносит
//! вердикт. Порт `agent/policy.py`; семантика нормализации путей повторяет
//! `ntpath.normpath`/`ntpath.splitroot` из стандартной библиотеки CPython,
//! потому что защита путей должна срабатывать для любой формы записи.

use crate::config::{MAX_PORT, MIN_PORT};

/// Системные каталоги в канонической форме (верхний регистр, один `\`).
const PROTECTED_DIRS: [&str; 6] = [
    "C:\\WINDOWS",
    "C:\\WINDOWS\\SYSTEM32",
    "C:\\PROGRAM FILES",
    "C:\\PROGRAM FILES (X86)",
    "C:\\USERS",
    "C:\\PROGRAMDATA",
];

/// Префиксы устройств Windows, снимаемые перед нормализацией.
const DEVICE_PREFIXES: [&str; 3] = ["\\\\?\\", "\\\\.\\", "\\??\\"];
/// Префиксы UNC-устройств, приводящие к обычному UNC-пути.
const UNC_PREFIXES: [&str; 2] = ["\\\\?\\UNC\\", "\\??\\UNC\\"];

/// Недопустимый ввод политики: сообщение называет параметр и ожидание.
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

/// Вердикт политики: разрешение/отказ, причина и машинный код.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    /// Разрешено ли действие.
    pub allow: bool,
    /// Человекочитаемая причина.
    pub reason: String,
    /// Стабильный машинный код (`OK`, `HOST_NOT_ALLOWED`, ...).
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

/// Схлопывает любую серию обратных слэшей в один.
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

/// Разбивает путь на (диск, корень, хвост) по правилам `ntpath.splitroot`.
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

/// Лексическая нормализация Windows-пути (`ntpath.normpath`).
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

/// Приводит путь к канонической форме для сравнения (DR-6).
///
/// `/` → `\`; снимаются префиксы `\\?\UNC\` и `\??\UNC\` (в обычный UNC
/// `\\server\share`), затем `\\?\`, `\\.\` и `\??\`; повторные `\`
/// схлопываются; `.` и `..` схлопываются лексически; хвостовые точки и пробелы
/// отбрасываются у каждого компонента (Windows их не различает); завершающий
/// `\` убирается, кроме корня тома; результат — в верхнем регистре. Для UNC
/// `\\server\share` ведущие два `\` сохраняются.
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

/// `^[A-Z]:\\$` — корень тома.
fn is_volume_root(norm: &str) -> bool {
    let bytes = norm.as_bytes();
    bytes.len() == 3 && bytes[0].is_ascii_uppercase() && bytes[1] == b':' && bytes[2] == b'\\'
}

/// `^VOLUME\{[^}]*\}$` — сам том в форме `Volume{GUID}`.
fn is_volume_guid(norm: &str) -> bool {
    let Some(rest) = norm.strip_prefix("VOLUME{") else {
        return false;
    };
    let Some(inner) = rest.strip_suffix('}') else {
        return false;
    };
    !inner.contains('}')
}

/// `^VOLUME\{[^}]*\}\\$` — корень тома в форме `Volume{GUID}\`.
fn is_volume_guid_root(norm: &str) -> bool {
    let Some(rest) = norm.strip_prefix("VOLUME{") else {
        return false;
    };
    let Some(inner) = rest.strip_suffix("}\\") else {
        return false;
    };
    !inner.contains('}')
}

/// `^\\\\[^\\]+\\[^\\]+$` — корень UNC-шара ровно на уровне шара.
fn is_unc_share_root(norm: &str) -> bool {
    let Some(rest) = norm.strip_prefix("\\\\") else {
        return false;
    };
    let Some((server, share)) = rest.split_once('\\') else {
        return false;
    };
    !server.is_empty() && !share.is_empty() && !share.contains('\\')
}

/// Истина для корней томов, UNC-корней шара и системных каталогов (DR-6).
///
/// Защищёнными считаются корни любых томов (`X:\`), корень UNC-шара
/// `\\server\share` ровно на уровне шара (подкаталоги внутри шара не защищены),
/// корень тома в форме `\\?\Volume{GUID}\` и системные каталоги вместе с их
/// поддеревом (ADR-0005 §5, AC-SEC04-1).
#[must_use]
pub fn is_protected_path(path: &str) -> bool {
    let norm = normalize_windows_path(path);
    if norm.is_empty() {
        return false;
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

/// Q-03: пустой список разрешает всё; `.` — суффикс, иначе точное совпадение.
#[must_use]
pub fn host_allowed(host: &str, allowed_hosts: &[String]) -> bool {
    if allowed_hosts.is_empty() {
        return true;
    }
    let candidate = host.trim().to_lowercase();
    for raw in allowed_hosts {
        let entry = raw.trim().to_lowercase();
        if entry.is_empty() {
            continue;
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

/// Возвращает порт без изменений или ошибку вне диапазона 1..65535.
///
/// # Errors
///
/// [`PolicyError`], если порт вне `MIN_PORT..=MAX_PORT`.
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

/// `None` — понижение проверки TLS допустимо; иначе причина отказа.
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

/// Решение по хосту против allowlist.
#[must_use]
pub fn decide_host(host: &str, allowed_hosts: &[String]) -> PolicyDecision {
    if host_allowed(host, allowed_hosts) {
        PolicyDecision::allow("host is allowed")
    } else {
        PolicyDecision::deny(
            format!("host {host:?} is not in WINRIG_ALLOWED_HOSTS"),
            "HOST_NOT_ALLOWED",
        )
    }
}

/// Решение по диапазону порта.
#[must_use]
pub fn decide_port(port: Option<i64>) -> PolicyDecision {
    match validate_port(port) {
        Ok(_) => PolicyDecision::allow("port is valid"),
        Err(error) => PolicyDecision::deny(error.to_string(), "PORT_OUT_OF_RANGE"),
    }
}

/// Решение по режиму проверки TLS.
#[must_use]
pub fn decide_tls(verify_cert: bool, allow_insecure_tls: bool) -> PolicyDecision {
    match tls_decision(verify_cert, allow_insecure_tls) {
        Some((_, reason)) => PolicyDecision::deny(reason, "TLS_VERIFY_NOT_ALLOWED"),
        None => PolicyDecision::allow("TLS policy satisfied"),
    }
}

/// Решение по рекурсивному удалению пути.
#[must_use]
pub fn decide_delete_path(path: &str) -> PolicyDecision {
    if is_protected_path(path) {
        PolicyDecision::deny(
            format!("refusing to delete protected path: {path:?}"),
            "PATH_PROTECTED",
        )
    } else {
        PolicyDecision::allow("path is not protected")
    }
}

/// Вердикт на запись файла: защищённый путь отвергается до сети (TR-FS-02).
///
/// Список тот же, что у удаления: возможность перезаписать системный файл не
/// отличается по последствиям от возможности его удалить.
#[must_use]
pub fn decide_write_path(path: &str) -> PolicyDecision {
    if is_protected_path(path) {
        PolicyDecision::deny(
            format!("refusing to write to protected path: {path:?}"),
            "PATH_PROTECTED",
        )
    } else {
        PolicyDecision::allow("path is not protected")
    }
}

/// Вердикт на перезапись: существующий файл заменяется только по флагу
/// (TR-FS-03).
///
/// Решение отделено от инструмента, потому что иначе его нельзя проверить:
/// путь записи идёт через подтверждение и `RequestContext`, которого тесты не
/// строят.
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

/// Результат предварительного скана удаляемого каталога, полученный от хоста.
///
/// `full_name` — путь, как его разрешил сам Windows-хост: только он раскрывает
/// короткие 8.3-имена и приводит точку повторной обработки к реальной цели.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteScan {
    /// Канонический путь, возвращённый хостом.
    pub full_name: String,
    /// Является ли каталог точкой повторной обработки (junction/symlink).
    pub is_reparse_point: bool,
    /// Сколько всего элементов найдено в поддереве.
    pub total_items: i64,
    /// Сколько файлов.
    pub file_count: i64,
    /// Сколько подкаталогов.
    pub dir_count: i64,
    /// Есть ли внутри поддерева точки повторной обработки.
    ///
    /// `Remove-Item -Recurse` в Windows PowerShell 5.1 может пройти сквозь
    /// junction и удалить его цель, поэтому вложенная точка — такая же причина
    /// отказа, как и корневая (DR-6).
    pub nested_reparse_point: bool,
}

impl DeleteScan {
    /// Разбирает JSON-ответ предварительного скана.
    ///
    /// # Errors
    ///
    /// Возвращает текст ошибки, если ответ не JSON-объект или в нём нет
    /// обязательных защитных полей `FullName`, `IsReparsePoint` и `TotalItems`.
    /// Отсутствующее защитное поле — не «безопасно по умолчанию», а признак
    /// нечитаемого скана: вызывающая сторона обязана отказать (ADR-0005 §5,
    /// fail-closed).
    pub fn from_json(raw: &str) -> Result<Self, String> {
        let value: serde_json::Value = serde_json::from_str(raw.trim())
            .map_err(|error| format!("Pre-scan returned an unreadable result: {error}"))?;
        let object = value
            .as_object()
            .ok_or_else(|| "Pre-scan returned a non-object result.".to_owned())?;
        let full_name = object
            .get("FullName")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "Pre-scan result is missing FullName.".to_owned())?;
        let is_reparse_point = object
            .get("IsReparsePoint")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| "Pre-scan result is missing IsReparsePoint.".to_owned())?;
        let total_items = object
            .get("TotalItems")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| "Pre-scan result is missing TotalItems.".to_owned())?;
        let nested_reparse_point = object
            .get("NestedReparsePoint")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| "Pre-scan result is missing NestedReparsePoint.".to_owned())?;
        Ok(Self {
            full_name: full_name.to_owned(),
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
        })
    }
}

/// Результат предварительного скана одного файла, полученный от хоста.
///
/// Нужен, чтобы отказать до отправки удаления, если путь разрешился в
/// защищённый или оказался каталогом (DR-6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileScan {
    /// Канонический путь, возвращённый хостом.
    pub full_name: String,
    /// Является ли цель каталогом.
    pub is_directory: bool,
}

impl FileScan {
    /// Разбирает JSON-ответ предварительного скана файла.
    ///
    /// # Errors
    ///
    /// Возвращает текст ошибки, если ответ не JSON-объект или в нём нет
    /// обязательных полей `FullName` и `IsDirectory`.
    pub fn from_json(raw: &str) -> Result<Self, String> {
        let value: serde_json::Value = serde_json::from_str(raw.trim())
            .map_err(|error| format!("Pre-scan returned an unreadable result: {error}"))?;
        let object = value
            .as_object()
            .ok_or_else(|| "Pre-scan returned a non-object result.".to_owned())?;
        let full_name = object
            .get("FullName")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "Pre-scan result is missing FullName.".to_owned())?;
        let is_directory = object
            .get("IsDirectory")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| "Pre-scan result is missing IsDirectory.".to_owned())?;
        Ok(Self {
            full_name: full_name.to_owned(),
            is_directory,
        })
    }
}

/// Решение по результату скана одиночного файла (DR-6).
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
    if is_protected_path(&scan.full_name) {
        return PolicyDecision::deny(
            format!(
                "refusing to delete a protected path (resolved by the host to {}): {requested}",
                scan.full_name
            ),
            "PATH_PROTECTED",
        );
    }
    PolicyDecision::allow("file delete scan is safe")
}

/// Решение по результату предварительного скана (DR-6, ADR-0005 §5).
///
/// Проверяет канонический путь хоста (`FullName`), точку повторной обработки и
/// предохранительный лимит элементов. Любая непройденная проверка — отказ.
#[must_use]
pub fn decide_delete_scan(scan: &DeleteScan, requested: &str, cap: i64) -> PolicyDecision {
    if is_protected_path(&scan.full_name) {
        return PolicyDecision::deny(
            format!(
                "refusing to delete a protected path (resolved by the host to {}): {requested}",
                scan.full_name
            ),
            "PATH_PROTECTED",
        );
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

    #[test]
    fn host_allowed_variants() {
        assert!(host_allowed("anything.example.com", &[]));
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

    /// TR-FS-02: запись охраняется тем же списком, что и удаление. Инструмент,
    /// умеющий перезаписать системный файл, равносилен удалению.
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

    /// TR-FS-03: существующий файл заменяется только по явному флагу, а
    /// создание нового не требует ничего.
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

    /// TR-FS-02: отказ говорит про запись, а не про удаление — иначе агент
    /// решит, что вызвал не тот инструмент.
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
            r#"{"FullName":"C:\\App\\link","IsReparsePoint":true,"FileCount":2,"DirCount":1,"TotalItems":3,"NestedReparsePoint":false}"#,
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
        // Fail-closed: отсутствие защитного поля — не «безопасно по умолчанию».
        assert!(DeleteScan::from_json(r#"{"FullName":"C:\\App"}"#).is_err());
        assert!(DeleteScan::from_json(r#"{"FullName":"C:\\App","TotalItems":1}"#).is_err());
        assert!(DeleteScan::from_json(r#"{"FullName":"C:\\App","IsReparsePoint":false}"#).is_err());
    }

    #[test]
    fn delete_scan_refuses_reparse_point() {
        // DR-6/AC-SEC04-2: junction на защищённый каталог не должен удаляться.
        let scan = DeleteScan {
            full_name: "C:\\App\\link".to_owned(),
            is_reparse_point: true,
            total_items: 1,
            file_count: 1,
            dir_count: 0,
            nested_reparse_point: false,
        };
        let decision = decide_delete_scan(&scan, "C:\\App\\link", 5000);
        assert!(!decision.allow);
        assert_eq!(decision.code, "PATH_REPARSE_POINT");
    }

    #[test]
    fn delete_scan_refuses_host_resolved_protected_path() {
        // Лексическая форма не защищена, но хост разрешил путь в системный.
        let scan = DeleteScan {
            full_name: "C:\\Windows\\System32".to_owned(),
            is_reparse_point: false,
            total_items: 1,
            file_count: 1,
            dir_count: 0,
            nested_reparse_point: false,
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
        };
        assert!(decide_delete_scan(&scan, "C:\\App\\logs", 5000).allow);
    }

    #[test]
    fn delete_scan_refuses_nested_reparse_point() {
        // Корень — обычный каталог, но внутри junction: рекурсивное удаление
        // могло бы уйти в цель. DR-6 требует отказа.
        let scan = DeleteScan {
            full_name: "C:\\App\\logs".to_owned(),
            is_reparse_point: false,
            total_items: 10,
            file_count: 9,
            dir_count: 1,
            nested_reparse_point: true,
        };
        let decision = decide_delete_scan(&scan, "C:\\App\\logs", 5000);
        assert!(!decision.allow);
        assert_eq!(decision.code, "NESTED_REPARSE_POINT");
    }

    #[test]
    fn delete_scan_requires_nested_reparse_field() {
        // Fail-closed: скан без признака вложенной точки не читается.
        assert!(
            DeleteScan::from_json(
                r#"{"FullName":"C:\\App","IsReparsePoint":false,"TotalItems":1}"#
            )
            .is_err()
        );
        let scan = DeleteScan::from_json(
            r#"{"FullName":"C:\\App","IsReparsePoint":false,"TotalItems":1,"NestedReparsePoint":false}"#,
        )
        .expect("valid scan");
        assert!(!scan.nested_reparse_point);
    }

    #[test]
    fn file_scan_parses_and_rejects_missing_fields() {
        let scan = FileScan::from_json(r#"{"FullName":"C:\\App\\a.txt","IsDirectory":false}"#)
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
        };
        assert_eq!(
            decide_file_delete(&directory, "C:\\App\\logs").code,
            "PATH_IS_DIRECTORY"
        );

        let protected = FileScan {
            full_name: "C:\\Windows\\System32\\drivers\\etc\\hosts".to_owned(),
            is_directory: false,
        };
        assert_eq!(
            decide_file_delete(&protected, "C:\\App\\shortcut").code,
            "PATH_PROTECTED"
        );

        let ordinary = FileScan {
            full_name: "C:\\App\\a.txt".to_owned(),
            is_directory: false,
        };
        assert!(decide_file_delete(&ordinary, "C:\\App\\a.txt").allow);
    }
}
