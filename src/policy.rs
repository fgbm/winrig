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

/// Элемент списка хостов, разрешающий любой хост (ADR-0015 §7).
pub const ANY_HOST: &str = "*";

/// Истина для loopback-литерала: `localhost`, адрес из `127.0.0.0/8` или
/// `::1` (в том числе в квадратных скобках).
///
/// DNS не разрешается: имя, которое лишь указывает на loopback, литералом не
/// является, потому что ответ DNS контролирует не оператор (ADR-0015 §6).
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

/// Решает, разрешён ли хост (Q-03, ADR-0015 §6–7).
///
/// Пустой список разрешает только loopback-литералы; `*` — любой хост;
/// элемент с ведущей `.` — суффикс; иначе точное совпадение без учёта регистра.
#[must_use]
pub fn host_allowed(host: &str, allowed_hosts: &[String]) -> bool {
    let candidate = host.trim().to_lowercase();
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
        let reason = if allowed_hosts.iter().all(|raw| raw.trim().is_empty()) {
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

/// Разбирает ответ скана хоста в JSON-объект.
///
/// Нечитаемый ответ — не «безопасно по умолчанию», а причина отказа
/// (fail-closed).
fn scan_object(raw: &str) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let value: serde_json::Value = serde_json::from_str(raw.trim())
        .map_err(|error| format!("Pre-scan returned an unreadable result: {error}"))?;
    match value {
        serde_json::Value::Object(object) => Ok(object),
        _ => Err("Pre-scan returned a non-object result.".to_owned()),
    }
}

/// Непустое строковое поле скана.
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

/// Булево поле скана.
fn required_bool(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<bool, String> {
    object
        .get(key)
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| format!("Pre-scan result is missing {key}."))
}

/// Защищённые корни, которые хост прочитал из своих системных переменных
/// (TR-FS-06, ADR-0015 §10–12).
///
/// Лексический список `PROTECTED_DIRS` знает только `C:`; эти корни называют
/// фактическое расположение системы, на каком бы томе она ни стояла.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostRoots {
    /// Пары (имя корня, путь на хосте).
    roots: Vec<(String, String)>,
}

impl HostRoots {
    /// Имена корней в том порядке, в каком их отдаёт скан (`ps::HOST_ROOTS`).
    const NAMES: [&'static str; 5] = [
        "SystemRoot",
        "ProgramFiles",
        "ProgramFilesX86",
        "ProgramData",
        "Users",
    ];

    /// Читает свойство `Roots` из скана.
    ///
    /// Пустой корень пропускается: `ProgramFiles(x86)` на 32-битной системе
    /// отсутствует законно. Пустой `SystemRoot` — отказ: без него проверка
    /// теряет главный корень (ADR-0015 §11).
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

    /// Корень, внутри которого лежит путь: `(имя, путь корня)`.
    #[must_use]
    pub fn containing(&self, path: &str) -> Option<(&str, &str)> {
        let norm = normalize_windows_path(path);
        if norm.is_empty() {
            return None;
        }
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

/// Отказ, если путь, разрешённый хостом, защищён лексически или лежит внутри
/// корня хоста (DR-6, TR-FS-06).
fn refuse_resolved(
    resolved: &str,
    roots: &HostRoots,
    requested: &str,
    verb: &str,
) -> Option<PolicyDecision> {
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
    /// Защищённые корни хоста (TR-SEC-04, ADR-0015 §10).
    pub roots: HostRoots,
}

impl DeleteScan {
    /// Разбирает JSON-ответ предварительного скана.
    ///
    /// # Errors
    ///
    /// Возвращает текст ошибки, если ответ не JSON-объект или в нём нет
    /// обязательных защитных полей `FullName`, `IsReparsePoint`, `TotalItems`,
    /// `NestedReparsePoint` и `Roots` с непустым `SystemRoot`.
    /// Отсутствующее защитное поле — не «безопасно по умолчанию», а признак
    /// нечитаемого скана: вызывающая сторона обязана отказать (ADR-0005 §5,
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
    /// Защищённые корни хоста (TR-SEC-04, ADR-0015 §10).
    pub roots: HostRoots,
}

impl FileScan {
    /// Разбирает JSON-ответ предварительного скана файла.
    ///
    /// # Errors
    ///
    /// Возвращает текст ошибки, если ответ не JSON-объект или в нём нет
    /// обязательных полей `FullName`, `IsDirectory` и `Roots` с непустым
    /// `SystemRoot`.
    pub fn from_json(raw: &str) -> Result<Self, String> {
        let object = scan_object(raw)?;
        Ok(Self {
            full_name: required_str(&object, "FullName")?,
            is_directory: required_bool(&object, "IsDirectory")?,
            roots: HostRoots::from_scan(&object)?,
        })
    }
}

/// Результат скана цели записи, полученный от хоста (TR-FS-06).
///
/// Путь разрешается дважды, потому что запись идёт двумя механизмами: куски
/// пишет .NET (`[IO.File]`), который разрешает относительный путь от текущего
/// каталога процесса, а цель заменяет `Move-Item`, который разрешает его от
/// расположения PowerShell. Проверяются оба.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteScan {
    /// Путь, как его разрешит PowerShell для `-LiteralPath`.
    pub full_name: String,
    /// Путь, как его разрешит .NET (`[IO.Path]::GetFullPath`).
    pub dotnet_full_name: String,
    /// Существует ли цель.
    pub exists: bool,
    /// Защищённые корни хоста.
    pub roots: HostRoots,
}

impl WriteScan {
    /// Разбирает JSON-ответ скана записи.
    ///
    /// # Errors
    ///
    /// Возвращает текст ошибки, если нет `FullName`, `DotNetFullName`,
    /// `Exists` или `Roots` с непустым `SystemRoot` (fail-closed).
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

/// Решение по скану записи: защищённый путь в любом из двух разрешений, затем
/// правило перезаписи (TR-FS-03, TR-FS-06).
#[must_use]
pub fn decide_write_scan(scan: &WriteScan, requested: &str, overwrite: bool) -> PolicyDecision {
    for resolved in [&scan.full_name, &scan.dotnet_full_name] {
        if let Some(refusal) = refuse_resolved(resolved, &scan.roots, requested, "write to") {
            return refusal;
        }
    }
    decide_overwrite(requested, scan.exists, overwrite)
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
    if let Some(refusal) = refuse_resolved(&scan.full_name, &scan.roots, requested, "delete") {
        return refusal;
    }
    PolicyDecision::allow("file delete scan is safe")
}

/// Решение по результату предварительного скана (DR-6, ADR-0005 §5).
///
/// Проверяет канонический путь хоста (`FullName`) по лексическому списку и по
/// корням хоста, точку повторной обработки и предохранительный лимит
/// элементов. Любая непройденная проверка — отказ.
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

    /// AC-SEC05-1: пустой список разрешает только loopback-литералы; имя,
    /// которое лишь разрешается в loopback, литералом не является (TR-SEC-14).
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

    /// AC-SEC05-4: элемент `*` разрешает любой хост, но только отдельным
    /// элементом (TR-SEC-14).
    #[test]
    fn star_admits_any_host() {
        assert!(host_allowed("anything.example.com", &hosts(&["*"])));
        assert!(host_allowed("10.0.0.1", &hosts(&["host1", "*"])));
        assert!(!host_allowed("web.example.com", &hosts(&["*.example.com"])));
    }

    /// Непустой список не подмешивает loopback: оператор перечислил хосты сам.
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
            roots: HostRoots::default(),
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
        // Корень — обычный каталог, но внутри junction: рекурсивное удаление
        // могло бы уйти в цель. DR-6 требует отказа.
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
        // Fail-closed: скан без признака вложенной точки не читается.
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

    /// AC-FS-07: корни читаются из скана; пустой необязательный пропускается,
    /// а пустой или отсутствующий `SystemRoot` — отказ (ADR-0015 §11).
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

    /// AC-FS-07: система на `D:` защищена по фактическому расположению, хотя
    /// лексический список знает только `C:`.
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

    /// AC-SEC04-5: удаление отвергает путь внутри корня хоста.
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

    /// AC-FS-07: запись отвергается, если в корень хоста попадает любое из
    /// двух разрешений пути, а обычный путь проходит к правилу перезаписи.
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
