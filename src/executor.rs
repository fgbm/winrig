//! Чистые функции исполнения: редактирование секретов, усечение, поля аудита.
//!
//! Модуль не знает о WinRM (ADR-0003): только текстовые преобразования.
//! Порт `agent/executor.py`. В Rust отдельная off-loop обёртка не нужна:
//! WinRM-вызов асинхронен по своей природе (TR-REL-01).

/// Предел вывода, возвращаемого агенту, в символах.
pub const MAX_OUTPUT_CHARS: usize = 60_000;

/// Предел поля аудита в символах.
pub const AUDIT_FIELD_MAX_CHARS: usize = 200;

/// Граничная линия блока аудита (TR-SEC-09).
pub const SEPARATOR: &str =
    "════════════════════════════════════════════════════════════════════════════════";

/// Чем заменяется секрет.
const REDACTED: &str = "***";

/// Заменяет секреты на `***` во всех формах (DR-4, Q-02).
///
/// Редактируются и сырой вид, и PowerShell-экранированный (`'` → `''`), чтобы
/// секрет не утёк через экранирование. Секреты короче `min_length` и пустые не
/// трогаются: иначе вывод искажался бы. Более длинные секреты заменяются
/// первыми, чтобы вложенные не оставляли хвостов. Функция идемпотентна.
#[must_use]
pub fn redact(text: &str, secrets: &[String], min_length: usize) -> String {
    if text.is_empty() {
        return String::new();
    }
    let mut candidates: Vec<&str> = secrets
        .iter()
        .map(String::as_str)
        .filter(|secret| !secret.is_empty() && secret.chars().count() >= min_length)
        .collect();
    candidates.sort_by_key(|secret| std::cmp::Reverse(secret.chars().count()));
    let mut result = text.to_owned();
    for secret in candidates {
        let escaped = secret.replace('\'', "''");
        // Обе формы могут совпасть, если в секрете нет `'`; тогда вторая
        // замена — no-op (идемпотентность).
        for form in [secret, escaped.as_str()] {
            result = result.replace(form, REDACTED);
        }
    }
    result
}

/// Усекает вывод до `limit` с пометкой о полном размере.
#[must_use]
pub fn truncate(text: &str, limit: usize) -> String {
    let total = text.chars().count();
    if total <= limit {
        return text.to_owned();
    }
    let head: String = text.chars().take(limit).collect();
    format!("{head}\n\n--- truncated ({total} chars total, showing first {limit}) ---")
}

/// Делает строку безопасной для одной строки аудита (TR-SEC-09).
///
/// Переводы строк заменяются пробелом, разделитель `═` — на `-`, длина
/// ограничивается, чтобы поле не подделывало структуру блока аудита.
#[must_use]
pub fn escape_log_field(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .map(|c| match c {
            '\r' | '\n' => ' ',
            '═' => '-',
            other => other,
        })
        .collect();
    cleaned.chars().take(AUDIT_FIELD_MAX_CHARS).collect()
}

/// Значение, пригодное для одной строки основного журнала (TR-SEC-09).
///
/// Хост и идентификатор сессии приходят из аргументов инструмента, поэтому
/// переводы строк схлопываются в пробел, чтобы значение не подделало строку.
#[must_use]
pub fn sanitize_log_value(value: &str) -> String {
    value.replace(['\r', '\n'], " ")
}

/// Делает тело аудита неспособным подделать границу блока (TR-SEC-09).
///
/// Тело (команда и вывод внешней системы) остаётся многострочным, поэтому
/// нейтрализуется только последовательность разделителя. Строка-замена
/// начинается с `[`, такую строку тело тоже не может выдать за маркер.
#[must_use]
pub fn neutralize_separator(body: &str) -> String {
    body.replace(SEPARATOR, "[separator]")
}

/// Делает значение диалога подтверждения неспособным подделать его структуру.
///
/// Имена сервисов, PID-значения, ключи реестра, пути и версии ПО приходят из
/// аргументов инструмента и попадают в сообщение elicitation. Переводы строк
/// схлопываются в пробел, разделитель `═` заменяется на `-`, длина
/// ограничивается, чтобы аргумент не мог вставить собственную «строку» диалога
/// или разорвать его до неверного согласия (DR-5).
#[must_use]
pub fn sanitize_prompt_value(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .map(|c| match c {
            '\r' | '\n' => ' ',
            '═' => '-',
            other => other,
        })
        .collect();
    cleaned.chars().take(AUDIT_FIELD_MAX_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn redacts_raw_and_powershell_escaped_form() {
        let secret = "pa'ss";
        let text = "raw=pa'ss escaped=pa''ss done";
        let result = redact(text, &secrets(&[secret]), 4);
        assert!(!result.contains(secret));
        assert!(!result.contains("pa''ss"));
        assert_eq!(result.matches("***").count(), 2);
    }

    #[test]
    fn short_secret_is_not_redacted() {
        assert_eq!(
            redact("port=abc value", &secrets(&["abc"]), 4),
            "port=abc value"
        );
    }

    #[test]
    fn secret_below_threshold_preserves_output() {
        for length in 1..=3 {
            let secret = "x".repeat(length);
            let text = format!("value={secret}!");
            assert_eq!(redact(&text, &secrets(&[&secret]), 4), text);
        }
    }

    #[test]
    fn secret_at_threshold_is_redacted() {
        assert_eq!(redact("value=abcd", &secrets(&["abcd"]), 4), "value=***");
    }

    #[test]
    fn empty_secret_and_empty_list_are_noops() {
        assert_eq!(redact("hello", &[], 4), "hello");
        assert_eq!(redact("hello", &secrets(&[""]), 4), "hello");
        assert_eq!(redact("", &secrets(&["secret"]), 4), "");
    }

    #[test]
    fn redaction_is_idempotent() {
        let once = redact("value=abcd", &secrets(&["abcd"]), 4);
        assert_eq!(redact(&once, &secrets(&["abcd"]), 4), once);
    }

    #[test]
    fn longer_secret_replaced_before_shorter() {
        let result = redact("value=abcdef", &secrets(&["abcd", "abcdef"]), 4);
        assert!(result.contains("***"));
        assert!(!result.contains("ef"));
        assert_eq!(result, "value=***");
    }

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate("short", 100), "short");
    }

    #[test]
    fn truncate_long_string_marks_truncation() {
        let text = "a".repeat(50);
        let result = truncate(&text, 10);
        assert!(result.starts_with(&"a".repeat(10)));
        assert!(result.contains("truncated"));
    }

    #[test]
    fn escape_log_field_removes_line_breaks() {
        let result = escape_log_field("line1\nline2\rline3");
        assert!(!result.contains('\n'));
        assert!(!result.contains('\r'));
        assert!(result.contains("line1") && result.contains("line2") && result.contains("line3"));
    }

    #[test]
    fn escape_log_field_replaces_audit_separator() {
        assert!(!escape_log_field("a═b").contains('═'));
    }

    #[test]
    fn escape_log_field_truncates_long_value() {
        assert!(escape_log_field(&"x".repeat(500)).chars().count() <= 200);
    }

    #[test]
    fn neutralize_separator_rewrites_only_the_boundary() {
        let body = format!("before\n{SEPARATOR}\nafter");
        let result = neutralize_separator(&body);
        assert!(!result.contains(SEPARATOR));
        assert!(result.contains("[separator]"));
        assert!(result.contains("before") && result.contains("after"));
    }

    #[test]
    fn sanitize_log_value_flattens_breaks() {
        assert_eq!(sanitize_log_value("host\r\nname"), "host  name");
    }

    #[test]
    fn sanitize_prompt_value_flattens_breaks_and_separator() {
        let result = sanitize_prompt_value("Service: x\nConfirm? yes\r\n═ evil");
        assert!(!result.contains('\n'), "{result}");
        assert!(!result.contains('\r'), "{result}");
        assert!(!result.contains('═'), "{result}");
        assert!(result.contains("Service: x"));
    }

    #[test]
    fn sanitize_prompt_value_truncates_long_value() {
        assert!(sanitize_prompt_value(&"x".repeat(500)).chars().count() <= 200);
    }

    #[test]
    fn truncate_counts_chars_not_bytes() {
        // Многобайтовый текст не должен паниковать на срезе.
        let text = "ы".repeat(50);
        let result = truncate(&text, 10);
        assert!(result.starts_with(&"ы".repeat(10)));
        assert!(result.contains("50 chars total"));
    }
}
