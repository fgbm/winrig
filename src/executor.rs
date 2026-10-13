//! Pure execution helpers: secret redaction, truncation and audit fields.
//!
//! The module knows nothing about WinRM (ADR-0003); it only transforms text. A
//! port of `agent/executor.py`. Rust needs no separate off-loop wrapper: a WinRM
//! call is asynchronous by nature (TR-REL-01).

/// Limit of the output returned to the agent, in characters.
pub const MAX_OUTPUT_CHARS: usize = 60_000;

/// Limit of an audit field, in characters.
pub const AUDIT_FIELD_MAX_CHARS: usize = 200;

/// Boundary line of the audit block (TR-SEC-09).
pub const SEPARATOR: &str =
    "════════════════════════════════════════════════════════════════════════════════";

/// What a secret is replaced with.
const REDACTED: &str = "***";

/// Replaces secrets with `***` in all forms (DR-4, Q-02).
///
/// Both the raw form and the PowerShell-escaped form (`'` to `''`) are redacted,
/// so the secret cannot leak through escaping. Secrets shorter than `min_length`
/// and empty ones are left alone: otherwise the output would be distorted. Longer
/// secrets are replaced first, so nested ones leave no tail. The function is
/// idempotent.
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
        // Both forms can be equal when the secret has no `'`; the second
        // replacement is then a no-op.
        for form in [secret, escaped.as_str()] {
            result = result.replace(form, REDACTED);
        }
    }
    result
}

/// Truncates the output to `limit` with a note about the full size.
#[must_use]
pub fn truncate(text: &str, limit: usize) -> String {
    let total = text.chars().count();
    if total <= limit {
        return text.to_owned();
    }
    let head: String = text.chars().take(limit).collect();
    format!("{head}\n\n--- truncated ({total} chars total, showing first {limit}) ---")
}

/// Makes a string safe for one audit line (TR-SEC-09).
///
/// Line breaks become spaces, the `═` separator becomes `-`, and the length is
/// capped, so the field cannot forge the audit block structure.
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

/// A value suitable for one main log line (TR-SEC-09).
///
/// The host and the session id come from tool arguments, so line breaks collapse
/// to a space and cannot forge the line.
#[must_use]
pub fn sanitize_log_value(value: &str) -> String {
    value.replace(['\r', '\n'], " ")
}

/// Makes the audit body unable to forge the block boundary (TR-SEC-09).
///
/// The body (a command and the output of an external system) stays multi-line, so
/// only the separator sequence is neutralized. The replacement starts with `[`,
/// so the body cannot pass a line off as a marker either.
#[must_use]
pub fn neutralize_separator(body: &str) -> String {
    body.replace(SEPARATOR, "[separator]")
}

/// Makes a confirmation prompt value unable to forge its structure.
///
/// Service names, PIDs, registry keys, paths and software versions come from tool
/// arguments and reach the elicitation message. Line breaks collapse to a space,
/// the `═` separator becomes `-`, and the length is capped, so an argument cannot
/// insert its own dialog "line" or break the dialog into a wrong consent (DR-5).
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
        // Multi-byte text must not panic on the slice.
        let text = "ы".repeat(50);
        let result = truncate(&text, 10);
        assert!(result.starts_with(&"ы".repeat(10)));
        assert!(result.contains("50 chars total"));
    }
}
