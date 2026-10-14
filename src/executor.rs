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
    format!("{head}\n\n--- truncated ({total} characters total, showing the first {limit}) ---")
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

/// True for a character that must not reach the prompt: the categories Cc, Cf,
/// Zl and Zp (TR-SEC-19).
///
/// Bidi controls (U+202A..U+202E, U+2066..U+2069), zero-width characters and the
/// other format characters are in Cf, so a value cannot reorder or hide the text.
/// `char::is_control` covers Cc, which holds NEL U+0085, ESC, VT and FF.
fn is_prompt_control(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{2028}' | '\u{2029}' // Zl, Zp
            | '\u{00AD}' | '\u{0600}'..='\u{0605}' | '\u{061C}' | '\u{06DD}' | '\u{070F}'
            | '\u{0890}'..='\u{0891}' | '\u{08E2}' | '\u{180E}'
            | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}' | '\u{110CD}' | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}' | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}' | '\u{E0020}'..='\u{E007F}'
        )
}

/// Collapses the prompt-forbidden characters to a space and the audit separator to
/// `-` (TR-SEC-19, ADR-0008 §11).
fn flatten_for_prompt(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c == '═' {
                '-'
            } else if is_prompt_control(c) {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// Makes a confirmation prompt value unable to forge its structure.
///
/// Service names, PIDs, registry keys, paths and software versions come from tool
/// arguments and reach the elicitation message. The control categories collapse to
/// a space, the `═` separator becomes `-`, and the length is capped, so an argument
/// cannot insert its own dialog "line", reorder the text or break the dialog into a
/// wrong consent (DR-5). A cut value carries the visible marker `...` inside the
/// cap: the head keeps `AUDIT_FIELD_MAX_CHARS - 3` characters (TR-SEC-19, Q-24).
#[must_use]
pub fn sanitize_prompt_value(value: &str) -> String {
    let cleaned = flatten_for_prompt(value);
    if cleaned.chars().count() <= AUDIT_FIELD_MAX_CHARS {
        return cleaned;
    }
    let head: String = cleaned.chars().take(AUDIT_FIELD_MAX_CHARS - 3).collect();
    format!("{head}...")
}

/// Normalizes a confirmation body (a command or a script) to LF, without the
/// 200-character cap (TR-SEC-22, Q-31).
///
/// The body keeps its line structure: the operator confirms what will run, and a
/// multi-line body is easier to read line by line. `\r\n` and `\r` become `\n`.
/// Every other control, format or bidi character collapses to a space and the `═`
/// separator becomes `-`, so a line cannot forge a header line, reorder the text
/// or break the consent (TR-SEC-09, ADR-0008 §11).
#[must_use]
pub fn sanitize_body_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push('\n');
            }
            '\n' => out.push('\n'),
            '═' => out.push('-'),
            other if is_prompt_control(other) => out.push(' '),
            other => out.push(other),
        }
    }
    out
}

/// Caps a path-like field in the middle: the head and the tail stay visible, so a
/// long path still shows its file name. The marker `...` counts inside the cap
/// (TR-SEC-19, Q-24).
#[must_use]
pub fn sanitize_path_value(value: &str) -> String {
    let cleaned = flatten_for_prompt(value);
    let count = cleaned.chars().count();
    if count <= AUDIT_FIELD_MAX_CHARS {
        return cleaned;
    }
    let head_len = (AUDIT_FIELD_MAX_CHARS - 3) / 2;
    let tail_len = AUDIT_FIELD_MAX_CHARS - 3 - head_len;
    let head: String = cleaned.chars().take(head_len).collect();
    let tail: String = cleaned.chars().skip(count - tail_len).collect();
    format!("{head}...{tail}")
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

    /// TR-SEC-19, Q-24: a cut field carries `...` inside the cap, and a value at
    /// the cap is left unchanged.
    #[test]
    fn sanitize_prompt_value_marks_a_cut_field() {
        let cut = sanitize_prompt_value(&"x".repeat(500));
        assert_eq!(cut.chars().count(), AUDIT_FIELD_MAX_CHARS);
        assert!(cut.ends_with("..."), "{cut}");
        let at_cap = sanitize_prompt_value(&"x".repeat(AUDIT_FIELD_MAX_CHARS));
        assert_eq!(at_cap.chars().count(), AUDIT_FIELD_MAX_CHARS);
        assert!(!at_cap.ends_with("..."), "a value at the cap is not cut");
    }

    /// TR-SEC-19: every character of Cc, Cf, Zl and Zp becomes a space, so a value
    /// cannot hide, reorder or break the dialog.
    #[test]
    fn sanitize_prompt_value_replaces_every_control_category() {
        for c in [
            '\u{0000}', '\u{000B}', '\u{000C}', '\u{001B}', '\u{007F}', '\u{0085}', '\u{2028}',
            '\u{2029}', '\u{200B}', '\u{200E}', '\u{202A}', '\u{202E}', '\u{2066}', '\u{2069}',
            '\u{FEFF}', '\u{00AD}',
        ] {
            let result = sanitize_prompt_value(&format!("a{c}b"));
            assert_eq!(
                result, "a b",
                "U+{:04X} is not replaced: {result:?}",
                c as u32
            );
        }
    }

    /// TR-SEC-22: the body keeps its lines and is not capped, so the operator sees
    /// the whole command.
    #[test]
    fn sanitize_body_value_keeps_the_lines_without_the_cap() {
        let long = format!("a\r\nb\rc═d{}", "x".repeat(500));
        let result = sanitize_body_value(&long);
        assert_eq!(result.lines().count(), 3, "{result}");
        assert!(!result.contains('\r'), "{result}");
        assert!(!result.contains('═'), "{result}");
        assert_eq!(result.matches('\n').count(), 2, "{result}");
        assert!(result.contains("c-d"), "{result}");
        assert_eq!(
            result.chars().count(),
            long.chars().count() - 1,
            "CRLF collapses to one LF and the body must not be cut"
        );
    }

    /// TR-SEC-22: every other control character collapses, but a newline stays.
    #[test]
    fn sanitize_body_value_replaces_other_controls_and_keeps_newlines() {
        assert_eq!(sanitize_body_value("a\u{200B}b\nc\u{001B}d"), "a b\nc d");
    }

    /// TR-SEC-19: a path field is cut in the middle, so the tail stays visible.
    #[test]
    fn sanitize_path_value_keeps_the_tail_visible() {
        let path = format!("C:\\{}", "d".repeat(300));
        let result = sanitize_path_value(&path);
        assert_eq!(result.chars().count(), AUDIT_FIELD_MAX_CHARS);
        assert!(result.starts_with("C:\\"), "{result}");
        assert!(result.contains("..."), "{result}");
        let tail: String = path.chars().skip(path.chars().count() - 40).collect();
        assert!(
            result.ends_with(&tail),
            "the last 40 characters must stay visible: {result}"
        );
        assert_eq!(sanitize_path_value("C:\\a"), "C:\\a");
    }

    #[test]
    fn truncate_counts_chars_not_bytes() {
        // Multi-byte text must not panic on the slice.
        let text = "ы".repeat(50);
        let result = truncate(&text, 10);
        assert!(result.starts_with(&"ы".repeat(10)));
        assert!(result.contains("50 characters total"));
    }
}
