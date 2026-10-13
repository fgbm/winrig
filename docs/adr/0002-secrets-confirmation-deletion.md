# ADR-0002 — Secrets in memory only, confirmation of modifications, deletion protection

- Status: accepted
- Date: 2026-09-19
- Related: AGENTS.md §3 DR-4, DR-5, DR-6

## Context

AD passwords would go into the logs and the audit log. The server could run modifying operations without confirmation. A recursive deletion could reach system directories and reparse points.

## Decision

1. **Secrets in memory only.** Passwords and passphrases do not go into the logs, the audit log, the configuration or a commit. The password is in `secrecy::SecretString`, and that type clears it on free. The server redacts a secret that a command carries from the audit log in all forms.
2. **Confirmation is obligatory.** The server runs a modifying operation only after an explicit confirmation through elicitation. If the confirmation channel is absent, the server does not run the operation (fail-closed). A modifying tool returns a ready answer with the `error` field and does not run the command.
2a. **The audit log is not forgeable.** The server escapes the audit fields (newlines and the separator). The body of a record (the command and the output of the external system) neutralizes the block separator characters. Therefore inserted text cannot make a false block boundary or a false field. The server also sanitizes the host and the session identifier in the main log.
3. **Deletion protection.** A recursive deletion fails for the roots of volumes and the system directories in any notation of the path, and for reparse points (junction/symlink).

## Consequences

- The redaction of a secret has a minimum length (ADR-0005).
- The code normalizes the path check (`src/policy.rs`).
- The header `X-AD-Password` supplies the AD password. Elicitation in the MCP specification is not for secrets. The server uses elicitation only for confirmation (ADR-0006).
