# ADR-0010 — Uniform notation of the `WINRIG_*` environment variables

- Status: accepted
- Date: 2026-09-20
- Related: ADR-0004, ADR-0009, DR-8, TR-PRF-01..10

## Context

The variable names came from two sources and had no single form. The Python version left `MCP_AUTH_TOKEN`, `MCPO_PORT` (with a mistake in the letter order), `LOG_DIR`, `ALLOWED_HOSTS` and `SECRET_REDACT_MIN_LENGTH`. The profile added `WINRIG_TOKEN`, `WINRIG_PROFILE`, `WINRIG_PROFILE_DIR` and `WINRIG_STATE_DIR`. The same product read variables with three different prefixes and with no prefix at all. The units of measure in the names were not consistent: `..._SECONDS` in some names, nothing in others. `AD_` also mixed the domain scope with the process scope.

## Decision

1. **Single prefix `WINRIG_`.** All environment variables begin with `WINRIG_`. The profile variables `WINRIG_TOKEN`, `WINRIG_PROFILE`, `WINRIG_PROFILE_DIR` and `WINRIG_STATE_DIR` already conformed and stay.
2. **Full rename map.**

   | Old name | New name |
   |---|---|
   | `MCP_AUTH_TOKEN` | `WINRIG_AUTH_TOKEN` |
   | `MCP_BIND_HOST` | `WINRIG_BIND_HOST` |
   | `MCPO_PORT` | `WINRIG_PORT` |
   | `AD_PASSWORD_IDLE_TTL_SECONDS` | `WINRIG_PASSWORD_TTL_SECONDS` |
   | `LOG_DIR` | `WINRIG_LOG_DIR` |
   | `LOG_LEVEL` | `WINRIG_LOG_LEVEL` |
   | `LOG_MAX_BYTES` | `WINRIG_LOG_MAX_BYTES` |
   | `LOG_BACKUP_COUNT` | `WINRIG_LOG_BACKUP_COUNT` |
   | `AUDIT_MAX_OUTPUT_CHARS` | `WINRIG_AUDIT_MAX_OUTPUT_CHARS` |
   | `AUDIT_LOG_BODY` | `WINRIG_AUDIT_LOG_BODY` |
   | `CONFIRM_TIMEOUT_SECONDS` | `WINRIG_CONFIRM_TIMEOUT_SECONDS` |
   | `AD_LOCKOUT_MAX_ATTEMPTS` | `WINRIG_LOCKOUT_ATTEMPTS` |
   | `AD_LOCKOUT_WINDOW_SECONDS` | `WINRIG_LOCKOUT_WINDOW_SECONDS` |
   | `SECRET_REDACT_MIN_LENGTH` | `WINRIG_SECRET_REDACT_MIN_LENGTH` |
   | `ALLOWED_HOSTS` | `WINRIG_ALLOWED_HOSTS` |
   | `ALLOW_INSECURE_TLS` | `WINRIG_ALLOW_INSECURE_TLS` |
   | `SFTP_CRED_IDLE_TTL_SECONDS` | `WINRIG_SFTP_CRED_TTL_SECONDS` |

3. **A clean break, not compatibility.** The server does not read the old names. If any old name is set, startup refuses (code 2) and reports the full list of the found pairs `old -> new` (DR-8). Thus the operator cannot think that a value applied when the server ignored it.
4. **The suffixes are in order.** The domain prefixes and the redundant prefixes are gone. `AD_` is removed; `AUDIT_` stays as a scope, but under the common prefix. The units of measure stay in the name where they are a dimension (`_SECONDS`, `_BYTES`, `_CHARS`, `_COUNT`). The word order goes from the general scope to the private scope: `WINRIG_LOG_MAX_BYTES`, not `LOG_MAX_BYTES`.
5. **CLI flags override the environment.** `serve --port`/`--host` already override `WINRIG_PORT`/`WINRIG_BIND_HOST`; the rule "CLI > env" stays.

## Consequences

- The variable table in the README and in ADR-0004 takes the new names; `AGENTS.md`, ADR-0001/0005/0008/0009, `docs/REQUIREMENTS.md`, `docs/QUESTIONS.md` and `docs/ROADMAP.md` are in agreement.
- The live configurations are updated: the `.env` of the server and the client definitions must use the new names. The definitions that `setup` writes already hold `WINRIG_*` (ADR-0009), so only the manual records need a regeneration.
- The permanent table of the old names lives in `src/config.rs::RENAMED_VARIABLES` and has test coverage: each old name gives a refusal with the new name.
- New variables come in only with the prefix `WINRIG_`; there are no exceptions.
