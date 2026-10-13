# ADR-0004 — Configuration only through environment variables

- Status: accepted
- Date: 2026-09-19
- Related: AGENTS.md §5, ADR-0003

## Context

The code reads parameters (TTL, the log limits and others) from the environment. New parameters — the lockout threshold and window, the minimum redaction length, the host allowlist and the TLS downgrade permission — must come in the same way.

## Decision

All parameters come through environment variables. The README has the full table. Secrets are in `.env`. The repository does not commit `.env`, `target/` and snapshots. The validation is in `src/config.rs` (ADR-0003).

New variables (the decisions of the operator, moved from the Python version):

| Variable | Default | Purpose |
|---|---|---|
| `WINRIG_LOCKOUT_ATTEMPTS` | `3` | the number of failures before lockout |
| `WINRIG_LOCKOUT_WINDOW_SECONDS` | `1800` | the lockout window, seconds |
| `WINRIG_SECRET_REDACT_MIN_LENGTH` | `4` | the minimum length of a secret for redaction |
| `WINRIG_ALLOWED_HOSTS` | empty | the host allowlist; an empty value allows everything |
| `WINRIG_ALLOW_INSECURE_TLS` | `true` | whether the server permits `verify_cert=false` |

## Consequences

- The project does not introduce a configuration file.
- The default values keep the behavior of the Python version, apart from security (the defaults allow everything, as before).

## Clarification (ADR-0009)

The account profile file is not a configuration. It is the storage of the authenticated password ciphertext, and the server does not keep the profile key. Parameters still come through environment variables. The parameters include the profile name (`WINRIG_PROFILE`), the profile token (`WINRIG_TOKEN`), the profile directory (`WINRIG_PROFILE_DIR`) and the state directory (`WINRIG_STATE_DIR`). `WINRIG_AUTH_TOKEN` is no longer obligatory: the start needs a shared secret or a profile token.

## Clarification (ADR-0015)

The security defaults changed: an empty `WINRIG_ALLOWED_HOSTS` permits only loopback literals, and the element `*` permits any host. `WINRIG_ALLOW_INSECURE_TLS` is `false` by default. The phrase "the defaults allow everything, as before" no longer applies to these two variables.
