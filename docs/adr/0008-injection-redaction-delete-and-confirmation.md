# ADR-0008 — Injection protection, redaction on the live path, no pool and a replacement of the confirmation channel

- Status: accepted
- Date: 2026-09-19
- Related: DR-4, DR-5, DR-6, DR-7, ADR-0002, ADR-0003, ADR-0006

## Context

The second audit found defects that the first audit did not catch:

1. `compare_files` inserted paths into a PowerShell string in double quotes, where `$(...)` expands. A file name of the form `a$(calc).txt` ran code on the host.
2. `run_ps` received a list of redacted values from the caller, but the server sent an empty list. The value of `set_registry` went into the audit log in cleartext and broke DR-4. The test AC-SEC02-1 sent the secrets by hand and did not see the gap.
3. `delete_file` did not check protected paths and did not tell a file from a directory, although its description promised a scan.
4. `delete_directory` checked a reparse point only in the root: `Remove-Item -Recurse` in Windows PowerShell 5.1 could go through a junction inside the tree.
5. `WINRIG_LOG_LEVEL=WARNING` and `CRITICAL` are not levels for `EnvFilter`, but target names. The server silenced the log.
6. The code parsed `whoami /priv /fo csv` by English headers, and it broke on a localized Windows.
7. The keys of the caches and of the lockout were case-sensitive: `contoso\alice` and `CONTOSO\ALICE` went around the lockout.
8. The confirmation waited for an answer without a limit.
9. ADR-0003 and AGENTS.md declared a pool of WinRM connections that the code did not have.
10. The protocol revision `2026-07-28` removes the confirmation channel (elicitation), and this change was not reflected.

## Decision

1. **Injections.** Free text goes to PowerShell only in single quotes with the doubling of `'`. Paths that the answer prints do not go into double quotes. The generator of the registry uses `-LiteralPath` instead of `-Path`. Coverage: `ps::tests::every_generator_escapes_single_quoted_free_text`, `ps::tests::compare_files_does_not_interpolate_paths_in_double_quotes`.
2. **Redaction on the live path.** `SessionRegistry::run_ps` always adds the password of the session itself to the list of secrets, and `set_registry` sends the value as a secret. The server redacts the audit log at `min_length=1`, and the answer to the agent at `WINRIG_SECRET_REDACT_MIN_LENGTH`.
3. **Protection of file deletion.** `delete_file` makes a preliminary scan with the host (`FileScan`) and fails for protected paths and directories before confirmation.
4. **Nested reparse points.** `DeleteScan` carries the field `NestedReparsePoint`; `decide_delete_scan` fails at `NESTED_REPARSE_POINT`. The delete command checks the root and the subtree again directly before `Remove-Item` (a close of TOCTOU).
5. **Log level.** `LogLevel::filter_directive()` maps `WARNING`→`warn` and `CRITICAL`→`error`; `EnvFilter` gets a valid level.
6. **Locale.** `get_security_context` calls `whoami /priv /fo csv /nh` and parses the positions with explicit headers, and keeps the raw value of the state.
7. **Identity.** `identity_from_context` canonicalizes the name to lowercase; this is the key of the caches and of the lockout (DR-3).
8. **Confirmation timeout.** The new `WINRIG_CONFIRM_TIMEOUT_SECONDS` (default 300); the confirmation goes through `elicit_with_timeout`, and an expiry is fail-closed.
9. **Pool.** The project does not introduce a pool: it makes a client for each call. NTLM encryption of the body over HTTP is on by default in `winrm-rs`. The project synchronized AGENTS.md and ADR-0003; the reuse of the client is a ROADMAP task.
10. **Confirmation channel.** Elicitation stays until the clients move to `2026-07-28`; the replacement with `input_required` (SEP-2322) is in the ROADMAP and Q-10 and comes with a separate ADR.
11. **Confirmation text.** `sanitize_prompt_value` collapses newlines and the separator, so an argument cannot forge the dialogue.

## Consequences

- New environment variables: `WINRIG_CONFIRM_TIMEOUT_SECONDS`; the changed default of `WINRIG_LOG_DIR` was `./logs` instead of `/app/logs`. ADR-0009 later replaced the default: without `WINRIG_LOG_DIR` the logs go to the state directory of the profile.
- A new ADR is not necessary for each item: the items clarify DR-4, DR-5 and DR-6.
- TR-SEC-08 (`invoke_http_request`) and the duration in TR-OBS-01 stay unimplemented; `docs/REQUIREMENTS.md` marks them.
- `cargo-deny` is part of the obligatory run (`deny.toml`). CI repeats the local set and checks the MSRV 1.98 from `Cargo.toml`/`rust-toolchain.toml`.

## Clarification (ADR-0015)

§1: the doubling of the ASCII apostrophe is not sufficient. PowerShell closes a single-quoted string also with the typographic quotes U+2018, U+2019, U+201A and U+201B. `ps::escape` doubles all five forms, and the test covers the scripts assembled in `src/server.rs` too.
