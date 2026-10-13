# ADR-0003 — Module boundaries: `config`, `policy`, `executor`

- Status: accepted
- Date: 2026-09-19
- Related: AGENTS.md §2, DR-7, DR-8

## Context

A mix of the validation of the configuration, the "allowed/not allowed" decisions, non-blocking execution and the generation of commands makes the checks inseparable from WinRM. It also prevents a test without a Windows host.

## Decision

Introduce modules with the same boundaries as in the Python version:

- `src/config.rs` — `AppConfig`, the read and the validation of all environment variables, one start failure (DR-8).
- `src/policy.rs` — the "allowed/not allowed" decisions: the host allowlist, the TLS downgrade mode, the normalization and the classification of paths, protected prefixes (DR-6, DR-7).
- `src/executor.rs` — the redaction of secrets, truncation, the format of the audit log.
- `src/session.rs` — the pool of WinRM connections behind the `WinRmTransport` trait; the real implementation is on top of `winrm-rs`, and the test implementation is a recording dummy transport.
- `src/ps.rs` — pure generators of PowerShell commands.
- `src/server.rs` — a thin adapter: the validation of arguments → `policy` → `session`.

The response contracts of the tools stay compatible with the Python version.

## Consequences

- Test seams appear: the tests of `policy`, `executor` and `ps` do not use WinRM; the tests of `session` use the dummy transport.
- A separate off-loop wrapper is not necessary: a WinRM call is asynchronous, and one request does not block the others (TR-REL-01).

## Clarification (ADR-0008)

The phrase "pool of WinRM connections" in the decision above described an intention, not the implementation. The code did not introduce a pool. `WinrmTransportImpl` makes a client for each call. `winrm-rs` makes and deletes the shell inside `run_command`. ADR-0008 §9 records this clarification. The reuse of the client is in the ROADMAP.
