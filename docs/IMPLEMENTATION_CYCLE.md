# docs/IMPLEMENTATION_CYCLE.md — the slice cycle, the subagent package, the reviewer checklist

## 1. Roles

- **Orchestrator** (the main agent): chooses the slice and its criteria, the plan and the document edits. It also owns the ADRs, the question journal and the roadmap, the document commits and the final report.
- **Implementer** — a subagent: one step of implementation or research.
- **Reviewer** — a subagent, always not the author of the code: checks the agreement with the documents.
- **Runner** — a separate subagent (or the orchestrator) starts the checks; the test status comes from the run, not from the words of the implementer.

## 1a. The command of the check run

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo deny check
cargo build --release
```

The full run must be green before a commit (AGENTS.md §6, §7). Clippy must have no warnings, the formatting must have no differences, and cargo-deny must have no refusals. The Rust version comes from `rust-toolchain.toml`; CI (`.github/workflows/ci.yml`) runs the same set and separately builds the project on the MSRV from `Cargo.toml`.

## 2. The cycle for a slice

0. **Slice.** The goal, the acceptance criteria with a reference to the document section, `risky yes/no`, what is outside the slice. A criterion that does not follow from the documents is an assumption `Q-NN` plus a line in `docs/QUESTIONS.md`.
1. **Plan.** No more than eight steps: files, tests, risks, rollback. Risky slices do not wait for the operator: they are done reversibly.
2. **Implementation.** A step is first a failing test, then the code. Nothing "on the side". A deviation from the documents is first a document or an ADR assumption, then the code.
3. **Tests.** `cargo test`. The external systems are a fake transport that records the commands; a live channel is not used (AGENTS.md §4). The full log goes to the slice file.
4. **Control.** An independent reviewer checks the agreement with the documents. Each "not done" returns to step 2; each "not verifiable" requires a test, a protocol or a document clarification.
5. **Documents.** README, AGENTS.md, ADRs, `docs/QUESTIONS.md`, `docs/ROADMAP.md`. A separate commit with the prefix `docs:`.
6. **Retrospective.** In `PAPERCUTS.md` — "what I did → what broke → the workaround". The journal is kept locally and does not go to a commit. It names details of the working environment that do not belong in the public history (`.gitignore`).

## 3. The subagent package (only the finished one)

```
GOAL: <one sentence>
INPUTS: <files/document sections to read>
CONSTRAINTS: <what is not allowed; references to Domain Rules and ADRs>
ANSWER FORMAT (<=40 lines):
STATUS:
CHANGED:
TESTS:
ASSUMPTIONS:
PAPERCUTS:
NOTES:
Raw data goes to the file: <path>
```

## 4. Reviewer checklist

1. Each acceptance criterion of the slice has the verdict "done / not done / not verifiable" with evidence (a test, the output, a protocol).
2. The Domain Rules (AGENTS.md §3) are done by the code and covered by a test.
3. There is no write to an external system outside the modifying tools and outside a confirmation (DR-5).
4. New entities/statuses/roles/channels have an ADR.
5. There are no references to files, commands or endpoints that do not exist.
6. No secret went to a log, the audit, the code or a commit.
7. The checks that are sensitive to the locale are in the code, with a test.
8. The full `cargo test` run is green and clippy is clean at the time of the check.

## 5. Backlog

The queue and the statuses are in `docs/ROADMAP.md`. These stay outside the slice (recorded in `docs/QUESTIONS.md`):

- there is no test Windows host, so the NTLM connection, the reparse check and the live parsing of output are not verified (Q-08);
- the tools of the Python version that are not ported (file transfer, archives, `invoke_http_request`, SFTP);
- the move of the confirmation channel to `input_required` at the change to the revision `2026-07-28` (Q-10). Clients without elicitation (opencode 1.18.31) stay fail-closed on modifying tools;
- the reuse of the WinRM client for a session and the duration in the audit record;
- the OS keyring as an alternative to the profile file (Q-12);
- the move of the inline PowerShell in `src/server.rs` (`set_registry`, `kill_process` and the others) into `src/ps.rs`, so the shared guard tests cover them;
- the verification on a live Windows host of the `PrinterStatus` semantics, the Restart Manager through `Reflection.Emit`, `-ErrorVariable +var` on PowerShell 5.1 and the CLIXML stderr format (Q-08).
