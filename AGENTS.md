# AGENTS.md — the canon of the winrig repository

The documents of this repository are the truth for agents and people. If the code disagrees with a document, the document is correct; the code or an ADR corrects the disagreement, not silence.

## 1. Product

`winrig` is an MCP server for remote administration of Windows hosts over WinRM/NTLM, written in Rust. The client calls tools: diagnostics (read only) and modifying operations (they require confirmation). The server runs from one binary in two modes. The HTTP endpoint `/mcp` (`winrig serve`) serves several projects, and the stdio process (`winrig stdio`) serves a local client. Both modes use one account profile.

The product is multi-user: several operators at the same time in the HTTP mode. `winrig` is the independent successor of the Python project `win-mcp-server`. The decisions and the rules moved from it. The stack changed to Rust for low memory use, speed and one static binary without a container.

## 2. Architectural boundaries

- `src/main.rs` — the entry point: CLI parsing, exit code.
- `src/app.rs` — orchestration: subcommands, logging, the serve and stdio modes.
- `src/cli.rs` — the `clap` subcommand definitions.
- `src/client_config.rs` — the write of the MCP server definition into client configuration files (ADR-0009, ADR-0012).
- `src/profile.rs` — the account profile: password ciphertext, profile token, rotation (ADR-0009).
- `src/paths.rs` — the profile and state directories, profile selection, the process lock (ADR-0009).
- `src/private_fs.rs` — private files and directories with the modes `0700`/`0600`.
- `src/config.rs` — `AppConfig`, the read and validation of environment variables (ADR-0003).
- `src/policy.rs` — the decisions "allowed/not allowed": host allowlist, the TLS downgrade mode, path normalization and classification, protected prefixes (ADR-0003).
- `src/executor.rs` — secret editing, truncation, field escaping and neutralization of the audit body (ADR-0003).
- `src/session.rs` — the WinRM session registry (the client is created for each call), the TTL password cache, the lockout after failures, the audit. The `WinRmTransport` trait separates the transport.
- `src/ps.rs` — pure PowerShell command generators.
- `src/identity.rs` — the identity from the headers or from the profile (DR-2, ADR-0009).
- `src/auth.rs` — the check of the shared secret or the profile token before trust (DR-1, ADR-0009).
- `src/server.rs` — the MCP tool definitions: argument validation, `policy` → `session`.
- `src/logging.rs` — the log and audit files with rotation and private permissions.

## 3. Domain Rules (they are obligatory for code and tests)

- DR-1. **Authentication before trust.** Each request must present one of the secrets. The shared `WINRIG_AUTH_TOKEN` uses the header path and requires `X-AD-User`. The profile token decrypts the profile file. A match of `WINRIG_AUTH_TOKEN` with the profile token stops the start. The server does not start without at least one secret.
- DR-2. **Identity on each request.** In HTTP, the secret of the current request defines the user in whose name a tool runs. The profile token gives the identity of the profile and makes the server ignore `X-AD-*`. The shared secret requires `X-AD-User`. The identity is not inherited from the task that made the MCP session. In stdio the identity equals the profile of the process.
- DR-3. **Isolation of the caches.** The password cache and the session cache are isolated by user. A user does not see the session of another user.
- DR-4. **Secrets stay in memory only.** Passwords and passphrases do not go to the logs, the audit, the configuration and they do not go to a commit. Only the authenticated ciphertext of the profile is on the disk, and the key is absent on the server. A secret that a command carries must not appear in the audit in any form.
- DR-5. **Modification only with confirmation.** Each modifying operation requires explicit confirmation; without a confirmation channel the operation does not run (fail-closed).
- DR-6. **Destructive operations are protected.** A recursive deletion refuses the roots of volumes and the system directories in any form of the path, and it refuses reparse points (junction/symlink).
- DR-7. **The outer boundary is controllable.** The host allowlist and the ban on the downgrade of the TLS check are configured through the environment.
- DR-8. **A start refusal is clear.** An invalid configuration stops the process with a message that names the variable and the expected format.

## 4. External systems and writes

- The Windows host is an external system. A write is permitted only through the tools that the README lists as modifying, and only after confirmation (DR-5). The only exception outside the tools is the write of the MCP server definition into the configuration of the selected client. The explicit flag `setup --write-config` with the level `--scope global|project` permits this write (ADR-0009, ADR-0012). The code makes no other write to an external system.
- There is no test Windows host in the environment. The automatic tests run on a fake transport that implements `WinRmTransport` and records the commands that it gets. They do not touch the network (see `src/session.rs::tests`).

## 5. Configuration

All parameters go through environment variables (ADR-0004). The full table is in the README. The secrets are in `.env`; `.env`, `target/` and snapshots do not go to a commit. The profile file is not a configuration, but a storage of ciphertext (ADR-0009); the server does not store the profile key.

## 6. Tests and quality

- Run: `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` and `cargo deny check`. The full run must be green, clippy must have no warnings, the formatting must have no differences, and cargo-deny must have no refusals.
- First the test that fails, then the code.
- The checks that are sensitive to the locale of the host run in the code, and a test covers them. PowerShell commands must not depend on the language of the system.
- A green full run is a mandatory condition of a commit.

## 7. Commits and releases

Atomic, conventional-commit. Documents go in a separate commit with the prefix `docs:`. Before a commit, run the full set of checks.

The repository is public (`github.com/fgbm/winrig`), and the working branch is `main`. Internal journals (`PAPERCUTS.md`) and local client configurations with tokens do not go into the public history: `.gitignore` lists them. A real domain and account in the code, the tests and the documents are replaced with anonymous ones (`contoso\alice`).

A release goes out under the tag `vX.Y.Z` on `main`. The version in `Cargo.toml` and the entry in `CHANGELOG.md` go up in one commit before the tag. The workflow `release.yml` refuses if the version of the tag and the manifest disagree. It takes the release text from the CHANGELOG. The tag starts the build of binaries for five targets and the GitHub Release.

## 8. Documents

- `docs/REQUIREMENTS.md` — the requirements `TR-*` and the acceptance criteria `AC-*`.
- `docs/ROADMAP.md` — the queue of slices.
- `docs/IMPLEMENTATION_CYCLE.md` — the slice cycle, the subagent package, the reviewer checklist, the backlog.
- `docs/QUESTIONS.md` — the journal of questions `Q-NN`.
- `docs/adr/` — the decisions. New entities, statuses, roles and channels come in only through an ADR.
- `docs/style/` — the rules of the language and the style of the text: `ste-en.md` (English, ASD-STE100) and `ru-technical.md` (Russian). ADR-0016 sets the language and the style.
- `docs/site/` — the bilingual documentation site (English and Russian), published to GitHub Pages.
- `AGENTS.md` — the canon of the repository (this file). `CONTRIBUTING.md` — the same for an external participant, in short.
- `SECURITY.md` — the channel for the private disclosure of vulnerabilities; a report about them does not go to a public issue.
- `CHANGELOG.md` — the history of changes by Keep a Changelog; the entry under a tag is the source of the release text.

## 9. Document formatting

- **The language of the text is English by ASD-STE100** (`docs/style/ste-en.md`, ADR-0016). Russian stays only in `README.ru.md` and in the Russian part of the documentation site `docs/site/src/content/docs/ru/` by `docs/style/ru-technical.md`. Code comments are plain short English, not STE.
- **No soft wrapping.** Each paragraph and each list item occupies one line of the source, however long it is. A line break by width is forbidden: it makes diff noise at edits and interferes with reading. Only a content break is allowed — a new paragraph, a new list item.
- Lines that carry meaning per line stay as they are: headings, tables, code blocks in a fence, horizontal rules, empty separators.
- Lines inside a code block do not wrap and do not unwrap.
- Multi-line paragraphs and "shifted" continuations of a list item are not permitted; unwrap the existing ones.
