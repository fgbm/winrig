# How to contribute to winrig

Thank you for your time. This project keeps the AD password and runs commands on remote hosts, so its rules are deliberately strict. Read `AGENTS.md` first: it is the canon of the repository, and at a disagreement the documents are more important than the code.

This file is the short version for an external person. `docs/IMPLEMENTATION_CYCLE.md` describes the slice cycle, the subagent package and the reviewer checklist that the project uses internally.

## Before you start

Open an issue before you write a large change. A new tool, a new external system, a new status or channel come in **only through an ADR** (`docs/adr/`). If your change fits an accepted decision, name it in the issue.

Small corrections — a bug, a test, a document fix — do not require an issue in advance.

## Build and checks

The toolchain is pinned in `rust-toolchain.toml`; `rustup` installs it at the first run.

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo deny check
```

All five must be green before a commit. There is no live Windows host in the development environment: the tests run on a fake `WinRmTransport` and do not touch the network. A change that only a live host can verify cannot be the only coverage of a domain rule.

## Rules that are not open to discussion

They follow from `AGENTS.md` §3 and `docs/REQUIREMENTS.md`. A pull request that violates them does not merge, however useful the capability is.

1. **Test first.** Add a failing test, then the code that makes it green.
2. **A secret does not go to the disk or to the reply.** Not to the log, not to the audit, not to the tool reply, not to the configuration, not to the commit (`DR-4`).
3. **Check the secret before you trust anything.** The identity is set on each request and never inherited from the MCP session (`DR-1`, `DR-2`).
4. **A modification is confirmed or it does not run.** When the client cannot ask, the call refuses (fail-closed) (`DR-5`).
5. **No injection into the command line.** A value from an argument goes as data and never concatenates with PowerShell.
6. **Independence from the locale.** A PowerShell command must not depend on the language of the host; format in the code, not in the shell.
7. **One paragraph, one line.** The documents do not wrap by column width: a soft wrap of a paragraph is diff noise (`AGENTS.md` §9).

## Commits

Conventional-commit, one logical change per commit. Documentation goes in a separate commit with the prefix `docs:`.

```
feat: add get_ad_object for a single directory entry
fix: refuse an AD account without a domain
test: pin down the parity guard in hex_decode
docs: decide Active Directory and record slices W19-W21
```

Do not add `Co-Authored-By` trailers and signatures about generation.

## Pull requests

- One topic per pull request.
- Run the full set of checks above; a red run is not ready for review.
- Describe what changes, which domain rule or requirement it serves and how it is verified.
- If the change is visible to a user, update `README.md` and `docs/REQUIREMENTS.md` in the same branch.
- If it is a decision, not an implementation, add an ADR, not code.

## How to report a vulnerability

Do not open a public issue — follow `SECURITY.md`.
