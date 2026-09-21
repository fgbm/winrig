# Contributing to winrig

Thanks for taking the time to look. This project holds an AD password and executes commands on remote hosts, so its rules are strict on purpose. Read `AGENTS.md` first — it is the repository canon, and the documents win over the code.

This file is the short version for a human contributor. `docs/IMPLEMENTATION_CYCLE.md` describes the slice cycle, the subagent brief and the reviewer checklist used inside the project.

## Before you start

Open an issue before writing a large change. A new tool, a new external system, a new status or a new channel is introduced **only through an ADR** (`docs/adr/`). If your change fits an existing decision, say which one in the issue.

Small fixes — a bug, a test, a documentation correction — need no prior issue.

## Build and test

The toolchain is pinned in `rust-toolchain.toml`; `rustup` installs it on first use.

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo deny check
```

All five must be green before a commit. There is no live Windows host in the development environment: tests run against a fake `WinRmTransport` and never touch the network. A change that can only be exercised against a real host must not be the only thing covering a Domain Rule.

## The rules that are not negotiable

These come from `AGENTS.md` §3 and `docs/REQUIREMENTS.md`. A pull request that breaks one is not merged, however useful the feature.

1. **Test first.** Add the test that fails, then the code that makes it pass.
2. **A secret never reaches disk or a reply.** Not a log, not the audit trail, not a tool response, not a config, not a commit (`DR-4`).
3. **Verify the secret before trusting anything.** Identity is established per request, never inherited from the MCP session (`DR-1`, `DR-2`).
4. **A modification is confirmed or it does not run.** When the client cannot prompt, the call fails closed (`DR-5`).
5. **No command-line injection.** A value from an argument is passed as data, never concatenated into PowerShell.
6. **Locale independence.** A PowerShell command must not depend on the host's language; format in code, not in the shell.
7. **One line per paragraph.** Documents do not wrap at a column width — a soft-wrapped paragraph is diff noise (`AGENTS.md` §9).

## Commits

Conventional commits, one logical change per commit. Documentation goes in its own commit with a `docs:` prefix.

```
feat: add get_ad_object for a single directory entry
fix: refuse an AD account without a domain
test: pin down the parity guard in hex_decode
docs: decide Active Directory and record slices W19-W21
```

Do not add `Co-Authored-By` trailers or generated-by footers.

## Pull requests

- One concern per pull request.
- Run the full check set above; a red run is not ready for review.
- Describe what changes, which Domain Rule or requirement it serves, and how it was verified.
- If the change is user-visible, update `README.md` and `docs/REQUIREMENTS.md` in the same branch.
- If it is a decision rather than an implementation, add an ADR instead of code.

## Reporting a security issue

Do not open a public issue — follow `SECURITY.md`.
