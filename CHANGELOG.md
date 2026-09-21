# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A release is cut by pushing a tag of the form `vX.Y.Z`; the tag drives `.github/workflows/release.yml`, which builds the platform archives, publishes the GitHub Release and attaches the binaries with their checksums. The version in `Cargo.toml` and the tag are bumped together — see `docs/IMPLEMENTATION_CYCLE.md`.

## [Unreleased]

### Added

- Active Directory read tools and the two write waves are decided in ADR-0014 (slices W19–W21); none of them exist in the binary yet.

## [0.1.0] - 2026-09-21

The first release: the Rust successor of the Python `win-mcp-server`, with the same domain rules and tool contracts.

### Added

- MCP server with 37 tools over WinRM/NTLM: filesystem reads, system diagnostics, identity and configuration, network and software inventory.
- Modifying tools behind confirmation: service control, process kill, registry write, file and directory deletion, DNS flush; `write_file` behind `WINRIG_ALLOW_FILE_WRITE`.
- Two run modes from one binary: `serve` (streamable HTTP `/mcp`, several projects) and `stdio` (one local client).
- Encrypted account profiles: `setup`, `list`, `rotate`, `forget`; the password is authenticated ciphertext whose key stays with the client.
- `setup --write-config` for opencode, Claude Code, Codex and Cursor, at `global` or `project` scope.
- Two secrets, one per request: the shared `WINRIG_AUTH_TOKEN` with `X-AD-User`, or the profile token that fixes identity.
- Audit trail and rotating logs with private permissions (`0700`/`0600`); secrets are redacted from replies and unconditionally from logs.
- Host allowlist, TLS-downgrade refusal, protected-path guards for deletion and file write, AD lockout handling.

[Unreleased]: https://github.com/fgbm/winrig/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/fgbm/winrig/releases/tag/v0.1.0
