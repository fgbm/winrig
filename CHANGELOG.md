# Changelog

All notable changes of the project are listed here. The format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the versions follow [Semantic Versioning](https://semver.org/).

A release goes out under the tag `vX.Y.Z`; the tag starts `.github/workflows/release.yml`. That workflow builds archives for five platforms, publishes a GitHub Release and attaches the binaries with checksums. The version in `Cargo.toml` and the entry here go up in one commit — see `docs/IMPLEMENTATION_CYCLE.md`.

## Unreleased

### Added

- The bilingual documentation site on GitHub Pages.
- The Russian README (`README.ru.md`).
- The style guides and the Vale check.
- The comment check.

### Changed

- The repository text is English by ASD-STE100 (ADR-0016).
- The tool descriptions, the parameter descriptions and the CLI help are rewritten in STE.
- The error messages, the log messages and the tool results are rewritten in STE.
- The comment check is stricter. It also finds a first sentence that restates the name. It finds a short field doc without information and a repeated subject in a doc block.
- The confirmation form describes its field in English.

### Fixed

- Two tests that capture the tracing output failed about one time in 300 runs. The capture now rebuilds the tracing interest cache (#9).

## [0.2.0] - 2026-09-22

Safe defaults and protected host roots (ADR-0015, slice W22). The release breaks compatibility: before an update read the "Changed" section.

### Changed — breaks compatibility

- An empty `WINRIG_ALLOWED_HOSTS` permits only loopback (`localhost`, `127.0.0.0/8`, `::1`), not any host. To restore the previous behavior, set `WINRIG_ALLOWED_HOSTS=*`; better, list the hosts (ADR-0015).
- `WINRIG_ALLOW_INSECURE_TLS` defaults to `false`: `verify_cert=false` is rejected until you permit it explicitly.
- On the header path `connect` requires `X-AD-Password` in the same request; a password cached by the name `X-AD-User` no longer opens a session.
- Client entries that an old `setup` made do not contain `WINRIG_ALLOWED_HOSTS`: make them again with `--allowed-hosts` or add the variable manually.
- An invalid element of `WINRIG_ALLOWED_HOSTS` (for example `*.corp.example`) stops the start, instead of silently permitting nothing.
- `write_file`, `delete_file` and `delete_directory` reject a path with an 8.3 name (`PROGRA~1`): pass the long name.

### Added

- `setup --allowed-hosts` writes `WINRIG_ALLOWED_HOSTS` into the client entry; a second `setup` without the flag removes the variable.
- Policy refusals before a host call go to the audit as the record `POLICY REFUSED`.
- The read of Active Directory and two waves of writes are decided in ADR-0014 (slices W19–W21). The binary does not have any of these tools yet.

### Security

- `ps::escape` doubled only the ASCII apostrophe, but PowerShell also closes a string with the typographic quotes `‘ ’ ‚ ‛`. A path with such a quote ran code on the host through the read tools. It also ran code through the service, registry and delete scripts, around confirmation. Now all five forms double.
- Any holder of the shared secret could open a session with the cached password of another user by naming that user's `X-AD-User`.
- A host of the form `evil.com/.corp.example` passed the suffix check of the list. `winrm-rs` connected to `evil.com` and gave the NTLMv2 response to it. A host that is not a name or an IP address is now rejected with any list.
- The administrative shares `\\host\C$\...`, `ADMIN$`, `PRINT$`, and on a domain controller `SYSVOL` and `NETLOGON` went around the path protection. Now a volume share is checked as a local path, and the others are protected in full.
- A write and a deletion check the path against the system directories that the host itself named. So Windows on a volume other than `C:` is also protected. Earlier `write_file` did not ask the host at all.

## [0.1.0] - 2026-09-21

The first release: the successor of the Python project `win-mcp-server` in Rust with the same domain rules and tool contracts.

### Added

- An MCP server with 37 tools over WinRM/NTLM: file system read, system diagnostics, identity and configuration, network and software inventory.
- Modifying tools behind a confirmation: service control, process termination, registry writes, deletion of files and directories, DNS cache reset; `write_file` behind `WINRIG_ALLOW_FILE_WRITE`.
- Two modes from one binary: `serve` (streamable HTTP `/mcp`, several projects) and `stdio` (one local client).
- Encrypted account profiles: `setup`, `list`, `rotate`, `forget`; the password is stored as authenticated ciphertext, and the key stays at the client.
- `setup --write-config` for opencode, Claude Code, Codex and Cursor, at the level `global` or `project`.
- Two secrets, one for each request: the shared `WINRIG_AUTH_TOKEN` with `X-AD-User`, or the profile token that sets the identity.
- Audit and log rotation with private permissions (`0700`/`0600`); the secrets are cut from the replies and always from the logs.
- A host allowlist, the ban on the TLS downgrade, path protection at deletion and file write, and the handling of an AD account lockout.
