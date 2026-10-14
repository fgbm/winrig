# Changelog

All notable changes of the project are listed here. The format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the versions follow [Semantic Versioning](https://semver.org/).

A release goes out under the tag `vX.Y.Z`; the tag starts `.github/workflows/release.yml`. That workflow builds archives for five platforms, publishes a GitHub Release and attaches the binaries with checksums. The version in `Cargo.toml` and the entry here go up in one commit — see `docs/IMPLEMENTATION_CYCLE.md`.

## Unreleased

### Added

- The bilingual documentation site on GitHub Pages.
- The Russian README (`README.ru.md`).
- The style guides and the Vale check.
- The comment check.
- The `subkeys` and `depth` parameters of `get_registry`, which list the child key names of a key (#18).
- Any event channel in `get_event_log`, and the read-only tool `list_event_logs` (#16).
- The read-only tool `get_open_handles`, which names the processes that hold a file open (#21).
- The read-only tools `get_printers` and `get_print_jobs` (#19).
- The `from_end`, `count_only`, `since`, `until` and `timestamp_format` parameters of `search_file_content`, and the `exclude` filter of the `read_file` tail mode (#17).
- The read-only tool `get_service_config` and the modifying tool `set_service_start_type`; `stop_service` verifies the stop (#10).
- The subcommand `winrig doctor`, which compares the settings of the winrig servers in the client configuration (#24).
- The `summary` mode and the `pid` and `process` filters of `get_tcp_connections` (#20).
- The modifying tool `run_command`, behind `WINRIG_ALLOW_COMMAND_EXEC`. The command goes in an encoded wrapper, holds at most 979 UTF-16 units, and the confirmation shows its full text. The optional prefix list `WINRIG_ALLOWED_COMMANDS` filters it (#14).
- `WINRIG_CONFIRM_FALLBACK=proceed`, which runs a modifying tool without a confirmation only when the client declared no elicitation capability (#14).
- The modifying tool `run_script`, behind `WINRIG_ALLOW_SCRIPT_EXEC`. It stages a temporary script on the host, checks its SHA-256 and runs it as a script block (#14).
- The operator allowlist `WINRIG_WRITE_ALLOW_PATHS`, which permits a write under a protected path. The confirmation warns for a system directory, a volume root or a share root (#13).
- The modifying tools `copy_file`, `move_file`, `rename_file` and `create_directory`, behind `WINRIG_ALLOW_FILE_OPS` (#12).
- The modifying tools `download_file` and `upload_file`, behind `WINRIG_ALLOW_FILE_DOWNLOAD` and `WINRIG_ALLOW_FILE_UPLOAD`. They move files between the host and `WINRIG_TRANSFER_DIR` and check the SHA-256 on both sides (#11).
- The setting `WINRIG_MAX_TRANSFER_BYTES`, with the default of 256 MiB.

### Changed

- The repository text is English by ASD-STE100 (ADR-0016).
- The tool descriptions, the parameter descriptions and the CLI help are rewritten in STE.
- The error messages, the log messages and the tool results are rewritten in STE.
- The comment check is stricter. It also finds a first sentence that restates the name. It finds a short field doc without information and a repeated subject in a doc block.
- The confirmation form describes its field in English.
- Every confirmation names the tool, the host and the user, and states the effect and whether the operator can undo it (TR-SEC-16..20).
- Every generated script carries a preamble that silences the PowerShell progress stream, and `write_file` sizes each chunk by the WinRS command-line budget.
- The tool list holds 52 declared tools, 43 of them visible by default. Each flag adds its tools.
- `write_file` reaches the host with literal .NET calls, so a wildcard in a path does not expand (#12).

### Fixed

- Two tests that capture the tracing output failed about one time in 300 runs. The capture now rebuilds the tracing interest cache (#9).
- The CLIXML progress record that PowerShell wrote to stderr no longer appears in the result of a tool call (#22).
- `write_file` expanded a wildcard in the destination path (#12).

### Security

- The result parser drops the CLIXML position lines that can hold a fragment of a secret (DR-4).
- The confirmation sanitizes every field that the host provides, so a value cannot forge the dialog (DR-4).
- `set_registry` hides the old value next to the new value, and `kill_process` shows the executable path and never the command line (DR-4).
- The dependency `rustls` is 0.23.46. It fixes RUSTSEC-2026-0346, RUSTSEC-2026-0347, RUSTSEC-2026-0348 and RUSTSEC-2026-0349.
- `write_file` no longer expands a wildcard in the destination, so a name with a wildcard cannot write to several files (#12).
- The certificate listing and `set_registry` pass the path with `-LiteralPath`, so a wildcard in the store name or the key name does not expand.
- The audit holds the text of a command and of a script with the secrets masked (DR-4). It never holds the base64 of the encoded wrapper or of a chunk.

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
