# winrig

[![CI](https://github.com/fgbm/winrig/actions/workflows/ci.yml/badge.svg)](https://github.com/fgbm/winrig/actions/workflows/ci.yml)
[![Release](https://github.com/fgbm/winrig/actions/workflows/release.yml/badge.svg)](https://github.com/fgbm/winrig/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/github/license/fgbm/winrig)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.98%2B-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)

**A Windows MCP server for remote administration over WinRM/NTLM, written in Rust.** Diagnose, inspect, and manage any AD-joined Windows host from Cursor, Claude Code, Codex, opencode, or any MCP (Model Context Protocol) client. The AD password is entered once through `winrig setup`, stored only as authenticated ciphertext under a key that stays with the client, and never written to a client config in plaintext.

`winrig` is the Rust successor of the Python `win-mcp-server`. It keeps the same domain rules, module boundaries and tool contracts, but ships as a single static binary with no container and no interpreter, running either as an HTTP service (`winrig serve`) or as a local stdio process (`winrig stdio`).

- **Low memory, one binary**: one release binary, no runtime, no container. Resident memory stays around 11 MiB after startup and repeated requests on the development machine (`VmRSS` from `/proc`).
- **37 tools**, plus `write_file` once the operator enables it: filesystem, services, registry, event logs, certificates, processes, network, scheduled tasks, and more. These are the tools ported so far; the Python `win-mcp-server` had file-transfer (copy/move/rename/archive), `invoke_http_request` and SFTP tools that are not yet ported.
- **One profile per process**: `winrig setup` writes an encrypted profile; the token it prints is the only key and is shown once. A second process on the same profile refuses to start and points to the HTTP mode.
- **Two secrets, one per request**: a request is authenticated either by `WINRIG_AUTH_TOKEN` (header path with `X-AD-User`) or by the profile token, which fixes the identity and ignores `X-AD-*`.
- **No secrets on disk**: no credentials in config files or logs. Only authenticated ciphertext lives in the profile file.

## Why Rust

- One release binary, `cargo build --release`; no Docker, no Python, no pip.
- Memory is bounded and small; one long command cannot stall another request because the transport is async.
- The WinRM/NTLM client, MCP protocol and HTTP stack are mature crates, so the project carries domain logic, not protocol plumbing. See `docs/adr/0007-rust-stack.md`.

## Tools

### Session

| Tool | Description |
|------|-------------|
| `connect` | Open a WinRM session to a Windows host and return a `session_id` (HTTP 5985 or HTTPS 5986 via `use_ssl`) |
| `disconnect` | Close an active WinRM session |
| `list_sessions` | List active WinRM sessions with usage details |

### Filesystem (read-only)

| Tool | Description |
|------|-------------|
| `list_directory` | List files and directories at a path |
| `find_files` | Recursively find files by wildcard pattern |
| `read_file` | Read file contents as numbered lines |
| `search_file_content` | Grep-like text search in a file or across a directory |
| `file_info` | JSON metadata for a file or directory |
| `compare_files` | Line-by-line diff of two files |

### System diagnostics (read-only)

| Tool | Description |
|------|-------------|
| `get_event_log` | Windows Event Log: crashes, service failures, auth errors |
| `get_services` | Services summary or full JSON detail per service |
| `list_processes` | Processes sorted by CPU, memory, or handles |
| `get_system_info` | OS version, uptime, RAM, CPU count, domain, timezone |
| `get_disk_space` | Disk space for all fixed drives |
| `get_perf_snapshot` | Locale-independent CPU, memory, disk I/O, network snapshot |
| `get_registry` | Read a registry key or value (read-only) |
| `get_certificates` | Personal store certificates sorted by days until expiry |
| `get_network_config` | Per-NIC IP, gateway, and DNS configuration |
| `test_network` | ICMP ping or TCP port test from the remote host |

### Identity & configuration (read-only)

| Tool | Description |
|------|-------------|
| `get_environment_variables` | Environment variables by scope |
| `get_scheduled_tasks` | Scheduled tasks with last/next run and result |
| `get_local_users` | Local user accounts with status and last logon |
| `get_user_groups` | Local group memberships |
| `get_security_context` | Current session identity, groups, privileges |
| `get_permissions` | File/folder ACL entries |

### Network & software (read-only)

| Tool | Description |
|------|-------------|
| `get_tcp_connections` | Active TCP connections with owning process |
| `get_dns_cache` | Local DNS client cache |
| `get_installed_software` | Installed software from 64-bit and 32-bit uninstall keys |
| `resolve_dns_name` | DNS resolution chain from the remote server |

### Active Directory — decided, not built yet

None of these exist in the binary today: the section records a decision (ADR-0014, slices W19–W21), not a capability. It is here because the absence itself misleads — an agent that sees WinRM and a domain-joined host assumes the directory is reachable, and it is not.

Why it is not: NTLM gives the remote host a network logon with no delegatable credentials, so a directory query from an ordinary member server is a second hop to a domain controller and fails with `An operations error occurred`. `run_command` will not change that — it runs in the same session with the same token. The route that works needs no delegation at all: **connect to the domain controller itself**, where the query is local. Only `get_security_context` touches AD today, and only because domain groups sit in the session token.

Planned for slice W19, read-only, queried through `System.DirectoryServices` rather than the RSAT cmdlets (those talk to ADWS and need the module and the service):

| Tool | Description |
|------|-------------|
| `get_ad_object` | One user, group, or computer: account state, password dates, last logon, DN, OU |
| `get_ad_membership` | Membership in both directions, optionally nested |
| `find_ad_objects` | Search by name or `sAMAccountName`, capped |
| `get_ad_domain_info` | Domain, forest, functional levels, FSMO roles, DCs, trusts, sites, password policy and PSOs |
| `get_ad_health` | Replication partners and lag, NTDS/DNS/ADWS/W32Time services, SYSVOL state |
| `get_ad_stale_objects` | Dormant users or computers by `lastLogonTimestamp` and `pwdLastSet` |

Writing to the directory (slices W20–W21) is decided in the same ADR and deliberately left out of the first wave: it will be off by default behind `WINRIG_ALLOW_AD_WRITE`, will confirm every call with the object's DN, will refuse protected objects and built-in groups before touching the network, will take one explicitly named object per call and never a filter, and will accept an attribute only if it passes `WINRIG_AD_WRITABLE_ATTRIBUTES`. Neither variable is read by the current binary. Changing the topology of a domain or forest — seizing FSMO roles, metadata cleanup, forcing replication — and deleting directory objects are not planned at all.

### Write operations (all require user confirmation)

| Tool | Description |
|------|-------------|
| `restart_service` / `stop_service` / `start_service` | Manage services with before/after state |
| `kill_process` | Force-terminate a process by PID |
| `set_registry` | Set a registry value showing old vs new |
| `delete_file` / `delete_directory` | Delete with a confirmation prompt; protected paths refused |
| `flush_dns` | Clear the DNS client cache |
| `write_file` | Write a file, replacing it as a whole. **Off by default**: set `WINRIG_ALLOW_FILE_WRITE=true`, or the tool is not advertised and cannot be called |

`write_file` refuses protected paths with the same list that guards deletion, and refuses an existing file unless `overwrite` is set. Content travels in ~2 KB chunks because the WinRS command line is limited to about 8191 characters, so it suits configuration files and scripts rather than large payloads; `WINRIG_MAX_WRITE_BYTES` (64 KiB by default) caps the rest. Chunks land in a temporary file next to the target, and the target is replaced by a rename, so a failure part-way leaves the existing file untouched.

That chunk limit applies to the command line, not to output. A script too long for one command is written with `write_file` and then run by path — the command stays short however long the script is.

## Install

Prebuilt binaries are attached to every release for Linux, macOS and Windows, with a `sha256` checksum beside each archive. Linux binaries are statically linked (musl), so they carry no glibc version requirement.

```bash
# Change the version and target to match your platform.
curl -LO https://github.com/fgbm/winrig/releases/latest/download/winrig-v0.1.0-x86_64-unknown-linux-musl.tar.gz
curl -LO https://github.com/fgbm/winrig/releases/latest/download/winrig-v0.1.0-x86_64-unknown-linux-musl.sha256
sha256sum -c winrig-v0.1.0-x86_64-unknown-linux-musl.sha256
tar xzf winrig-v0.1.0-x86_64-unknown-linux-musl.tar.gz
install -m 0755 winrig ~/.local/bin/winrig
```

Archives are named `winrig-v<version>-<target>`, where the target is one of `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-apple-darwin`, `aarch64-apple-darwin` or `x86_64-pc-windows-msvc`. On macOS the `aarch64` archive is for Apple Silicon and `x86_64` for Intel; `tar` and `unzip` both work, as the archive carries `LICENSE` and `README.md` next to the binary.

To build from source instead, see [Quick Start](#quick-start).

## Quick Start

Build once:

```bash
cargo build --release
```

Create an encrypted profile. The password is read without echo, and the token is printed exactly once:

```bash
./target/release/winrig setup corp --user 'DOMAIN\your-ad-username'
```

The command prints the access token and a JSON definition of the MCP server. Either paste that definition into your client, or let `setup` write it for you (the config is updated in place, other entries are untouched):

```bash
./target/release/winrig setup corp --user 'DOMAIN\your-ad-username' --write-config opencode --scope global
./target/release/winrig setup corp --user 'DOMAIN\your-ad-username' --write-config claude-code --scope project
```

`--write-config` requires a scope. Pass `--scope global` for the user-wide config or `--scope project` for the current repository; without the flag `setup` asks in the terminal, and in a non-interactive run (script, CI) it refuses and points you to `--scope`.

The entry is named after the one that already serves this profile, so re-running `setup` updates it in place instead of adding a second one. That matters: two entries on one profile start two processes, the second one loses the profile lock and exits, and the client reports only `MCP error -32000: Connection closed`. When no entry serves the profile yet the name is `winrig`; `--server-name` sets it explicitly.

Supported clients: `opencode`, `claude-code`, `codex`, `cursor`. Project scope finds the nearest ancestor directory containing `.git` (falling back to the current directory) and writes to `<root>/opencode.json`, `<root>/.mcp.json`, `<root>/.codex/config.toml` or `<root>/.cursor/mcp.json`; global scope keeps the user-wide paths. For opencode the token is written to a separate `0600` file and referenced as `{file:...}` so it never sits inside the config; at project scope that file lives in `WINRIG_STATE_DIR`, not in the repository. For the other three the token is written into the client config as a value; at project scope that file is usually committed, so `setup` prints a warning and `winrig` sets the file to `0600` on Unix.

Run the server in one of two modes:

```bash
# Local stdio process for one client (token comes from the client environment)
WINRIG_TOKEN='<token from setup>' ./target/release/winrig stdio --profile corp

# HTTP service on 127.0.0.1:8005/mcp for several projects
WINRIG_TOKEN='<token from setup>' ./target/release/winrig serve --profile corp

# Override the address from the command line (wins over the environment)
./target/release/winrig serve --profile corp --port 9000 --host 0.0.0.0

# Supply the secrets as arguments instead of the environment (wins over env)
./target/release/winrig serve --profile corp --token '<token from setup>'
./target/release/winrig serve --auth-token '<shared secret>'
```

The `--token` and `--auth-token` flags override `WINRIG_TOKEN` and `WINRIG_AUTH_TOKEN`. A secret passed as an argument is visible in the process list, so prefer the environment or the client config where possible.

The server definition printed and written by `setup` includes `WINRIG_TOKEN`, `WINRIG_PROFILE_DIR` and `WINRIG_STATE_DIR`, so a client finds the profile even when the directories are not the standard ones.

To keep the header path instead of a profile, set a shared secret and skip the profile:

```bash
echo "WINRIG_AUTH_TOKEN=$(openssl rand -base64 32)" >> .env
set -a; . ./.env; set +a
./target/release/winrig serve
```

In HTTP mode the default bind is `127.0.0.1:8005`; the endpoint is `/mcp`. At least one secret is required — the server refuses to start with neither a profile token nor `WINRIG_AUTH_TOKEN`.

## Profiles

```bash
winrig setup corp --user 'DOMAIN\user'   # create; prints the token once
winrig setup corp --user 'DOMAIN\user' --overwrite   # replace an existing profile
winrig list                              # table: NAME, USER, PATH; never secrets
winrig list --json                       # same data as JSON
winrig rotate corp                       # re-encrypt under a fresh token
winrig forget corp                       # delete the profile (idempotent)
```

The profile file is `corp.json` inside the profile directory, holding a format version, the canonical account name, an HKDF-SHA256 salt, an XChaCha20-Poly1305 nonce and ciphertext; the account name is bound as associated data. The file is `0600` inside a `0700` directory on Unix; wider permissions produce a warning, not a refusal. A wrong token and a corrupt file are reported differently in the journal but both answer the client with 401. If `WINRIG_AUTH_TOKEN` happens to be the profile token, startup refuses.

The account is given as `DOMAIN\user`; the split for NTLM follows `spnego` (the engine `requests-ntlm` used in the Python server): the name is split on the first backslash, a UPN (`user@realm`) or a bare name stays whole with an empty domain. The profile stores the account in canonical lower case, and that same value is sent to the host; NTLM upper-cases the user name itself when it builds the hash, so the case of the domain does not change the result.

One process per profile: a lock file in the profile's state directory stops a second process on the same profile and points to the HTTP mode. Profile changes on disk take effect on the next start. The profile password is still subject to the AD lockout; if it is rejected twice in separate lockout windows, the profile is refused until the process restarts and you should run `setup` again.

## Configuration

Everything is configured through the environment; there is no config file. The profile file is not configuration — it is a store of ciphertext (ADR-0009).

| Variable | Default | Purpose |
|----------|---------|---------|
| `WINRIG_AUTH_TOKEN` | — | Shared secret for the header path; a request must present it as `Authorization: Bearer <token>` or `X-MCP-Token`. Optional when a profile token is used |
| `WINRIG_PROFILE` | — | Profile name; omitted when exactly one profile exists, required when several do |
| `WINRIG_TOKEN` | — | Access token printed by `setup`; required in stdio mode and for the profile path in HTTP |
| `WINRIG_PROFILE_DIR` | OS config dir | Overrides the profile directory (`~/.config/winrig` on Linux) |
| `WINRIG_STATE_DIR` | OS state dir | Overrides the **root** of the state directory; `winrig` appends the profile name itself, so the per-profile locks and default logs land in `<WINRIG_STATE_DIR>/<profile>`. Point it at the root, not at a profile's own directory, or the lock moves one level away from where the config claims it is |
| `WINRIG_BIND_HOST` | `127.0.0.1` | Address the HTTP server listens on |
| `WINRIG_PORT` | `8005` | Port the HTTP server listens on |
| `WINRIG_PASSWORD_TTL_SECONDS` | `3600` | How long a cached AD password survives without use. `0` disables expiry. In profile mode it only bounds how long the decrypted password stays in memory; it never forces a re-entry |
| `WINRIG_LOG_DIR` | profile state dir | Directory for `winrig.log` and `winrig-audit.log`. Created `0700`, files `0600` |
| `WINRIG_LOG_LEVEL` | `INFO` | Level of the server log (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`). Does not affect the audit trail, which is always written |
| `WINRIG_LOG_MAX_BYTES` | `10485760` | Size at which a log file rotates |
| `WINRIG_LOG_BACKUP_COUNT` | `5` | Rotated files kept per log |
| `WINRIG_AUDIT_MAX_OUTPUT_CHARS` | `2000` | Characters of stdout/stderr per call kept in the audit trail |
| `WINRIG_AUDIT_LOG_BODY` | `1` | `0`, `false`, `no` or `off` logs only call metadata: no command text, no output |
| `WINRIG_CONFIRM_TIMEOUT_SECONDS` | `300` | How long a mutating tool waits for the confirmation answer before it fails closed |
| `WINRIG_LOCKOUT_ATTEMPTS` | `3` | Failed AD password attempts after which the password is not presented again for the lockout window |
| `WINRIG_LOCKOUT_WINDOW_SECONDS` | `1800` | How long a rejected password is kept from being retried, in seconds |
| `WINRIG_SECRET_REDACT_MIN_LENGTH` | `4` | Shortest secret redacted from the **reply to the agent**. The audit trail and log files redact secrets of any length, unconditionally |
| `WINRIG_ALLOWED_HOSTS` | *(empty)* | Comma-separated allowlist; empty allows every host. An entry is an exact hostname/IP (case-insensitive); an entry starting with `.` matches a suffix |
| `WINRIG_ALLOW_INSECURE_TLS` | `true` | Whether `verify_cert=false` is accepted. `false` refuses such a call before any network activity |
| `WINRIG_ALLOW_FILE_WRITE` | `false` | Whether the `write_file` tool exists. While `false` it is removed from the router: not advertised and not callable |
| `WINRIG_MAX_WRITE_BYTES` | `65536` | Largest content `write_file` accepts, in bytes. Refused before any network activity. Cannot be set below one 2000-byte chunk |
| `WINRIG_SFTP_CRED_TTL_SECONDS` | `3600` | Reserved for the SFTP tools (not yet ported); parsed and validated at startup |

### Transport security

`winrig` serves plain HTTP on `/mcp`; there is no TLS listener in the binary. **The bearer token is now a key: whoever captures it can both reach the server and decrypt the AD password.** Do not bind to a non-loopback address without a TLS-terminating reverse proxy in front (nginx, Caddy, or an ingress). The default bind address is `127.0.0.1` for exactly this reason: the multi-user deployment assumes the proxy authenticates clients and forwards the `Authorization`, `X-AD-User` and `X-AD-Password` headers unchanged. The remote WinRM leg is separate: use `use_ssl` / port 5986 when the hop to the Windows host must be encrypted, and keep `WINRIG_ALLOW_INSECURE_TLS=false` unless a self-signed certificate is deliberate.

Over plain HTTP that WinRM leg is only partly encrypted. `winrm-rs` seals SOAP bodies with the NTLM session key, but the key does not exist until the handshake completes, so the **first** request on every new connection carries its body as cleartext alongside the Type 3 message; only the follow-ups on that keep-alive connection are sealed. For `winrig` the first body is the shell `Create`, not the script — but a host that answers an unencrypted message with an empty `HTTP 500` (`AllowUnencrypted=false`, the Windows default) will refuse that first request outright. Port 5986 avoids both the exposure and the refusal.

## Client setup

There are two request shapes. With a **profile token**, the token is the secret and the identity comes from the profile — no `X-AD-User` is needed. With the **shared secret**, the request must carry `WINRIG_AUTH_TOKEN` and `X-AD-User`; the token is verified before `X-AD-User` is trusted, because that header is the key of the in-memory password and session cache.

`WINRIG_AUTH_TOKEN` is required only on the header path. `X-AD-Password` is optional at the HTTP layer but required to open a session unless a profile supplies the password: `winrig` does not request passwords through elicitation, because the MCP specification excludes secrets from it and protocol revision `2026-07-28` removes elicitation entirely (see `docs/adr/0006-password-header-and-confirmation.md`).

The paths below are the global ones written by `--scope global`; with `--scope project` the same entry goes to the project file listed in Quick Start.

### opencode (`~/.config/opencode/opencode.json`)

Written by `setup --write-config opencode --scope global`; the token is referenced from a private file:

```json
{
  "mcp": {
    "winrig": {
      "type": "local",
      "command": ["/path/to/winrig", "stdio", "--profile", "corp"],
      "environment": { "WINRIG_TOKEN": "{file:~/.config/opencode/winrig-token}" },
      "disabled": false
    }
  }
}
```

### Claude Code

Written by `setup --write-config claude-code --scope global` into the `mcpServers` block of `~/.claude.json`. The CLI equivalent:

```bash
claude mcp add winrig -- /path/to/winrig stdio --profile corp
```

### Codex (`~/.codex/config.toml`)

Written by `setup --write-config codex --scope global`:

```toml
[mcp_servers.winrig]
command = "/path/to/winrig"
args = ["stdio", "--profile", "corp"]

[mcp_servers.winrig.env]
WINRIG_TOKEN = "<token from setup>"
```

### Cursor (`~/.cursor/mcp.json`)

Written by `setup --write-config cursor --scope global` into the `mcpServers` block. The HTTP shape works the same way for any client: point it at the streamable HTTP endpoint and pass `Authorization: Bearer <token>`.

Any other MCP client works the same way: either use the stdio definition printed by `setup`, or point it at the HTTP endpoint with the profile token as the bearer.

### Confirmations on clients without elicitation

Mutating tools confirm through MCP elicitation and **fail closed** when the client cannot prompt. opencode 1.18.31 announces only `roots`, so write tools refuse to run there and say so instead of acting unconfirmed; read-only tools work normally. The replacement channel (`input_required`, SEP-2322) is tracked in `docs/ROADMAP.md` and `docs/QUESTIONS.md` Q-10.

## Logging

`WINRIG_LOG_DIR` holds `winrig.log` and the audit trail `winrig-audit.log`; the directory is created `0700` and the files `0600`, reapplied on every rotation.

The audit trail records each call with the PowerShell text and an excerpt of its output. Because that output can contain file contents, registry data, account lists and certificates, only the first `WINRIG_AUDIT_MAX_OUTPUT_CHARS` characters default to being written — the agent still receives the full response. Set `WINRIG_AUDIT_LOG_BODY=0` to log only call metadata.

In stdio mode stdout carries only JSON-RPC: the server log and audit go to stderr and to the profile's state directory, so a client that runs `winrig stdio` never sees log lines mixed into the protocol.

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo deny check
cargo build --release
```

The pinned toolchain lives in `rust-toolchain.toml`; CI runs the same commands, plus `cargo-audit` and a build on the MSRV (`rust-version` in `Cargo.toml`). There is no live Windows host in the development environment. Tests run against a fake `WinRmTransport` that records the commands it is given, and never touch the network; `tests/http_gate.rs` exercises the real axum+rmcp `/mcp` wiring, and `tests/stdio_mode.rs` runs the real binary over stdio. The project canon, requirements, ADRs and review cycle live in `AGENTS.md` and `docs/`.

### Releases

A release is cut by bumping `version` in `Cargo.toml`, adding a matching entry to `CHANGELOG.md`, and pushing a `vX.Y.Z` tag. The tag drives `.github/workflows/release.yml`: a GitHub Release is created from the changelog entry, and the binary is built for five targets and attached with a `sha256` checksum. The workflow refuses to run if the tag and the `Cargo.toml` version disagree.

| Workflow | Trigger | What it does |
|----------|---------|--------------|
| `ci.yml` | every push and pull request | `fmt`, `clippy`, `test`, release build, MSRV build, `cargo-audit`, `cargo-deny` |
| `release.yml` | a `vX.Y.Z` tag | writes the GitHub Release and uploads the platform archives with checksums |

## License

MIT — see [LICENSE](LICENSE).
