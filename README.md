# winrig

[![CI](https://github.com/fgbm/winrig/actions/workflows/ci.yml/badge.svg)](https://github.com/fgbm/winrig/actions/workflows/ci.yml)
[![Release](https://github.com/fgbm/winrig/actions/workflows/release.yml/badge.svg)](https://github.com/fgbm/winrig/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/github/license/fgbm/winrig)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.98%2B-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)

English | [Русский](README.ru.md)

The full documentation is at https://fgbm.github.io/winrig/.

**An MCP server for the remote administration of Windows hosts over WinRM/NTLM, written in Rust.** Diagnose, examine and administer any Windows host that joined the AD domain. Use Cursor, Claude Code, Codex, opencode or any MCP (Model Context Protocol) client. Enter the AD password one time through `winrig setup`. The server keeps the password only as authenticated ciphertext under a key that stays at the client. The server never writes the password in clear text into the client configuration.

`winrig` is the Rust successor of the Python project `win-mcp-server`. It keeps the same domain rules, module boundaries and tool contracts. It ships as one static binary without a container or an interpreter. It runs either as an HTTP service (`winrig serve`) or as a local stdio process (`winrig stdio`).

- **Low memory, one binary**: one release binary, with no runtime and no container. Resident memory stays near 11 MiB after start and repeated requests on the development computer (`VmRSS` from `/proc`).
- **43 tools** plus `write_file`, `run_command`, `run_script`, the file operations, `download_file` and `upload_file`, when the operator enables them. They cover the file system, services, registry, event logs, certificates, processes, network, scheduled tasks and more. The current version includes these ported tools. The Python version `win-mcp-server` had archive tools (compress and expand), `invoke_http_request` and SFTP tools. The current version does not include those tools yet.
- **One process for each profile**: `winrig setup` creates an encrypted profile. The printed profile token is the only key, and `setup` shows it one time. A second process on the same profile refuses to start and points to the HTTP mode.
- **Two secrets, one for each request**: a request authenticates with `WINRIG_AUTH_TOKEN` (the header path with `X-AD-User`) or with a profile token. The profile token gives the identity and makes the server ignore `X-AD-*`.
- **No secrets on disk**: no account credentials in configurations or in logs. The profile file holds only authenticated ciphertext.

## Why Rust

- One release binary, `cargo build --release`; without Docker, without Python, without pip.
- Memory stays bounded and small. One long command cannot block another request, because the transport is asynchronous.
- The WinRM/NTLM client, the MCP protocol and the HTTP stack are mature crates. The project therefore carries the domain logic, not the protocol plumbing. See `docs/adr/0007-rust-stack.md`.

## Tools

### Session

| Tool | Description |
|------|-------------|
| `connect` | Open a WinRM session to a Windows host and return a `session_id` (HTTP 5985 or HTTPS 5986 through `use_ssl`) |
| `disconnect` | Close the active WinRM session |
| `list_sessions` | List the active WinRM sessions with usage details |

### File system (read only)

| Tool | Description |
|------|-------------|
| `list_directory` | List the files and directories at a path |
| `find_files` | Find files recursively by a pattern |
| `read_file` | Read the content of a file with line numbers. The tail mode can drop the lines that contain a literal text |
| `search_file_content` | Search text in a file or a directory, like grep. The tool can return the last matches, count the matches, and filter the lines by the timestamp at the start |
| `file_info` | The metadata of a file or a directory in JSON |
| `compare_files` | A line-by-line diff of two files |

### System diagnostic (read only)

| Tool | Description |
|------|-------------|
| `get_event_log` | The Windows event log: crashes, service failures, authentication errors |
| `list_event_logs` | The event log channels with the record count and the enabled state |
| `get_services` | A summary of the services, or the full details of each service in JSON |
| `get_service_config` | One service: the start type, the account, the binary path and the recovery actions. The start type is Automatic, AutomaticDelayed, Manual or Disabled. The recovery actions hold the action, the delay and the reset period |
| `list_processes` | The processes with a sort by CPU, memory or handles |
| `get_open_handles` | The processes that hold a file open, with the PID, the name and the start time. It uses the Restart Manager, so a host needs no Sysinternals `handle.exe` |
| `get_printers` | The printers with the share name, the driver, the port, the port host and number, the state as the PrinterStatus name and the job count |
| `get_print_jobs` | The print jobs of one printer with the job id, the state, the size and the submit time. The document name and the owner stay hidden unless `include_personal_data` is true |
| `get_system_info` | The OS version, uptime, RAM, CPU count, domain, time zone |
| `get_disk_space` | The free space on all fixed disks |
| `get_perf_snapshot` | A snapshot of CPU, memory, disk I/O and network, independent of the locale |
| `get_registry` | Read a registry key or value and, on request, the child key names (read only) |
| `get_certificates` | The certificates in the personal store, sorted by the days to expiry |
| `get_network_config` | IP, gateway and DNS for each network adapter |
| `test_network` | An ICMP ping or a TCP port check from the host |

### Identity and configuration (read only)

| Tool | Description |
|------|-------------|
| `get_environment_variables` | The environment variables by scope |
| `get_scheduled_tasks` | The scheduled tasks with the last/next run and the result |
| `get_local_users` | The local accounts with the status and the last logon |
| `get_user_groups` | The membership in local groups |
| `get_security_context` | The identity of the current session, the groups, the privileges |
| `get_permissions` | The ACL entries for files and directories |

### Network and software (read only)

| Tool | Description |
|------|-------------|
| `get_tcp_connections` | The active TCP connections, filtered by state, port, PID or process name, with an optional grouped summary |
| `get_dns_cache` | The local DNS client cache |
| `get_installed_software` | The installed software from the 64-bit and 32-bit uninstall keys |
| `resolve_dns_name` | The DNS resolution chain from the host |

### Active Directory — decided, but not built

The binary has none of these tools today. The section records a decision (ADR-0014, slices W19–W21), not a capability. It is here because the absence itself is misleading. An agent that sees WinRM and a host in the domain assumes that the directory is available, but it is not.

Why: NTLM gives the host a network logon without delegatable credentials. A directory request from a host that is a domain member is therefore a second hop to the domain controller, and it fails with `An operations error occurred`. `run_command` will not change this. It runs in the same session with the same token. The route that works needs no delegation at all: **connect to the domain controller itself**, where the request is local. Today AD touches only `get_security_context`, and only because the domain groups are in the session token.

The project plans these tools in slice W19. They are read only and use `System.DirectoryServices`, not RSAT cmdlets. Those cmdlets go to ADWS and need an installed module and a running service:

| Tool | Description |
|------|-------------|
| `get_ad_object` | One user, group or computer: the account state, the password dates, the last logon, the DN, the OU |
| `get_ad_membership` | The membership in both directions, nested when necessary |
| `find_ad_objects` | A search by name or `sAMAccountName` with a result cap |
| `get_ad_domain_info` | The domain, the forest, the functional levels, the FSMO roles, the controllers, the trusts, the sites, the password policy and the PSO |
| `get_ad_health` | The replication partners and the lag, the NTDS/DNS/ADWS/W32Time services, the SYSVOL state |
| `get_ad_stale_objects` | The stale users and computers by `lastLogonTimestamp` and `pwdLastSet` |

The same ADR decides the directory write (slices W20–W21), and it stays intentionally outside the first wave. It will be off by default behind `WINRIG_ALLOW_AD_WRITE`. It will confirm each call with the object DN. It will reject protected objects and built-in groups before any network activity. It will accept exactly one explicitly named object for each call, and never a filter. It will accept an attribute only if the attribute passes `WINRIG_AD_WRITABLE_ATTRIBUTES`. The current binary does not read any of these variables. The project does not plan a change of the domain or the forest topology: FSMO role seizure, metadata cleanup or forced replication. The project does not plan the deletion of directory objects either.

### Modifying operations (all need confirmation)

| Tool | Description |
|------|-------------|
| `restart_service` / `stop_service` / `start_service` | Manage the services with the state before and after. `stop_service` verifies the stop: it waits `wait_seconds` (15 by default), reads the state and the System events 7031/7034/7036, and reports an error when the service runs again. With `disable=true` it sets the start type to Disabled before the stop |
| `set_service_start_type` | Set the start type (Automatic, AutomaticDelayed, Manual or Disabled). The confirmation shows the current and the new start type. The tool refuses a service that is critical for the remote session |
| `kill_process` | Terminate a process by PID. The confirmation shows the name, the executable path (with no arguments) and the start time. The command line is never read, so a secret in it cannot leak (DR-4) |
| `set_registry` | Write a registry value. The old value and the new value appear only as `hidden`; the prompt shows whether the old value is present and its type |
| `delete_file` / `delete_directory` | Delete with a confirmation prompt; the tool rejects protected paths, including by the actual location of the system on the host. `delete_file` accepts the operator allowlist `WINRIG_WRITE_ALLOW_PATHS`; the recursive `delete_directory` does not (DR-6) |
| `flush_dns` | Clear the DNS client cache |
| `write_file` | Write a file with a full replacement. **Off by default**: set `WINRIG_ALLOW_FILE_WRITE=true`, or the server does not declare the tool and no call can reach it |
| `run_command` | Run an arbitrary PowerShell command. **Off by default**: set `WINRIG_ALLOW_COMMAND_EXEC=true`, or the server does not declare the tool and no call can reach it. The confirmation shows the full command text. The server refuses a command outside a non-empty `WINRIG_ALLOWED_COMMANDS` before any network activity |
| `run_script` | Run a PowerShell script that is longer than one WinRS command line. **Off by default**: set `WINRIG_ALLOW_SCRIPT_EXEC=true`, or the server does not declare the tool and no call can reach it. The server writes the script into a temporary `.ps1` in the session temp directory. It reads the file and runs its text as a script block, then tries to delete the file. The script has no `$PSScriptRoot`, no `$PSCommandPath` and no arguments. One confirmation covers the whole operation and shows the whole script and its SHA-256. The prefix list `WINRIG_ALLOWED_COMMANDS` does not filter a script |
| `copy_file` / `move_file` / `rename_file` / `create_directory` | Copy, move or rename a file or a directory, and create a directory with its parents. **Off by default**: set `WINRIG_ALLOW_FILE_OPS=true`, or the server does not declare the tools and no call can reach them. All four prompt for confirmation. A directory copy shows the counts, and it refuses a source tree that holds a symbolic link or a junction. A move on one volume renames; across volumes it copies a file and deletes the source, and it refuses a cross-volume directory move (DR-6). A rename takes one new name. None of the four replaces an existing directory, and an existing target needs `overwrite` (except `create_directory`, which refuses it). The target obeys `WINRIG_WRITE_ALLOW_PATHS`; a copy source may lie under a system directory, because a copy only reads it |
| `download_file` | Copy a file from the host into the local transfer directory. **Off by default**: set `WINRIG_ALLOW_FILE_DOWNLOAD=true`, or the server does not declare the tool and no call can reach it. The tool reads the file on the host in chunks and writes it into `WINRIG_TRANSFER_DIR`, and it compares the SHA-256 of the two sides. The reply carries the name, the size and the hash, not the content. Every download needs a confirmation (ADR-0017 §21–28) |
| `upload_file` | Copy a file from the local transfer directory to the host. **Off by default**: set `WINRIG_ALLOW_FILE_UPLOAD=true`, or the server does not declare the tool and no call can reach it. The tool hashes the local file and shows the SHA-256 in the confirmation. It sends the bytes in windows of 4 MiB into a temporary file. Each window goes through the standard input of a host command. The host hashes that file before the rename. The target obeys `WINRIG_WRITE_ALLOW_PATHS`, and an existing target needs `overwrite`. Every upload needs a confirmation (ADR-0017 §26) |

Each confirmation names the host of the session, the user of the request and the tool. It names the target and the operation with the details that are available before the call. It holds one plain line that states the effect. The line states whether the operator can undo it. A hidden value appears only as `hidden`: the old and new values of `set_registry` and the content of `write_file` are hidden values. The text of a command and the text of a script appear in full, without the 200-character cap, because the operator confirms what will run. `kill_process` does not read the command line at all. The server sanitizes each field and caps the other fields at 200 characters. A cut path keeps its tail, and a cut field carries the marker `...` inside the cap. The text is English and does not depend on the language of the host. The file operations show the resolved source and target, the size or the counts, and the overwrite state.

`write_file` rejects protected paths with the same list that guards deletion. It rejects an existing file if `overwrite` is not set. Before confirmation, the host reports where the file will really land and where the system directories are (`SystemRoot`, `ProgramFiles`, `ProgramFiles(x86)`, `ProgramData`, user profiles). Therefore Windows on a volume other than `C:` is equally protected. The tool rejects a path with an 8.3 name (`PROGRA~1`), because only the host can compare it with the list. The tool checks the administrative share `\\host\C$\...` as `C:\...`. The server protects the shares `ADMIN$`, `PRINT$`, `SYSVOL` and `NETLOGON` in full. The tool does not resolve junctions and symlinks in the parent directories of the target (ADR-0015). The operator can permit a write under a protected root with `WINRIG_WRITE_ALLOW_PATHS` (ADR-0017). Such an entry lifts the refusal for `write_file` and `delete_file`. The confirmation then carries a warning line that names the class. The allowlist never lifts the 8.3 refusal. It also never lifts the refusal of a symbolic link or a junction, because the operation would act on the link target. A device volume path (`\\?\Volume{...}`, `\\?\GLOBALROOT`) and an existing directory target are refused too. The audit records the entry that permitted a protected path. The content travels in chunks of about 1.5 KB, because the WinRS command line accepts about 8191 characters at most. The tool refuses a path so long that its commands would not fit this line. The limit is about 530 characters for UTF-8 and about 470 characters for the other encodings, for a path with no quote character. The tool is therefore good for configuration files and scripts, not for large volumes. `WINRIG_MAX_WRITE_BYTES` limits the size (64 KiB by default). The chunks land in a temporary file next to the target. A rename replaces the target. A failure in the middle therefore leaves the existing file untouched.

This length limit applies to the command line, not to the output. Write a script that does not fit in one command with `write_file`, then run the script by its path. The command stays short, however long the script is.

`run_command` is off by default. Set `WINRIG_ALLOW_COMMAND_EXEC=true` to declare it. It runs one PowerShell command. The operator confirms it, and the prompt shows the full command text. The server encodes the command text as a base64 UTF-16 string. It decodes the string into a script block on the host. A quote or a terminator in the text therefore cannot break out of the generated wrapper. The command must fit one WinRS command line, so the text holds at most 979 characters. A longer script goes through `write_file` and then runs by path, or through `run_script`. The server refuses a command outside a non-empty `WINRIG_ALLOWED_COMMANDS` before any network activity. The list is a set of prefixes, matched without case after a trim. An empty list admits any command. The list is not a boundary. A leading `&`, `.` or `powershell -c` starts with text the list need not contain. An alias, a call operator and an encoded command do the same. Any text after an allowed prefix runs. So `;`, a newline, `|` and `$(...)` do not return control to the list. An entry of `&` or `.` alone admits every command. A script written with `write_file` and then started also goes around it (ADR-0013 §18). The list protects against an accidental command, not against intent. With `run_command` on and an empty list, the path protection of the other tools stops being a guarantee of the product. The same holds for the confirmation of the other modifying operations. They stay properties of their own tools. This is a deliberate choice of the operator (ADR-0013, Q-14).

`run_script` is off by default. Set `WINRIG_ALLOW_SCRIPT_EXEC=true` to declare it. It runs a PowerShell script that is longer than one WinRS command line. The server writes the script into a temporary `.ps1` in the session temp directory in chunks. It reads the file and runs its text as a script block, then tries to delete the file. The script has no `$PSScriptRoot`, no `$PSCommandPath` and no arguments. The tool shows the SHA-256 of the script in the confirmation and records it in the audit, and it verifies the hash before the run. One confirmation covers the whole operation and shows the whole script, line by line and without the 200-character cap. The prefix list `WINRIG_ALLOWED_COMMANDS` does not filter a script, because the server cannot prefix-check the text of a script in a meaningful way. The confirmation states this. The script obeys `WINRIG_MAX_WRITE_BYTES`, and the output obeys the same limits as `run_command`. The result carries `temp_file` with the cleanup outcome, and a `warning` when the temporary file may remain. The tool can fail if the script produces no output for 60 seconds (ADR-0017 §29–34).

The file operations `copy_file`, `move_file`, `rename_file` and `create_directory` are off by default. Set `WINRIG_ALLOW_FILE_OPS=true` to declare them. `copy_file` copies a file or a directory. A directory copy is recursive, and the confirmation shows the file, directory and byte counts. The copy walks the source tree once and refuses it when it holds a symbolic link or a junction. The command repeats the check at run time. `move_file` renames the object on one volume. Across volumes it copies a file, verifies the size and then deletes the source. It refuses a cross-volume move of a directory, because the implied recursive delete falls under DR-6. Copy the directory and delete the source with two calls. `rename_file` changes the last component in the same directory, and it takes one new name. A separator, a reserved device name (`CON`, `NUL`, `COM1`, ...) and a trailing dot or space are refused. `create_directory` creates the final directory and each missing parent. The confirmation shows the number of created levels and the shallowest created level, which also passes the write boundary. The target of each tool obeys the allowlist `WINRIG_WRITE_ALLOW_PATHS`. The source of a copy is read-only, so it may lie under a system directory. None of the four replaces an existing directory, and an existing target needs `overwrite` (except `create_directory`, which refuses it). The tools reach the host with the `[IO.File]` and `[IO.Directory]` classes, so a wildcard in a path cannot expand. A partial copy or move is an error, never a success. A long copy or move can fail if it produces no output for 60 seconds. A read-only target or source fails the operation with a clear error, because the tool has no `-Force` and never clears the read-only attribute. An overwrite keeps the replaced file's access control list and attributes. `write_file` also uses the host-resolved .NET path for its chunks.

`download_file` is off by default. Set `WINRIG_ALLOW_FILE_DOWNLOAD=true` to declare it. It reads a file on the host and writes it into the local transfer directory. First the tool reads the size and the modification time of the source. It refuses a file above `WINRIG_MAX_TRANSFER_BYTES` (256 MiB by default) before any read. The confirmation shows the resolved remote path, the size, the modification time and the local destination. It shows no hash, because the hash is not known before the read. The tool then reads the file in windows of 16 MiB through a raw channel, as base64 lines of 1 MiB. The output is continuous, so a large file does not time out, and the whole file never loads into the host memory. The host reads with a shared read and delete, so a file that another process holds open (a live log) still copies. The tool hashes the bytes while it reads them. After the last window, one more host pass hashes exactly the scanned length and compares the two digests. A mismatch or a short file is a refusal with the text "the source changed during the transfer". The tool writes the windows into a temporary file next to the target. A failure or a cancel removes that file, so no partial file remains. The reply carries the name, the size and the hash. The content never goes inline into the result. The local endpoint is `WINRIG_TRANSFER_DIR`, the transfer subdirectory of the state directory by default. In HTTP mode the server isolates each user in a subdirectory of its canonical identity (DR-3). The directory and its files use the private modes (`0700`/`0600`). The tool takes one plain local file name. It refuses a separator, a `..` component, a leading dot, a reserved device name, a symbolic link and a control or format character. An existing local file needs `overwrite`. A source that is a directory, a symbolic link or a junction is refused. A source under a system directory is allowed, and the confirmation warns for it. Every download needs a confirmation, because it moves data off the host. The audit records the resolved paths, the size, both hashes and the confirmation state. It never records the content (ADR-0017 §21–28).

`upload_file` is off by default. Set `WINRIG_ALLOW_FILE_UPLOAD=true` to declare it. It copies a file from the local transfer directory to the host. The tool takes one plain local file name and the absolute remote path. It reads only from the directory of the request user (DR-3). It refuses a symbolic link, an item that is not a regular file and a file that another user can write. On Unix it also refuses a file with more than one hard link. On Windows the tool cannot see a hard link, so keep the transfer directory private. It refuses a file above `WINRIG_MAX_TRANSFER_BYTES` (256 MiB by default) before the read. The tool hashes the local file once. The confirmation shows the local source, the resolved remote path, the size, the SHA-256, the overwrite state and the effect. The remote target obeys the boundary of `write_file`. A protected path is refused unless `WINRIG_WRITE_ALLOW_PATHS` covers it, and then the confirmation warns. An existing target needs `overwrite`. After the confirmation, the tool sends the file in windows of 4 MiB. Each window is one host command, and the bytes arrive on its standard input, not in the command text. Therefore the WinRS command line limit of about 8191 characters does not limit the size of a window. The first window creates a temporary file next to the target and refuses an existing file. Each later window must find the temporary file at the expected length. The tool hashes the bytes again while it sends them. It stops when the digest differs from the confirmed one, for example when the local file changed after the confirmation. The last host command hashes the temporary file and compares the digest with the confirmed one. It then checks the target and every parent directory for a symbolic link or a junction. Then it places the file by a rename (an atomic replace with `overwrite`). A mismatch or a failure before the placement removes the temporary file and leaves the target unchanged. A cancel stops the host command and removes the temporary file. A cancel or a lost answer during the placement may come after the replace. The target is then in an unknown state, the audit records `unknown`, and the operator must check the file. If the host cannot be reached for the removal, the error names the temporary file. The reply carries the name, the remote path, the size and the hash. The audit records the two paths, the size, both hashes and the confirmation state. It never records the content (ADR-0017 §26, §38).

A client without elicitation refuses a modifying operation by default, because the confirmation has no channel. The operator can set `WINRIG_CONFIRM_FALLBACK=proceed` to run the operation anyway, and the audit marks the run as done without a confirmation. The relaxation applies only when the client declared no channel. A user refusal, a cancel, a timeout and a transport error are never bypassed (ADR-0013 §19–23, TR-SEC-11).

## Installation

Each release has ready binaries for Linux, macOS and Windows. Each archive has a `sha256` checksum next to it. The Linux binaries use a static link (musl) and they do not need a specific glibc version.

```bash
# Replace the version and the target with your platform.
curl -LO https://github.com/fgbm/winrig/releases/latest/download/winrig-v0.2.0-x86_64-unknown-linux-musl.tar.gz
curl -LO https://github.com/fgbm/winrig/releases/latest/download/winrig-v0.2.0-x86_64-unknown-linux-musl.sha256
sha256sum -c winrig-v0.2.0-x86_64-unknown-linux-musl.sha256
tar xzf winrig-v0.2.0-x86_64-unknown-linux-musl.tar.gz
install -m 0755 winrig ~/.local/bin/winrig
```

The archives have the name `winrig-v<version>-<target>`, where the target is one of `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-apple-darwin`, `aarch64-apple-darwin` or `x86_64-pc-windows-msvc`. On macOS, the `aarch64` archive is for Apple Silicon and the `x86_64` archive is for Intel. Both `tar` and `unzip` work, because the archive holds `LICENSE` and `README.md` next to the binary.

To build from the source, see [Quick start](#quick-start).

## Quick start

Build the project one time:

```bash
cargo build --release
```

Create an encrypted profile. The command reads the password without echo and prints the profile token exactly one time:

```bash
./target/release/winrig setup corp --user 'DOMAIN\user'
```

The command prints the profile token and the JSON definition of the MCP server. Either insert the definition into the client by hand, or let `setup` write it for you. The tool updates the client configuration in place and does not touch other entries:

```bash
./target/release/winrig setup corp --user 'DOMAIN\user' --write-config opencode --scope global
./target/release/winrig setup corp --user 'DOMAIN\user' --write-config claude-code --scope project
```

`--write-config` requires a scope. Pass `--scope global` for the user configuration or `--scope project` for the current repository. Without the flag, `setup` asks in the terminal. In a non-interactive run (a script, CI), `setup` refuses and points to `--scope`.

By default, the server connects only to loopback (`localhost`, `127.0.0.0/8`, `::1`). `--allowed-hosts` sets the hosts that the server can reach: a comma-separated list, an item with a leading `.` is a domain suffix, and `*` is any host. `setup` writes the value into the client entry as `WINRIG_ALLOWED_HOSTS`. A repeated `setup` without the flag removes this variable:

```bash
./target/release/winrig setup corp --user 'DOMAIN\user' --write-config claude-code --scope global --allowed-hosts '.corp.example,web-01'
```

The entry has the same name as the entry that already serves this profile. A repeated `setup` therefore updates it in place and does not add a second entry. This fact is important: two entries for one profile start two processes. The second process loses the profile lock and exits, and the client reports only `MCP error -32000: Connection closed`. When no process serves the profile yet, the name is `winrig`. `--server-name` sets it explicitly.

Supported clients: `opencode`, `claude-code`, `codex`, `cursor`. The project scope finds the nearest parent directory with `.git` (with a fallback to the current directory) and writes to `<root>/opencode.json`, `<root>/.mcp.json`, `<root>/.codex/config.toml` or `<root>/.cursor/mcp.json`. The global scope keeps the user paths. For opencode, the profile token goes into a separate file `0600` and a reference `{file:...}` inserts it. The profile token therefore never sits inside the client configuration. At the project scope, this file lives in `WINRIG_STATE_DIR`, not in the repository. For the other three clients, the profile token goes into the client configuration as a value. At the project scope, the project usually commits such a file, so `setup` prints a warning and `winrig` sets the file mode to `0600` on Unix.

Start the server in one of the two modes:

```bash
# Local stdio process for one client (the profile token comes from the client environment)
WINRIG_TOKEN='<token from setup>' ./target/release/winrig stdio --profile corp

# HTTP service at 127.0.0.1:8005/mcp for several projects
WINRIG_TOKEN='<token from setup>' ./target/release/winrig serve --profile corp

# Override the address from the command line (this value is more important than the environment)
./target/release/winrig serve --profile corp --port 9000 --host 0.0.0.0

# Pass the secrets as arguments instead of the environment (this value is more important than the environment)
./target/release/winrig serve --profile corp --token '<token from setup>'
./target/release/winrig serve --auth-token '<shared secret>'
```

The flags `--token` and `--auth-token` override `WINRIG_TOKEN` and `WINRIG_AUTH_TOKEN`. A secret that goes as an argument is visible in the process list. Therefore prefer the environment or the client configuration, where possible.

The server definition that `setup` prints and writes includes `WINRIG_TOKEN`, `WINRIG_PROFILE_DIR` and `WINRIG_STATE_DIR`. The client therefore finds the profile even with non-standard directories.

To keep the header path instead of the profile, set the shared secret and do without a profile:

```bash
echo "WINRIG_AUTH_TOKEN=$(openssl rand -base64 32)" >> .env
set -a; . ./.env; set +a
./target/release/winrig serve
```

In the HTTP mode, the default bind is `127.0.0.1:8005` and the endpoint is `/mcp`. The server needs at least one secret. It refuses to start if it has neither a profile token nor `WINRIG_AUTH_TOKEN`.

## Profiles

```bash
winrig setup corp --user 'DOMAIN\user'   # create the profile; print the profile token one time
winrig setup corp --user 'DOMAIN\user' --overwrite   # replace the existing profile
winrig list                              # a table: NAME, USER, PATH; no secrets
winrig list --json                       # the same data in JSON
winrig rotate corp                       # re-encrypt with a fresh profile token
winrig forget corp                       # delete the profile (idempotent)
winrig doctor                            # compare the settings of the winrig servers; read-only
```

`doctor` reads the client configurations of every client and of both scopes. It lists each winrig server with the effective values of the known settings: `WINRIG_ALLOWED_HOSTS`, `WINRIG_ALLOW_INSECURE_TLS`, `WINRIG_ALLOW_FILE_WRITE` and the other `WINRIG_*` settings. A setting that is absent shows its default with the marker `(default)`. The command compares the servers and marks every setting on which they disagree. It prints a value only for the known settings; every other variable appears as `set` or `empty`, so no token value is shown. The per-server plumbing (`WINRIG_TOKEN`, `WINRIG_PROFILE_DIR` and the other identity variables) is listed but not compared, because it differs between servers by design. A winrig entry that is not a stdio server, for example an HTTP entry, appears as `not compared` and does not change the exit code. The command writes nothing. It exits with code 0 when the servers agree. It exits with 1 when they disagree, or a configuration file was skipped, or an entry was not parsed. It exits with 2 on a usage error.

The profile file is `corp.json` in the profile directory. It holds the format version, the canonical account name, the HKDF-SHA256 salt, the XChaCha20-Poly1305 nonce and the ciphertext. The account name is bound as associated data. On Unix, the file mode is `0600` inside a directory `0700`. Wider permissions give a warning, not a refusal. The log tells a wrong profile token from a damaged file, but the client gets 401 in both cases. If `WINRIG_AUTH_TOKEN` matches the profile token, the start fails.

An account has the form `DOMAIN\user`, for example `contoso\alice`. The split for NTLM repeats `spnego` (the `requests-ntlm` engine that the Python server used): the system splits the name at the first backslash. A UPN (`user@realm`) or a bare name stays whole with an empty domain. The profile holds the account in the canonical lower case, and the same value goes to the host. NTLM changes the user name to upper case when it builds the hash. The domain case therefore does not change the result.

One process for each profile. A lock file in the profile state directory stops a second process on the same profile. The second process refuses and points to the HTTP mode. Profile changes on disk apply at the next start. The profile password is still subject to the AD account lockout. If the host rejects the password two times in different lockout windows, the profile fails until the process restarts. Run `setup` again.

## Configuration

You configure everything through the environment; there is no configuration file. The profile file is not a configuration, but a ciphertext store (ADR-0009).

| Variable | Default | Purpose |
|----------|---------|---------|
| `WINRIG_AUTH_TOKEN` | — | The shared secret for the header path; a request must present it as `Authorization: Bearer <token>` or `X-MCP-Token`. Not necessary when a profile token is in use |
| `WINRIG_PROFILE` | — | The profile name; omit it when exactly one profile exists, and it is mandatory when several exist |
| `WINRIG_TOKEN` | — | The profile token that `setup` printed; mandatory in the stdio mode and for the profile path in HTTP |
| `WINRIG_PROFILE_DIR` | the OS configuration directory | Overrides the profile directory (`~/.config/winrig` on Linux) |
| `WINRIG_STATE_DIR` | the OS state directory | Overrides the **root** of the state directory; `winrig` adds the profile name, so locks and logs land in `<WINRIG_STATE_DIR>/<profile>` by default. Give the root, not the profile directory, or the lock goes away from the place where the client configuration expects it |
| `WINRIG_BIND_HOST` | `127.0.0.1` | The address that the HTTP server listens on |
| `WINRIG_PORT` | `8005` | The port that the HTTP server listens on |
| `WINRIG_PASSWORD_TTL_SECONDS` | `3600` | How long a cached AD password lives without use. After this time, the server erases the password and closes the user sessions. `0` disables the expiry. On the header path, the cache does not open a session: `connect` needs `X-AD-Password` in each request. In the profile mode, the TTL never causes a repeated prompt |
| `WINRIG_LOG_DIR` | the profile state directory | The directory for `winrig.log` and `winrig-audit.log`. The server creates it `0700` and the files `0600` |
| `WINRIG_LOG_LEVEL` | `INFO` | The server log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`). The level does not change the audit log, which the server always writes |
| `WINRIG_LOG_MAX_BYTES` | `10485760` | The size at which the log file rotates |
| `WINRIG_LOG_BACKUP_COUNT` | `5` | The number of rotated files to keep for each log |
| `WINRIG_AUDIT_MAX_OUTPUT_CHARS` | `2000` | The number of stdout/stderr characters that the server keeps in the audit for each call |
| `WINRIG_AUDIT_LOG_BODY` | `1` | A value of `0`, `false`, `no` or `off` records only the call metadata: no command text and no output |
| `WINRIG_CONFIRM_TIMEOUT_SECONDS` | `300` | How long a modifying tool waits for the confirmation answer before it refuses (fail-closed) |
| `WINRIG_LOCKOUT_ATTEMPTS` | `3` | The number of failed AD password attempts, after which the server does not present the password until the end of the lockout window |
| `WINRIG_LOCKOUT_WINDOW_SECONDS` | `1800` | How many seconds the server does not repeat a rejected password |
| `WINRIG_SECRET_REDACT_MIN_LENGTH` | `4` | The shortest secret that the server removes from the **agent response**. The audit and the log files always remove secrets of any length |
| `WINRIG_ALLOWED_HOSTS` | *(empty)* | The host allowlist, comma-separated. An empty value permits only the loopback literals: `localhost`, `127.0.0.0/8`, `::1`; the server does not resolve DNS. A separate item `*` permits any host. Other entries are an exact host name or IP (case-insensitive), or a suffix if the entry starts with `.`. A wrong item (for example `*.corp.example`) makes the start fail. The server rejects a host with a port, a path or `@` in `connect` with any list. `setup --allowed-hosts` writes the value into the client entry |
| `WINRIG_ALLOW_INSECURE_TLS` | `false` | Whether the server accepts `verify_cert=false`. By default it rejects such a call before any network activity; `true` permits self-signed certificates |
| `WINRIG_ALLOW_FILE_WRITE` | `false` | Whether the tool `write_file` exists. While the value is `false`, the server removes the tool from the router: it does not declare the tool and no call reaches it |
| `WINRIG_MAX_WRITE_BYTES` | `65536` | The largest content that `write_file` and the uploaded `run_script` script accept, in bytes. The server rejects it before any network activity. The value cannot be smaller than one 1536-byte chunk |
| `WINRIG_WRITE_ALLOW_PATHS` | *(empty)* | The operator allowlist of write paths, comma-separated. An entry lifts the protected-path refusal for `write_file`, `delete_file`, `copy_file` (target), `move_file` (target and source), `rename_file` (path and destination) and `create_directory`. The match is a prefix at a path-component boundary on the normalized and case-folded resolved path, and it checks both path resolutions. A system directory, a volume root and a share root are lawful entries; the confirmation then warns for the class. An entry must be an absolute drive or `\\server\share` directory, with no wildcard, 8.3 component or `..`. A file operation needs a strict descendant; only a volume root or a share root covers itself. An 8.3 component and a symbolic link or a junction stay refused, while any other reparse point stays writable. `delete_directory` does not consult the list. A bad entry makes the start fail |
| `WINRIG_ALLOW_COMMAND_EXEC` | `false` | Whether the tool `run_command` exists. While the value is `false`, the server removes the tool from the router: it does not declare the tool and no call reaches it |
| `WINRIG_ALLOW_SCRIPT_EXEC` | `false` | Whether the tool `run_script` exists. While the value is `false`, the server removes the tool from the router: it does not declare the tool and no call reaches it |
| `WINRIG_ALLOW_FILE_OPS` | `false` | Whether the tools `copy_file`, `move_file`, `rename_file` and `create_directory` exist. While the value is `false`, the server removes the tools from the router: it does not declare them and no call reaches them |
| `WINRIG_ALLOW_FILE_DOWNLOAD` | `false` | Whether the tool `download_file` exists. While the value is `false`, the server removes the tool from the router: it does not declare the tool and no call reaches it |
| `WINRIG_ALLOW_FILE_UPLOAD` | `false` | Whether the tool `upload_file` exists. While the value is `false`, the server removes the tool from the router: it does not declare the tool and no call reaches it |
| `WINRIG_TRANSFER_DIR` | *(state directory)* | The local endpoint of the file transfer. By default it is the `transfer` subdirectory of the profile state directory. The value must be an absolute path; a relative value makes the start fail. The directory and its files use the private modes (`0700`/`0600`). In HTTP mode the server adds one subdirectory per user (DR-3) |
| `WINRIG_MAX_TRANSFER_BYTES` | `268435456` | The largest file that `download_file` or `upload_file` accepts, in bytes (256 MiB). The server refuses a larger file before the read |
| `WINRIG_ALLOWED_COMMANDS` | *(empty)* | The command allowlist, comma-separated. An empty value admits any command. A non-empty value admits only a command that begins with one entry, matched without case after a trim. A prefix is not a boundary: a leading `&`, `.`, `powershell -c`, an alias and a script started by path all go around it. A bad entry refuses the start |
| `WINRIG_CONFIRM_FALLBACK` | `refuse` | What a modifying tool does when the client declared no elicitation channel. `refuse` is fail-closed. `proceed` runs the operation and marks the run in the audit. A user refusal, a cancel, a timeout and a transport error are never bypassed |
| `WINRIG_SFTP_CRED_TTL_SECONDS` | `3600` | Reserved for the SFTP tools (not ported yet); the server parses and checks it at start |

### Transport security

`winrig` serves open HTTP on `/mcp`; the binary has no TLS listener. **The bearer token is now a key: anyone who intercepts it reaches the server and decrypts the AD password.** Do not bind to a non-loopback address without a TLS-terminating reverse proxy in front (nginx, Caddy or ingress). The default address is `127.0.0.1` for this reason. A multi-user deployment assumes that the proxy authenticates the clients. The proxy passes the headers `Authorization`, `X-AD-User` and `X-AD-Password` without changes. The remote WinRM leg is separate: use `use_ssl` / port 5986 when the hop to the Windows host needs encryption. Do not enable `WINRIG_ALLOW_INSECURE_TLS=true` unless the self-signed certificate is intentional. The host allowlist permits only loopback by default. Otherwise an agent could receive an instruction from data. The agent could connect to the host of an attacker and give the attacker the NTLMv2 response of the domain account.

Over open HTTP, the encryption of this WinRM leg is only partial. `winrm-rs` seals the SOAP bodies with the NTLM session key, but the key does not exist until the handshake completes. The **first** request on each new connection therefore carries its body in clear text next to the Type 3 message. The server seals only the later requests on this keep-alive connection. For `winrig`, the first body is a shell `Create`, not a script. But if a host answers an unencrypted message with an empty `HTTP 500` (`AllowUnencrypted=false`, the Windows default), it rejects this first request immediately. Port 5986 removes both the exposure and the refusal.

## Client setup

There are two request forms. With a **profile token**, the secret is the profile token and the identity comes from the profile, so the request does not need `X-AD-User`. With a **shared secret**, the request must carry `WINRIG_AUTH_TOKEN` and `X-AD-User`. The server checks the token before it trusts `X-AD-User`, because this header is the key of the password and session cache in memory.

`WINRIG_AUTH_TOKEN` is mandatory only on the header path. `X-AD-Password` is optional at the HTTP level, but on the header path it is mandatory for each `connect`. A cached password does not open a session for a name alone, because any holder of the shared secret can name `X-AD-User`. An open session runs commands without a repeated password until the server closes it (ADR-0015). The password comes in a header, not in a dialog: `winrig` does not ask for passwords through elicitation. The MCP specification excludes secrets from elicitation, and the protocol revision `2026-07-28` removes elicitation completely (see `docs/adr/0006-password-header-and-confirmation.md`).

The paths below are the user paths that `--scope global` writes. With `--scope project`, the same entry goes into the project file that [Quick start](#quick-start) lists.

### opencode (`~/.config/opencode/opencode.json`)

`setup --write-config opencode --scope global` writes this file. The profile token comes from a private file:

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

`setup --write-config claude-code --scope global` writes the block `mcpServers` of the file `~/.claude.json`. The equivalent through the CLI:

```bash
claude mcp add winrig -- /path/to/winrig stdio --profile corp
```

### Codex (`~/.codex/config.toml`)

`setup --write-config codex --scope global` writes it:

```toml
[mcp_servers.winrig]
command = "/path/to/winrig"
args = ["stdio", "--profile", "corp"]

[mcp_servers.winrig.env]
WINRIG_TOKEN = "<token from setup>"
```

### Cursor (`~/.cursor/mcp.json`)

`setup --write-config cursor --scope global` writes the block `mcpServers`. The HTTP form works the same for any client: point the client at the streamable-HTTP endpoint and pass `Authorization: Bearer <token>`.

Any other MCP client works the same way. Either use the stdio definition that `setup` printed, or point the client at the HTTP endpoint. Use the profile token as the bearer.

### Confirmation on clients without elicitation

The modifying tools get confirmation through MCP elicitation. They **fail closed** when the client cannot ask. opencode 1.18.31 declares only `roots`. The modifying tools therefore refuse to work there and say so, rather than act without confirmation. The read-only tools work normally. The project tracks a replacement channel (`input_required`, SEP-2322) in `docs/ROADMAP.md` and `docs/QUESTIONS.md` Q-10.

`WINRIG_CONFIRM_FALLBACK=proceed` changes this. The setting lets a modifying operation run when the client declared no elicitation channel. The audit marks the run as done without a confirmation. It removes fail-closed from every modifying tool at once, deletion included. In clients that use their own permission system, the permission replaces the confirmation. With `permission: "*": "allow"` nobody confirms. The combination `proceed` + `WINRIG_ALLOW_COMMAND_EXEC=true` + an empty `WINRIG_ALLOWED_COMMANDS` + a client permission of `allow` runs arbitrary commands. No person takes part in that run. None of the four settings is on by default (ADR-0013 §23, Consequences). In HTTP mode the setting applies to every client that lacks elicitation, because winrig decides by the declared capabilities of each request.

## Logging

`WINRIG_LOG_DIR` holds `winrig.log` and the audit log `winrig-audit.log`. The server creates the directory `0700` and the files `0600`, and applies the permissions again at each rotation.

The audit log records each call with the PowerShell text and an extract of its output. This output can hold file content, registry data, account lists and certificates. The audit log therefore records only the first `WINRIG_AUDIT_MAX_OUTPUT_CHARS` characters by default. The agent still receives the full answer. Set `WINRIG_AUDIT_LOG_BODY=0` to record only the call metadata. A policy refusal before any access to the host goes into a separate `POLICY REFUSED` record. The record holds the user, the tool, the code and the reason. Forbidden hosts, ports and TLS, a `connect` without `X-AD-Password` and protected paths are examples. A write that the operator allowlist `WINRIG_WRITE_ALLOW_PATHS` permitted into a protected location goes into a separate `WRITE ALLOWED BY ALLOWLIST` record that names the entry that permitted it (ADR-0017 §39).

In the stdio mode, stdout carries only JSON-RPC. The server log and the audit log go to stderr and to the profile state directory. A client that starts `winrig stdio` therefore never sees log lines mixed into the protocol.

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo deny check
cargo build --release
```

The pinned toolchain is in `rust-toolchain.toml`. CI runs the same commands plus `cargo-audit` and a build on the MSRV (`rust-version` in `Cargo.toml`). The development environment has no live Windows host. The tests run on a fake `WinRmTransport` that records the commands it receives, and they do not touch the network. `tests/http_gate.rs` checks the real axum+rmcp `/mcp` wiring, and `tests/stdio_mode.rs` starts the real binary over stdio. The project canon, the requirements, the ADRs and the review cycle live in `AGENTS.md` and `docs/`.

### Releases

A release works like this: raise `version` in `Cargo.toml`, add the matching entry to `CHANGELOG.md` and push the tag `vX.Y.Z`. The tag starts `.github/workflows/release.yml`. GitHub builds the Release from the changelog entry. The workflow builds the binary for five targets and attaches it with a `sha256` checksum. The workflow fails if the tag and the version in `Cargo.toml` disagree.

| Workflow | Trigger | What it does |
|----------|---------|--------------|
| `ci.yml` | each push and pull request | `fmt`, `clippy`, `test`, a release build, an MSRV build, `cargo-audit`, `cargo-deny` |
| `release.yml` | the tag `vX.Y.Z` | writes the GitHub Release and uploads the platform archives with checksums |

## License

MIT — see [LICENSE](LICENSE).
