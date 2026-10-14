---
title: Tools
description: The read-only tools and the modifying tools of winrig, with the switches that enable the modifying tools.
---

The binary declares 43 tools, plus `write_file`, `run_command`, `run_script`, the file operations `copy_file`, `move_file`, `rename_file` and `create_directory`, `download_file` and `upload_file` when the operator enables them. The read-only tools need no confirmation. The modifying tools require the explicit confirmation of the operator (DR-5).

## Session

| Tool | Description |
|------|-------------|
| `connect` | Open a WinRM session to a Windows host and return a `session_id` (HTTP 5985 or HTTPS 5986 through `use_ssl`) |
| `disconnect` | Close the active WinRM session |
| `list_sessions` | List the active WinRM sessions with usage details |

## Read-only tools

### File system

| Tool | Description |
|------|-------------|
| `list_directory` | List the files and directories at a path |
| `find_files` | Find files recursively by a pattern |
| `read_file` | Read the content of a file with line numbers. The tail mode can drop the lines that contain a literal text |
| `search_file_content` | Search text in a file or a directory, like grep. The tool can return the last matches, count the matches, and filter the lines by the timestamp at the start |
| `file_info` | The metadata of a file or a directory in JSON |
| `compare_files` | A line-by-line diff of two files |

### System diagnostic

| Tool | Description |
|------|-------------|
| `get_event_log` | The Windows event log: crashes, service failures, authentication errors |
| `list_event_logs` | The event log channels with the record count and the enabled state |
| `get_services` | A summary of the services, or the full details of each service in JSON |
| `get_service_config` | One service: the start type, the account, the binary path and the recovery actions. The start type is Automatic, AutomaticDelayed, Manual or Disabled. The recovery actions hold the action, the delay and the reset period |
| `list_processes` | The processes with a sort by CPU, memory or handles |
| `get_open_handles` | The processes that hold a file open, with the PID, the name and the start time. It uses the Restart Manager, so no Sysinternals `handle.exe` is needed |
| `get_printers` | The printers with the share name, the driver, the port, the port host and number, the state as the PrinterStatus name and the job count |
| `get_print_jobs` | The print jobs of one printer. The document name and the owner stay hidden unless `include_personal_data` is true |
| `get_system_info` | The OS version, uptime, RAM, CPU count, domain, time zone |
| `get_disk_space` | The free space on all fixed disks |
| `get_perf_snapshot` | A snapshot of CPU, memory, disk I/O and network, independent of the locale |
| `get_registry` | Read a registry key or value and, on request, the child key names (read only) |
| `get_certificates` | The certificates in the personal store, sorted by the days to expiry |
| `get_network_config` | IP, gateway and DNS for each network adapter |
| `test_network` | An ICMP ping or a TCP port check from the host |

### Identity and configuration

| Tool | Description |
|------|-------------|
| `get_environment_variables` | The environment variables by scope |
| `get_scheduled_tasks` | The scheduled tasks with the last/next run and the result |
| `get_local_users` | The local accounts with the status and the last logon |
| `get_user_groups` | The membership in local groups |
| `get_security_context` | The identity of the current session, the groups, the privileges |
| `get_permissions` | The ACL entries for files and directories |

### Network and software

| Tool | Description |
|------|-------------|
| `get_tcp_connections` | The active TCP connections, filtered by state, port, PID or process name, with an optional grouped summary |
| `get_dns_cache` | The local DNS client cache |
| `get_installed_software` | The installed software from the 64-bit and 32-bit uninstall keys |
| `resolve_dns_name` | The DNS resolution chain from the host |

## Active Directory — decided, but not built

The binary has none of these tools today. This section records a decision ([ADR-0014](https://github.com/fgbm/winrig/blob/main/docs/adr/0014-active-directory.md), slices W19–W21), not a capability. An agent that sees WinRM and a host in the domain assumes that the directory is available, but it is not.

The tools are read only and use `System.DirectoryServices`, not RSAT cmdlets:

| Tool | Description |
|------|-------------|
| `get_ad_object` | One user, group or computer: the account state, the password dates, the last logon, the DN, the OU |
| `get_ad_membership` | The membership in both directions, nested when necessary |
| `find_ad_objects` | A search by name or `sAMAccountName` with a result cap |
| `get_ad_domain_info` | The domain, the forest, the functional levels, the FSMO roles, the controllers, the trusts, the sites, the password policy and the PSO |
| `get_ad_health` | The replication partners and the lag, the NTDS/DNS/ADWS/W32Time services, the SYSVOL state |
| `get_ad_stale_objects` | The stale users and computers by `lastLogonTimestamp` and `pwdLastSet` |

The directory write (slices W20–W21) stays intentionally outside the first wave. It will be off by default behind `WINRIG_ALLOW_AD_WRITE`. The current binary does not read that variable.

## Modifying tools

These tools change the host and they require confirmation.

Each confirmation names the host of the session, the user of the request and the tool. It names the target and the operation with the details that are available before the call. It holds one plain line that states the effect. The line states whether the operator can undo it. A hidden value appears only as `hidden`: the old and new values of `set_registry` and the content of `write_file` are hidden values. The text of a command and the text of a script appear in full, without the 200-character cap, because the operator confirms what will run. `kill_process` does not read the command line at all. The server sanitizes each field and caps the other fields at 200 characters. A cut path keeps its tail, and a cut field carries the marker `...` inside the cap. The text is English and does not depend on the language of the host.

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
| `download_file` | Copy a file from the host into the local transfer directory. **Off by default**: set `WINRIG_ALLOW_FILE_DOWNLOAD=true`, or the server does not declare the tool and no call can reach it. The tool reads the file on the host in windows of 16 MiB and writes it into `WINRIG_TRANSFER_DIR`, and it confirms the SHA-256 of both sides. The reply carries the name, the size and the hash, not the content. Every download needs a confirmation (ADR-0017 §21–28) |
| `upload_file` | Copy a file from the local transfer directory to the host. **Off by default**: set `WINRIG_ALLOW_FILE_UPLOAD=true`, or the server does not declare the tool and no call can reach it. The tool hashes the local file and shows the SHA-256 in the confirmation. It sends the bytes in windows of 4 MiB into a temporary file. Each window goes through the standard input of a host command. The host hashes that file before the rename. The target obeys `WINRIG_WRITE_ALLOW_PATHS`, and an existing target needs `overwrite`. Every upload needs a confirmation (ADR-0017 §26) |

## Switches that enable the modifying tools

| Switch | Effect |
|--------|--------|
| `WINRIG_ALLOW_FILE_WRITE=true` | Declares the tool `write_file`. While the value is `false`, the server removes the tool from the router |
| `WINRIG_MAX_WRITE_BYTES` | The largest content that `write_file` and the uploaded `run_script` script accept, in bytes (64 KiB by default) |
| `WINRIG_WRITE_ALLOW_PATHS` | The operator allowlist of write paths, comma-separated. An entry lifts the protected-path refusal for `write_file`, `delete_file`, `copy_file` (target), `move_file` (target and source), `rename_file` (path and destination) and `create_directory`. The confirmation then warns for a system directory, a volume root or a share root. An 8.3 component and a symbolic link or a junction stay refused (ADR-0017 §7–13) |
| `WINRIG_ALLOW_COMMAND_EXEC=true` | Declares the tool `run_command`. While the value is `false`, the server removes the tool from the router |
| `WINRIG_ALLOW_SCRIPT_EXEC=true` | Declares the tool `run_script`. While the value is `false`, the server removes the tool from the router |
| `WINRIG_ALLOW_FILE_OPS=true` | Declares the tools `copy_file`, `move_file`, `rename_file` and `create_directory`. While the value is `false`, the server removes them from the router |
| `WINRIG_ALLOW_FILE_DOWNLOAD=true` | Declares the tool `download_file`. While the value is `false`, the server removes the tool from the router |
| `WINRIG_ALLOW_FILE_UPLOAD=true` | Declares the tool `upload_file`. While the value is `false`, the server removes the tool from the router |
| `WINRIG_TRANSFER_DIR` | The local endpoint of the file transfer (the transfer subdirectory of the state directory by default). Must be an absolute path. In HTTP mode the server adds one subdirectory per user (DR-3) |
| `WINRIG_MAX_TRANSFER_BYTES` | The largest file that `download_file` or `upload_file` accepts, in bytes (256 MiB by default) |
| `WINRIG_ALLOWED_COMMANDS` | The command allowlist, comma-separated. An empty value admits any command. A prefix is not a boundary (ADR-0013 §18) |
| `WINRIG_CONFIRM_FALLBACK` | `refuse` (default) or `proceed`. With `proceed` a client without elicitation runs a modifying operation, and the audit marks the run (TR-SEC-11) |
| `WINRIG_ALLOW_INSECURE_TLS=true` | Permits `verify_cert=false` on `connect`. By default the server rejects it |

`run_command` runs one PowerShell command that the operator confirms. The server encodes the command text as a base64 UTF-16 string. It decodes the string into a script block, so the text cannot break out of the generated wrapper. The command must fit one WinRS command line, so the text holds at most 979 characters. `WINRIG_ALLOWED_COMMANDS` is a prefix list, matched without case after a trim. An empty list admits any command. The list is not a boundary. A leading `&`, `.`, `powershell -c`, an alias, a call operator and an encoded command all go around it. Any text after an allowed prefix runs. So `;`, a newline, `|` and `$(...)` do not return control to the list. An entry of `&` or `.` alone admits every command. A script written with `write_file` and then started also goes around it. With `run_command` on and an empty list, the path protection of the other tools stops being a guarantee of the product (ADR-0013 §18).

`run_script` runs a PowerShell script that is longer than one WinRS command line. It is off by default (`WINRIG_ALLOW_SCRIPT_EXEC`). The server writes the script into a temporary `.ps1` in the session temp directory in chunks. It reads the file and runs its text as a script block, then tries to delete the file. The script has no `$PSScriptRoot`, no `$PSCommandPath` and no arguments. The tool shows the SHA-256 of the script in the confirmation and records it in the audit, and it verifies the hash before the run. One confirmation covers the whole operation and shows the whole script, line by line and without the 200-character cap. `WINRIG_ALLOWED_COMMANDS` does not filter a script, because the server cannot prefix-check the text of a script in a meaningful way; the confirmation states this. The script obeys `WINRIG_MAX_WRITE_BYTES`, and the output obeys the same limits as `run_command`. The result carries `temp_file` with the cleanup outcome, and a `warning` when the temporary file may remain. The tool can fail if the script produces no output for 60 seconds (ADR-0017 §29–34).

`copy_file`, `move_file`, `rename_file` and `create_directory` are off by default (`WINRIG_ALLOW_FILE_OPS`). `copy_file` copies a file or a directory. A directory copy is recursive, and the confirmation shows the file, directory and byte counts. The copy walks the source tree once and refuses it when it holds a symbolic link or a junction. The command repeats the check at run time. `move_file` renames the object on one volume. Across volumes it copies a file, verifies the size and then deletes the source. It refuses a cross-volume move of a directory, because the implied recursive delete falls under DR-6. `rename_file` changes the last component in the same directory, and it takes one new name. A separator, a reserved device name (`CON`, `NUL`, `COM1`, ...) and a trailing dot or space are refused. `create_directory` creates the final directory and each missing parent. The confirmation shows the number of created levels and the shallowest created level, which also passes the write boundary. The target of each tool obeys the allowlist `WINRIG_WRITE_ALLOW_PATHS`. The source of a copy is read-only, so it may lie under a system directory. None of the four replaces an existing directory, and an existing target needs `overwrite` (except `create_directory`, which refuses it). The tools reach the host with the `[IO.File]` and `[IO.Directory]` classes, so a wildcard in a path cannot expand. A partial copy or move is an error, never a success. A long copy or move can fail if it produces no output for 60 seconds. A read-only target or source fails the operation with a clear error, because the tool has no `-Force` and never clears the read-only attribute. An overwrite keeps the replaced file's access control list and attributes. `write_file` also uses the host-resolved .NET path for its chunks.

`download_file` is off by default. Set `WINRIG_ALLOW_FILE_DOWNLOAD=true` to declare it. It reads a file on the host and writes it into the local transfer directory. First the tool reads the size and the modification time of the source. It refuses a file above `WINRIG_MAX_TRANSFER_BYTES` (256 MiB by default) before any read. The confirmation shows the resolved remote path, the size, the modification time and the local destination. It shows no hash, because the hash is not known before the read. The tool then reads the file in windows of 16 MiB through a raw channel, as base64 lines of 1 MiB. The output is continuous, so a large file does not time out, and the whole file never loads into the host memory. The host reads with a shared read and delete, so a file that another process holds open still copies. The tool hashes the bytes while it reads them. After the last window, one more host pass hashes exactly the scanned length and compares the two digests. A mismatch or a short file is a refusal with the text "the source changed during the transfer". The tool writes the windows into a temporary file next to the target. A failure or a cancel removes that file, so no partial file remains. The reply carries the name, the size and the hash. The content never goes inline into the result. The local endpoint is `WINRIG_TRANSFER_DIR`, the transfer subdirectory of the state directory by default. In HTTP mode the server isolates each user in a subdirectory of its canonical identity (DR-3). The directory and its files use the private modes (`0700`/`0600`). The tool takes one plain local file name. It refuses a separator, a `..` component, a leading dot, a reserved device name, a symbolic link and a control or format character. An existing local file needs `overwrite`. A source that is a directory, a symbolic link or a junction is refused. A source under a system directory is allowed, and the confirmation warns for it. Every download needs a confirmation, because it moves data off the host. The audit records the resolved paths, the size, both hashes and the confirmation state, never the content (ADR-0017 §21–28).

`upload_file` is off by default. Set `WINRIG_ALLOW_FILE_UPLOAD=true` to declare it. It copies a file from the local transfer directory to the host. The tool takes one plain local file name and the absolute remote path. It reads only from the directory of the request user (DR-3). It refuses a symbolic link, an item that is not a regular file and a file that another user can write. On Unix it also refuses a file with more than one hard link. On Windows the tool cannot see a hard link, so keep the transfer directory private. It refuses a file above `WINRIG_MAX_TRANSFER_BYTES` (256 MiB by default) before the read. The tool hashes the local file once. The confirmation shows the local source, the resolved remote path, the size, the SHA-256, the overwrite state and the effect. The remote target obeys the boundary of `write_file`. A protected path is refused unless `WINRIG_WRITE_ALLOW_PATHS` covers it, and then the confirmation warns. An existing target needs `overwrite`. After the confirmation, the tool sends the file in windows of 4 MiB. Each window is one host command, and the bytes arrive on its standard input, not in the command text. Therefore the WinRS command line limit of about 8191 characters does not limit the size of a window. The first window creates a temporary file next to the target and refuses an existing file. Each later window must find the temporary file at the expected length. The tool hashes the bytes again while it sends them. It stops when the digest differs from the confirmed one, for example when the local file changed after the confirmation. The last host command hashes the temporary file and compares the digest with the confirmed one. It then checks the target and every parent directory for a symbolic link or a junction. Then it places the file by a rename (an atomic replace with `overwrite`). A mismatch or a failure before the placement removes the temporary file and leaves the target unchanged. A cancel stops the host command and removes the temporary file. A cancel or a lost answer during the placement may come after the replace. The target is then in an unknown state, the audit records `unknown`, and the operator must check the file. If the host cannot be reached for the removal, the error names the temporary file. The reply carries the name, the remote path, the size and the hash. The audit records the two paths, the size, both hashes and the confirmation state. It never records the content (ADR-0017 §26, §38).

:::danger
`delete_file`, `delete_directory`, `write_file` and the file operations reject protected paths and reparse points. Do not call them on a volume root or a system directory. Data loss can occur. The allowlist `WINRIG_WRITE_ALLOW_PATHS` lifts the refusal for `write_file`, `delete_file` and the target of a file operation when an entry covers it. A copy only reads its source, so a source under a system directory is allowed. The confirmation then warns for a system directory, a volume root or a share root. The entry never lifts an 8.3 component or a symbolic link or a junction. `run_command` and `run_script` have no path protection at all: one command or script can delete or rewrite anything the account can reach.
:::

:::note
The Active Directory modifying tools are not built. The variable `WINRIG_ALLOW_AD_WRITE` does nothing in the current binary.
:::
