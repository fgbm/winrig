---
title: Tools
description: The read-only tools and the modifying tools of winrig, with the switches that enable the modifying tools.
---

The binary declares 41 tools, plus `write_file` when the operator enables it. The read-only tools need no confirmation. The modifying tools require the explicit confirmation of the operator (DR-5).

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
| `read_file` | Read the content of a file with line numbers |
| `search_file_content` | Search text in a file or a directory, like grep |
| `file_info` | The metadata of a file or a directory in JSON |
| `compare_files` | A line-by-line diff of two files |

### System diagnostic

| Tool | Description |
|------|-------------|
| `get_event_log` | The Windows event log: crashes, service failures, authentication errors |
| `list_event_logs` | The event log channels with the record count and the enabled state |
| `get_services` | A summary of the services, or the full details of each service in JSON |
| `list_processes` | The processes with a sort by CPU, memory or handles |
| `get_open_handles` | The processes that hold a file open, with the PID, the name and the start time. It uses the Restart Manager, so no Sysinternals `handle.exe` is needed |
| `get_printers` | The printers with the share name, the driver, the port, the port host and number, the state as decoded flags and the job count |
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

| Tool | Description |
|------|-------------|
| `restart_service` / `stop_service` / `start_service` | Manage the services with the state before and after |
| `kill_process` | Kill a process by PID |
| `set_registry` | Write a registry value and show the old value and the new value |
| `delete_file` / `delete_directory` | Delete with a confirmation prompt; the tool rejects protected paths, including by the actual location of the system on the host |
| `flush_dns` | Clear the DNS client cache |
| `write_file` | Write a file with a full replacement. **Off by default**: set `WINRIG_ALLOW_FILE_WRITE=true`, or the server does not declare the tool and no call can reach it |

## Switches that enable the modifying tools

| Switch | Effect |
|--------|--------|
| `WINRIG_ALLOW_FILE_WRITE=true` | Declares the tool `write_file`. While the value is `false`, the server removes the tool from the router |
| `WINRIG_MAX_WRITE_BYTES` | The largest content that `write_file` accepts, in bytes (64 KiB by default) |
| `WINRIG_ALLOW_INSECURE_TLS=true` | Permits `verify_cert=false` on `connect`. By default the server rejects it |

:::danger
`delete_file`, `delete_directory` and `write_file` reject protected paths and reparse points. Do not call them on a volume root or a system directory. Data loss can occur.
:::

:::note
The Active Directory modifying tools are not built. The variable `WINRIG_ALLOW_AD_WRITE` does nothing in the current binary.
:::
