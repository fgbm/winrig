---
title: Configuration
description: The complete table of the WINRIG_* environment variables, grouped by topic, with the default of each one.
---

You configure everything through the environment; there is no configuration file. The profile file is not a configuration, but a ciphertext store ([ADR-0009](https://github.com/fgbm/winrig/blob/main/docs/adr/0009-profile-cli-and-stdio.md)).

A value with the wrong format stops the start with a message that names the variable and the expected format (DR-8). An old variable name from the notation before `WINRIG_*` stops the start and names the new name ([ADR-0010](https://github.com/fgbm/winrig/blob/main/docs/adr/0010-environment-variable-naming.md)).

## Secrets and identity

| Variable | Default | Purpose |
|----------|---------|---------|
| `WINRIG_AUTH_TOKEN` | — | The shared secret for the header path; a request must present it as `Authorization: Bearer <token>` or `X-MCP-Token`. Not necessary when a profile token is in use |
| `WINRIG_PROFILE` | — | The profile name; omit it when exactly one profile exists, and it is mandatory when several exist |
| `WINRIG_TOKEN` | — | The profile token that `setup` printed; mandatory in the stdio mode and for the profile path in HTTP |

## Profile and state directories

| Variable | Default | Purpose |
|----------|---------|---------|
| `WINRIG_PROFILE_DIR` | the OS configuration directory | Overrides the profile directory (`~/.config/winrig` on Linux) |
| `WINRIG_STATE_DIR` | the OS state directory | Overrides the **root** of the state directory; `winrig` adds the profile name, so locks and logs land in `<WINRIG_STATE_DIR>/<profile>` by default. Give the root, not the profile directory, or the lock goes away from the place where the client configuration expects it |
| `WINRIG_LOG_DIR` | the profile state directory | The directory for `winrig.log` and `winrig-audit.log`. The server creates it `0700` and the files `0600` |

## HTTP server

| Variable | Default | Purpose |
|----------|---------|---------|
| `WINRIG_BIND_HOST` | `127.0.0.1` | The address that the HTTP server listens on |
| `WINRIG_PORT` | `8005` | The port that the HTTP server listens on |

## Password cache and lockout

| Variable | Default | Purpose |
|----------|---------|---------|
| `WINRIG_PASSWORD_TTL_SECONDS` | `3600` | How long a cached AD password lives without use. After this time, the server erases the password and closes the user sessions. `0` disables the expiry. On the header path, the cache does not open a session: `connect` needs `X-AD-Password` in each request. In the profile mode, the TTL never causes a repeated prompt |
| `WINRIG_LOCKOUT_ATTEMPTS` | `3` | The number of failed AD password attempts, after which the server does not present the password until the end of the lockout window |
| `WINRIG_LOCKOUT_WINDOW_SECONDS` | `1800` | How many seconds the server does not repeat a rejected password |

## Logging and audit

| Variable | Default | Purpose |
|----------|---------|---------|
| `WINRIG_LOG_LEVEL` | `INFO` | The server log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`). The level does not change the audit log, which the server always writes |
| `WINRIG_LOG_MAX_BYTES` | `10485760` | The size at which the log file rotates |
| `WINRIG_LOG_BACKUP_COUNT` | `5` | The number of rotated files to keep for each log |
| `WINRIG_AUDIT_MAX_OUTPUT_CHARS` | `2000` | The number of stdout/stderr characters that the server keeps in the audit for each call |
| `WINRIG_AUDIT_LOG_BODY` | `1` | A value of `0`, `false`, `no` or `off` records only the call metadata: no command text and no output |

## Confirmation and redaction

| Variable | Default | Purpose |
|----------|---------|---------|
| `WINRIG_CONFIRM_TIMEOUT_SECONDS` | `300` | How long a modifying tool waits for the confirmation answer before it refuses (fail-closed) |
| `WINRIG_SECRET_REDACT_MIN_LENGTH` | `4` | The shortest secret that the server removes from the **agent response**. The audit and the log files always remove secrets of any length |

## Host allowlist and TLS

| Variable | Default | Purpose |
|----------|---------|---------|
| `WINRIG_ALLOWED_HOSTS` | *(empty)* | The host allowlist, comma-separated. An empty value permits only the loopback literals: `localhost`, `127.0.0.0/8`, `::1`; the server does not resolve DNS. A separate item `*` permits any host. Other entries are an exact host name or IP (case-insensitive), or a suffix if the entry starts with `.`. A wrong item (for example `*.corp.example`) makes the start fail. The server rejects a host with a port, a path or `@` in `connect` with any list. `setup --allowed-hosts` writes the value into the client entry |
| `WINRIG_ALLOW_INSECURE_TLS` | `false` | Whether the server accepts `verify_cert=false`. By default it rejects such a call before any network activity; `true` permits self-signed certificates |

## File write

| Variable | Default | Purpose |
|----------|---------|---------|
| `WINRIG_ALLOW_FILE_WRITE` | `false` | Whether the tool `write_file` exists. While the value is `false`, the server removes the tool from the router: it does not declare the tool and no call reaches it |
| `WINRIG_MAX_WRITE_BYTES` | `65536` | The largest content that `write_file` accepts, in bytes. The server rejects it before any network activity. The value cannot be smaller than one 1536-byte chunk. The tool also refuses a path so long that its commands would not fit the WinRS command line of about 8191 characters. The limit is about 760 characters for UTF-8 and about 460 characters for the other encodings, for a path with no quote character |

## Reserved

| Variable | Default | Purpose |
|----------|---------|---------|
| `WINRIG_SFTP_CRED_TTL_SECONDS` | `3600` | Reserved for the SFTP tools (not ported yet); the server parses and checks it at start |

:::note
The Active Directory write variables (`WINRIG_ALLOW_AD_WRITE`, `WINRIG_AD_WRITABLE_ATTRIBUTES`) are decided but not built. The current binary does not read them ([ADR-0014](https://github.com/fgbm/winrig/blob/main/docs/adr/0014-active-directory.md)).
:::

See the [transport security](/winrig/security/model/) notes before you bind to a non-loopback address.
