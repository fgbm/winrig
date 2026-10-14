---
title: Security model
description: How winrig authenticates each request, keeps secrets in memory, and protects destructive operations.
---

winrig administers Windows hosts over WinRM and keeps the AD password in memory. A bearer token is a key that at the same time gives access to the server and decrypts the AD password. This page describes the protections that the server applies.

## Authentication before trust

Each request must present one of the two secrets. The shared `WINRIG_AUTH_TOKEN` uses the header path and requires `X-AD-User`. The profile token decrypts the profile file. A match of `WINRIG_AUTH_TOKEN` with the profile token stops the start. The server does not start without at least one secret ([ADR-0001](https://github.com/fgbm/winrig/blob/main/docs/adr/0001-shared-secret-and-request-identity.md)).

## Identity on each request

In HTTP, the secret of the current request defines the user in whose name a tool runs. The profile token gives the identity of the profile and makes the server ignore `X-AD-*`. The shared secret requires `X-AD-User`. The identity is not inherited from the task that made the MCP session. In stdio the identity equals the profile of the process.

The server checks the token before it trusts `X-AD-User`, because this header is the key of the password and session cache in memory. The password cache and the session cache are isolated by user ([ADR-0001](https://github.com/fgbm/winrig/blob/main/docs/adr/0001-shared-secret-and-request-identity.md)).

## Secrets stay in memory only

Passwords and passphrases do not go to the logs, the audit, the configuration and they do not go to a commit. Only the authenticated ciphertext of the profile is on the disk, and the key is absent on the server. A secret that a command carries must not appear in the audit in any form ([ADR-0002](https://github.com/fgbm/winrig/blob/main/docs/adr/0002-secrets-confirmation-deletion.md), [ADR-0008](https://github.com/fgbm/winrig/blob/main/docs/adr/0008-injection-redaction-delete-and-confirmation.md)).

The profile file is `corp.json` in the profile directory. It holds the format version, the canonical account name, the HKDF-SHA256 salt, the XChaCha20-Poly1305 nonce and the ciphertext. The account name is bound as associated data. On Unix, the file mode is `0600` inside a directory `0700`.

## Confirmation, fail-closed

Each modifying operation requires the explicit confirmation of the operator; without a confirmation channel the operation does not run. The modifying tools get confirmation through MCP elicitation, and they fail closed when the client cannot ask ([ADR-0006](https://github.com/fgbm/winrig/blob/main/docs/adr/0006-password-header-and-confirmation.md)). The confirmation names the host, the user and the tool, and it names the target and the effect. A hidden value appears only as `hidden`. The old and new values of `set_registry`, the content of `write_file` and the command line of `kill_process` stay hidden. The text of a command and the text of a script appear in full, without the 200-character cap, because the operator confirms what will run. The server sanitizes each field and caps the other fields at 200 characters.

An operator can set `WINRIG_CONFIRM_FALLBACK=proceed` to run a modifying operation even when the client declared no elicitation channel. The relaxation attaches to the absent channel only: a user refusal, a cancel, a timeout and a transport error are never bypassed. The audit marks a run that happened without a confirmation ([ADR-0013](https://github.com/fgbm/winrig/blob/main/docs/adr/0013-file-write-and-command-execution.md), TR-SEC-11).

The setting removes fail-closed from every modifying tool at once, deletion included. It applies to every client that lacks elicitation, and in HTTP mode that means each request that declares no channel.

:::danger
Some clients apply their own permission to a tool call and replace the confirmation. With `permission: "*": "allow"` nobody confirms. The combination `proceed` + `WINRIG_ALLOW_COMMAND_EXEC=true` + an empty `WINRIG_ALLOWED_COMMANDS` + `permission: allow` runs arbitrary commands on the host. No person takes part in that run. None of the four settings is on by default ([ADR-0013](https://github.com/fgbm/winrig/blob/main/docs/adr/0013-file-write-and-command-execution.md) §23, Consequences).
:::

:::caution
The password comes in a header, not in a dialog. winrig does not ask for passwords through elicitation. The MCP specification excludes secrets from elicitation, and the protocol revision `2026-07-28` removes elicitation completely.
:::

## Protected paths and destructive operations

A recursive deletion refuses the roots of volumes and the system directories, in any form of the path. It also refuses reparse points (junction or symlink). `write_file` rejects protected paths with the same list that guards deletion ([ADR-0002](https://github.com/fgbm/winrig/blob/main/docs/adr/0002-secrets-confirmation-deletion.md), [ADR-0015](https://github.com/fgbm/winrig/blob/main/docs/adr/0015-security-defaults-and-host-resolved-paths.md)).

The operator can permit a write under a protected root with the allowlist `WINRIG_WRITE_ALLOW_PATHS` ([ADR-0017](https://github.com/fgbm/winrig/blob/main/docs/adr/0017-write-boundary-and-file-transfer.md) §7–13). An entry lifts the lexical refusal and the host-root refusal for `write_file`, `delete_file` and the file operations `copy_file`, `move_file`, `rename_file` and `create_directory`. The confirmation then carries an explicit warning sentence that names the class. The match is a prefix at a path-component boundary. It uses the normalized, case-folded resolved path, and it checks both resolutions. The allowlist never lifts the refusal of an 8.3 component. It also never lifts the refusal of a symbolic link or a junction, because the operation would act on the link target. A device volume path and an existing directory target are refused too. `delete_directory` and DR-6 do not change. The audit records the entry that permitted a protected path (§39).

Before confirmation, the host reports where the file will really land and where the system directories are. Therefore Windows on a volume other than `C:` is equally protected. The tool checks the administrative share `\\host\C$\...` as `C:\...`, and it protects the shares `ADMIN$`, `PRINT$`, `SYSVOL` and `NETLOGON` in full.

`copy_file`, `move_file`, `rename_file` and `create_directory` are off by default (`WINRIG_ALLOW_FILE_OPS`) and they obey the confirmation of DR-5. A directory copy is recursive and shows the counts. It refuses a source tree that holds a symbolic link or a junction, and the command repeats the check at run time. A move on one volume renames. Across volumes a file is copied and then deleted. A directory is refused, because the implied recursive delete falls under DR-6. The target of each tool obeys the write boundary. The source of a copy is read-only, so a read or a download from a system directory works ([ADR-0017](https://github.com/fgbm/winrig/blob/main/docs/adr/0017-write-boundary-and-file-transfer.md) §14–20).

## Arbitrary command execution

`run_command` runs one PowerShell command on the host. It is off by default (`WINRIG_ALLOW_COMMAND_EXEC`) and it obeys the confirmation of DR-5. The server encodes the command text as a base64 UTF-16 string. It decodes the string into a script block on the host. A quote or a terminator in the text therefore cannot break out of the generated wrapper. The command must fit one WinRS command line, so the text holds at most 979 characters. A longer script runs through `run_script`.

`run_script` runs a PowerShell script that is longer than one WinRS command line. It is off by default (`WINRIG_ALLOW_SCRIPT_EXEC`) and it obeys the confirmation of DR-5. The server writes the script into a temporary `.ps1` in the session temp directory in chunks. It reads the file and runs its text as a script block, then tries to delete the file. The script has no `$PSScriptRoot`, no `$PSCommandPath` and no arguments. The tool shows the SHA-256 of the script in the confirmation and records it in the audit, and it verifies the hash before the run. One confirmation covers the whole operation and shows the whole script. `WINRIG_ALLOWED_COMMANDS` does not filter a script: the server cannot prefix-check the text of a script. The script obeys `WINRIG_MAX_WRITE_BYTES`, and the output obeys the same limits as `run_command` ([ADR-0017](https://github.com/fgbm/winrig/blob/main/docs/adr/0017-write-boundary-and-file-transfer.md) §29–34).

`WINRIG_ALLOWED_COMMANDS` is a prefix list, matched without case after a trim. An empty list admits any command. The list is not a boundary ([ADR-0013](https://github.com/fgbm/winrig/blob/main/docs/adr/0013-file-write-and-command-execution.md) §18). A leading `&`, `.`, `powershell -c`, an alias, a call operator and an encoded command all start with text the list need not contain. Any text after an allowed prefix runs. So `;`, a newline, `|` and `$(...)` do not return control to the list. An entry of `&` or `.` alone admits every command. A script written with `write_file` and then started also goes around it. The list protects against an accidental command, not against intent.

:::danger
With `run_command` on and an empty `WINRIG_ALLOWED_COMMANDS`, the path protection of the other tools stops being a guarantee of the product. The same holds for the confirmation of the other modifying operations. They stay properties of their own tools. One line of PowerShell goes around both. `run_script` does not consult the command list at all, so it goes around the same guarantees. This is a deliberate choice of the operator ([ADR-0013](https://github.com/fgbm/winrig/blob/main/docs/adr/0013-file-write-and-command-execution.md), Q-14).
:::

## Host allowlist and TLS defaults

The list of allowed hosts and the ban on the downgrade of the TLS check are configured through the environment ([ADR-0004](https://github.com/fgbm/winrig/blob/main/docs/adr/0004-environment-configuration.md), [ADR-0015](https://github.com/fgbm/winrig/blob/main/docs/adr/0015-security-defaults-and-host-resolved-paths.md)).

- By default, the server connects only to loopback: `localhost`, `127.0.0.0/8`, `::1`. It does not resolve DNS.
- `WINRIG_ALLOW_INSECURE_TLS` defaults to `false`: the server rejects `verify_cert=false` before any network activity.
- A wrong item in `WINRIG_ALLOWED_HOSTS` (for example `*.corp.example`) stops the start.

:::danger
Do not permit any host without a reason. An agent could receive an instruction from data and connect to the host of an attacker. The call gives the attacker the NTLMv2 response of the domain account.
:::

## Transport security

winrig serves open HTTP on `/mcp`; the binary has no TLS listener. The bearer token is now a key: anyone who intercepts it reaches the server and decrypts the AD password.

:::danger
Do not bind to a non-loopback address without a TLS-terminating reverse proxy in front (nginx, Caddy or ingress). The default address is `127.0.0.1` for this reason.
:::

A multi-user deployment assumes that the proxy authenticates the clients. The proxy passes the headers `Authorization`, `X-AD-User` and `X-AD-Password` without changes.

The remote WinRM leg is separate: use `use_ssl` or port 5986 when the hop to the Windows host needs encryption. Over open HTTP, the encryption of this WinRM leg is only partial. `winrm-rs` seals the SOAP bodies with the NTLM session key, but the key does not exist until the handshake completes. The first request on each new connection therefore carries its body in clear text next to the Type 3 message. But if a host answers an unencrypted message with an empty `HTTP 500` (`AllowUnencrypted=false`, the Windows default), it rejects this first request immediately. Port 5986 removes both the exposure and the refusal.

## Report a vulnerability

Do not open a public issue. Use the private GitHub channel in [SECURITY.md](https://github.com/fgbm/winrig/blob/main/SECURITY.md). The security policy lists the accepted boundaries of the product and what to expect after a report.
