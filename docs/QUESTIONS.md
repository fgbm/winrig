# docs/QUESTIONS.md — the journal of questions

## Q-01. Lockout threshold and window

Decided: `WINRIG_LOCKOUT_ATTEMPTS=3`, `WINRIG_LOCKOUT_WINDOW_SECONDS=1800` (ADR-0005 §1).

## Q-02. Minimum redaction length

Decided: `WINRIG_SECRET_REDACT_MIN_LENGTH=4` limits only the reply to the agent; the audit is redacted at any length (ADR-0005 §2).

## Q-03. The semantics of the allowlist

Decided: an empty value permits everything; `.` is a suffix; otherwise the value must match exactly (ADR-0005 §3).

Revised 2026-09-22 (ADR-0015): an empty value means only the loopback literals (`localhost`, `127.0.0.0/8`, `::1`) without a DNS resolution. A separate element `*` means any host. The previous default let the agent connect to the host of an attacker and give it the NTLMv2 response of the domain account. `WINRIG_ALLOW_INSECURE_TLS` now defaults to `false`.

## Q-04. Idempotency of modifications

Decided: a second call asks for a confirmation again and applies the operation again (ADR-0005 §4).

## Q-05. The confirmation channel for modifications in Rust

Decided: elicitation of the form `{ "confirm": bool }`; when it is not available, fail-closed with the field `error` (ADR-0006 §2).

Correction of 2026-09-21: an earlier edition stated that the channel "is covered by a predicate test". That was not true: `grep -rn confirm tests/` gave no match, and no test ran `WinrigServer::confirm`. Slice W17 closed the hole. `tests/tool_calls.rs` starts an MCP client and a server on `tokio::io::duplex` and runs all branches live: a yes, a refusal, no capability at the client, a timeout. It checks not the text of the reply but the absence of a run command in the transport. The tests were checked by mutation: a break of the `confirm` branches drops exactly them.

## Q-06. The input of the AD password

Decided: the password comes in the header `X-AD-Password`; elicitation is not used for secrets (ADR-0006 §1). This differs from the Python version, where the password could be entered interactively.

Clarified 2026-09-22 (ADR-0015): on the header path `connect` opens a session only with the password from `X-AD-Password` of the same request. A password cached by one name no longer opens a session, because any holder of the shared secret can name the `X-AD-User`. The residual risk — an already open session runs commands without a password — is named in ADR-0015.

## Q-07. The version of `winrm-rs`

Decided: pinned to `=1.1.2`, because 1.2.x needs rustc 1.98 (ADR-0007 §1). Revisit at the release of stable 1.98.

Closed: rustc 1.98 went to stable, the pin is removed, and `winrm-rs` 1.2.2 is used (ADR-0007 §1).

## Q-08. A check on a live Windows host

Open. There is no live host; the NTLM connection, the behavior of reparse points and the parse of real output are not verified. Until a host or recorded traffic appears, these criteria are "not verifiable".

## Q-09. Findings of the independent audit of revision 1d5630a

Closed in the code and the tests. A configuration panic at an overflow of u32 fields (it was exit 101 instead of DR-8). The absence of a preliminary scan in `delete_directory` (a reparse point, a `FullName` that the host resolved, an element limit). A removed UTF-8 preamble (TR-REL-02). A duplicated audit entry in `winrig.log`. An unredacted stderr or error in the `connect` branch (DR-4). A missing `CONNECT ERROR` record (TR-OBS-01). A panic at a poisoned mutex. False coverages in `docs/REQUIREMENTS.md` are replaced with real tests, and `AC-SEC04-2` is added. The automatic tests of the HTTP start and of a live client stay outside the coverage and are marked as such.

## Q-10. The replacement of elicitation at the change to revision 2026-07-28

Open. ADR-0006 confirms that revision `2026-07-28` removes elicitation as a confirmation channel, and `rmcp` 3.4.0 already carries its replacement, `input_required` (SEP-2322). While clients run on old revisions, the tools are confirmed with elicitation. At the change, the modifying tools become fail-closed; the plan is to move `confirm()` to `input_required`, keeping the strict "explicit true only". A separate ADR comes before the change of the channel; for now it is recorded in the ROADMAP.

## Q-11. The pool of WinRM connections

Decided: there is no pool. `WinrmClient` is created for each call, and `winrm-rs` creates and deletes a shell inside `run_command`. AGENTS.md §2 and ADR-0003 are brought into agreement with the code. The reuse of a client for a session goes to the ROADMAP as a separate improvement, not as a correctness defect. NTLM encryption of the body over HTTP in `winrm-rs` is on by default (`EncryptionMode::Auto`). So the absence of a pool does not weaken the channel.

## Q-12. Profile, secrets and stdio

Decided (ADR-0009): the server stores only the authenticated ciphertext of the password. The key is derived from the profile token and is not stored on the server. A secret is mandatory, but one of two: `WINRIG_AUTH_TOKEN` for the header path, or the profile token `WINRIG_TOKEN`. A match of the shared secret with the profile token stops the start. The presented secret sets the identity. One profile for each process with a lock file; for several projects on one computer, use the HTTP mode. Logs without `WINRIG_LOG_DIR` go to the state directory of the OS, in a subdirectory of the profile. The profile token cannot go to the server configuration, so `.env` does not contain it.

Open subitems of Q-12:
- The OS keyring as an alternative to the profile file does not come in (outside the slice, in the ROADMAP).
- The change of the confirmation channel (Q-10) is not part of W12; clients without elicitation stay fail-closed.

## Q-13. The level of the client configuration write

Decided (ADR-0012): `setup --write-config` takes `--scope global|project`. Without the flag the level is asked in the terminal, and without a terminal the write refuses (fail-closed). The project level is the nearest git root from the current directory, or the directory itself. Paths: opencode `<root>/opencode.json`, Claude Code `<root>/.mcp.json`, Codex `<root>/.codex/config.toml`, Cursor `<root>/.cursor/mcp.json`. For the opencode project level the profile token is a file `0600` in `WINRIG_STATE_DIR` with the reference `{file:...}`. For Claude/Cursor/Codex the profile token is inline, with a warning about a possible commit. `--scope` without `--write-config` is rejected.

## Q-14. Arbitrary execution on the host

Decided (ADR-0013): arbitrary execution and a file write are necessary for the product and come in as the tools `run_command` and `write_file`. Before that decision, the absence of arbitrary execution was a property of the code, not a position. All 37 tools carried a hard-coded script from `src/ps.rs`, and `SessionRegistry::run_ps` was not exposed.

The frame in which this comes in: both tools are modifying and obey DR-5. Both are off by default (`WINRIG_ALLOW_FILE_WRITE`, `WINRIG_ALLOW_COMMAND_EXEC`) and in the off state are not declared to the agent. `write_file` reuses the path protection `is_protected_path` and requires an explicit `overwrite`. `run_command` takes the prefix allowlist `WINRIG_ALLOWED_COMMANDS` and shows the full command text in the confirmation.

Named directly and accepted: with `run_command` on and an empty allowlist, the path protection and the confirmation of modifying operations stop being guarantees of the product. They remain only properties of individual tools: one line of PowerShell goes around both. This is the choice of the operator, not what winrig continues to provide.

The confirmation goes through elicitation, which opencode 1.18.31 does not have, so earlier both tools would be declared there and always refuse. The decision is not to wait for Q-10: `WINRIG_CONFIRM_FALLBACK=proceed` moves the risk to the operator. The relaxation triggers only on `ElicitationError::CapabilityNotSupported`. It does not trigger on a refusal of the user, a cancellation, a timeout or a transport error. "The user said no" and "there is no one to ask" stay different cases. The scope is all modifying tools: a setting that permits arbitrary execution and forbids the deletion of a file is meaningless.

The confirmation does not disappear, but moves to the client. opencode puts each call through its permission system (`permission` with keys of the form `winrig-tm_run_command`). winrig does not see this gate, so `proceed` is a statement of the operator that the gate is configured. The opposite is also true and is recorded in the ADR: with `permission: "*": "allow"` nobody asks.

Separately: WinRM runs commands in a non-interactive session without a desktop, so there is no one to show a GUI application to. This is a limitation of the protocol; none of the decisions above removes it.

## Q-15. Work with Active Directory and the method of the directory query

Decided (ADR-0014): work with the directory is necessary for the product and comes in with slices W19, W20 and W21. W19 is read and maintenance, W20 is accounts and membership, and W21 is attributes by rules. Before that decision, the absence of AD was nobody's position. It was only a state of the code: no tool, no requirement, no line in the section "What the product does not have".

The route: a session opens to the domain controller itself. So a query to the directory is local and a double NTLM hop does not occur. CredSSP is rejected: a C dependency `openssl` in the build and the delegation of the password to each host. Credentials in the text of a script are rejected: a password in the command line of each call. LDAP directly from winrig through `ldap3` is deferred to a separate ADR, if AD becomes a separate direction.

An assumption that stays open: the directory is queried with the classes `System.DirectoryServices`, and not with RSAT cmdlets. The classes are `[ADSI]`, `DirectorySearcher` and `System.DirectoryServices.ActiveDirectory`. RSAT cmdlets are rejected, because they go to ADWS and depend on an installed module and a running service. On a live domain controller neither method was verified: there is no Windows host in the environment (Q-08). The first live call removes the assumption. If `[ADSI]` behaves differently than expected under network logon on a domain controller, the route stays the same. Only the method of the query changes.

Named directly and accepted: the read of the directory is also a disclosure. `find_ad_objects` and `get_ad_membership` allow the export of the structure of the organization, the composition of privileged groups and the list of stale accounts. A result ceiling and the audit of the calls limit this; there is no ban on enumeration.

Named directly and accepted: with `WINRIG_ALLOW_AD_WRITE=true` and an empty `WINRIG_AD_WRITABLE_ATTRIBUTES`, the protection stays only on unconditionally forbidden attributes and protected objects. With `WINRIG_CONFIRM_FALLBACK=proceed` this means a change of the directory by a decision of the agent without a person, as for `run_command` in Q-14.

## Q-16. Safe defaults and protected host roots

Decided (ADR-0015): four security corrections in one decision. PowerShell quotes are escaped in all five forms (TR-SEC-12). `connect` by headers requires the password in the same request (TR-SEC-13). An empty host allowlist means only loopback, and `*` means any host. `WINRIG_ALLOW_INSECURE_TLS` defaults to `false`, and `setup --allowed-hosts` writes the list into the client entry (TR-SEC-14, TR-SEC-06, TR-PRF-17). A write and a deletion check the path against the roots from the host system variables (TR-FS-06, TR-SEC-04). Policy refusals go to the audit (TR-OBS-03). The change of the defaults breaks compatibility, so the release is 0.2.0.

Named directly and accepted: an already open session runs commands without a repeated password. Junctions and symlinks in parent directories of a write target are not resolved. Both residual risks are recorded in ADR-0015.

## Q-17. The CLIXML progress record in stderr

Decided: every generated script sets `$ProgressPreference = 'SilentlyContinue'` in its preamble (TR-REL-10, slice W23, GitHub #22). The bug report offered two options — the preamble, or a result parser that drops the `S="progress"` records. The preamble removes the record at the cause, on the host. The slice takes both. The preamble silences the stream. The parser `strip_clixml` keeps the stream records and drops the progress objects and the position lines. The slice also sizes the `write_file` chunk by the WinRS command-line budget: `WRITE_CHUNK_BYTES` is 1536 and the path limit comes from the budget. `run_ps` refuses a command that does not fit one WinRS command line before the transport, with the audit entry `COMMAND REFUSED`.

## Q-18. Registry subkeys: a new tool or a parameter

Decided: `get_registry` takes the parameters `subkeys: bool` (default `false`) and `depth: i64` (default 1, the range is 1 to 5) (TR-REL-11, slice W24, GitHub #18). The issue offered a new tool `list_registry_subkeys` or a parameter of `get_registry`. Both operations are read-only and of the same risk, and ADR-0014 §10 groups same-risk operations into one tool. A parameter also keeps the exact tool count stable.

## Q-19. The parameter names of `get_tcp_connections`

Decided: the existing `state_filter` and `port_filter` stay, and the slice adds `pid: i64` (default 0), `process` (a wildcard, default empty) and `summary: bool` (default `false`) (TR-REL-13, slice W26, GitHub #20). The issue used the names `state` and `local_port`. A rename would break the response contract of the ported tool (ADR-0003), so the slice keeps the existing names. The summary groups the rows by process, local port, local address and remote address, with a count for each group. The server refuses an unknown state before the call.

## Q-20. Protected services for the service tools

Decided: `set_service_start_type`, `stop_service` and `restart_service` refuse a service that is critical for the remote session (TR-SEC-15, AC-SEC15-3, slice W30, GitHub #10). The issue says "as `stop_service` does now, if it does". The code had no such refusal before the slice. The set is fixed in `policy::PROTECTED_SERVICES`: `WinRM`, `RpcSs`, `DcomLaunch`, `LanmanServer` and `Winmgmt`. The server also refuses a target on which a protected service depends. The host resolves the canonical name and repeats the check, because `ServiceController` also accepts a display name.

## Q-21. Personal data in the print job result

Decided: `get_print_jobs` returns the document name and the owner only with `include_personal_data: bool` (default `false`) (TR-REL-15, AC-REL15-2, slice W28, GitHub #19). Without the flag the two fields are absent from the result. The issue asks to return them "only when the caller asks for them explicitly"; the default-off flag is that explicit request.

## Q-22. The time filter of the log search

Decided: `search_file_content` takes `since` and `until` (timestamps) and `timestamp_format` (a .NET fixed-width custom format, default `yyyy-MM-dd HH:mm:ss`, at the start of the line) (TR-REL-16, slice W29, GitHub #17). The format is not a regular expression. The host parses the timestamp prefix with `InvariantCulture`. The server refuses a variable-width specifier, a quoted or escaped literal and a non-ASCII character. If the caller gives `since` or `until` without a format, the server uses the default format. A date-only bound is the start of the day for `since` and the end of the day for `until`. The `exclude` pattern of the `read_file` tail mode is a literal substring, as in `search_file_content` (the `-SimpleMatch` rule), not a regular expression. `exclude` without the tail mode is refused.

## Q-23. The form of `doctor`

Decided: `doctor` is a read-only subcommand (TR-PRF-18, AC-PRF-69, slice W31, GitHub #24). The issue offered a command `winrig doctor` or an option of `setup`. The subcommand keeps `setup` a single responsibility for the client configuration write. The command shows a value only for a known non-secret setting. Its exit code is 0 without a difference, 1 on a difference or an incomplete scan and 2 on a usage error. The optional part of the issue stays outside the slice: `setup` writes the same set of variables for each profile it adds. That part changes the write of the client configuration and needs its own decision.

## Q-24. The markers and the envelope of the confirmation text

Decided (slice W32): the server shows a hidden value as the literal `hidden` beside its label, for example `new value: hidden` (TR-SEC-18). The old value of `set_registry` is hidden too. The server caps a field of the confirmation at 200 characters. The marker of a cut is `...`, and it counts inside the cap. The server cuts the value to 197 characters and appends `...`, so the field holds at most 200 characters. The host is the host of the session of the call. The identity is the user of the current request (DR-2). The tool is the MCP tool name; the plain line of the action may hold the action label of today next to it. `kill_process` shows the executable path and the start time, never the command line (DR-4). `write_file` shows the size and the resolved path.

The exact sentences of the effect and undo lines of each tool are fixed in `src/server.rs` as the `EFFECT_*` constants (TR-SEC-16, TR-SEC-20). A test checks that each sentence fits the 200-character cap. The requirement fixes that one line exists and states the operation and whether the operator can undo it.

## Q-25. The write allowlist and the hard ban on the system directories

Decided (ADR-0017 §11): the operator allowlist `WINRIG_WRITE_ALLOW_PATHS` may cover a system directory or a volume root. Issue #13 proposed the opposite: "The system directories (`C:\Windows`, `C:\Windows\System32`) cannot be in the list." The operator asked for freedom of action, and the confirmation carries an explicit warning line for the class. Two bypass protections stay, and the allowlist does not lift them. The first is a path with an 8.3 component (AC-SEC04-6). The second is a target whose final component is a reparse point.

## Q-26. The scope of the allowlist on a delete

Decided (ADR-0017 §9): the allowlist lifts the protected-prefix refusal for the write-side file tools, and it includes `delete_file`. Issue #13 named `delete_file` as one of the tools, and the field case was the delete of an empty database file under `C:\ProgramData`. `delete_directory` does not consult the allowlist: DR-6 keeps its refusals of a volume root, a system directory and a reparse point.

## Q-27. One flag for each new capability

Decided (ADR-0017 §3): each new capability has its own flag: `WINRIG_ALLOW_SCRIPT_EXEC`, `WINRIG_ALLOW_FILE_OPS`, `WINRIG_ALLOW_FILE_DOWNLOAD` and `WINRIG_ALLOW_FILE_UPLOAD`. The pattern of `write_file` and `WINRIG_ALLOW_FILE_WRITE` (ADR-0013 §2) continues. A distinct capability has a distinct risk, and the operator enables one at a time. `write_file` keeps its own flag.

## Q-28. Where `run_script` is decided

Decided: in ADR-0017, not as an amendment to ADR-0013. The composition writes a file, runs it and deletes it, and ADR-0017 owns the write mechanism and the write boundary. ADR-0013 receives a pointer.

## Q-29. The staging file of `run_script`

Decided (ADR-0017 §31–32): the temporary `.ps1` is the staging of the tool, not a target of the operator. The write boundary and the protected-root refusal do not apply to it. The session temp directory (`$env:TEMP`) is under a protected root, and a tool that needs an allowlist entry to start would be useless. The confirmation names the path, and the audit records it.

## Q-30. `run_script` and the command allowlist

Decided (ADR-0017 §34): `run_script` is enabled by `WINRIG_ALLOW_SCRIPT_EXEC` alone. The prefix list `WINRIG_ALLOWED_COMMANDS` does not filter the script, because the server cannot prefix-check the text of a script in a meaningful way. The confirmation states this. The composition of `write_file` and `run_command` already broke the allowlist (ADR-0013 §18); `run_script` makes the composition one tool.

## Q-31. The body in the confirmation text

Decided (ADR-0017 §37): the text of a command and the text of a script appear in full in the confirmation, without truncation. The 200-character cap of TR-SEC-19 applies to the other fields. A cut script would confirm a different operation. The server sanitizes the field (ADR-0008 §11), so the body cannot forge the dialogue.

## Q-32. Every download needs a confirmation

Decided (ADR-0017 §28): a download moves data off the host, and the data may be personal. The confirmation is mandatory for every download, not only for a file under a protected or a system path. Issue #11 proposed the flag `WINRIG_ALLOW_FILE_DOWNLOAD`, and the flag stays.

## Q-33. The transfer defaults and the raw channel

Decided (ADR-0017 §21–27): the local endpoint is `WINRIG_TRANSFER_DIR`, with a per-user subdirectory in HTTP mode (DR-3). The size ceiling `WINRIG_MAX_TRANSFER_BYTES` defaults to 256 MiB. A download uses a raw chunked channel outside the 60 000-character reply truncation, and it verifies the SHA-256 on both sides. A resume is not required. A small file does not go into the reply as base64; the reply carries the name, the size and the hash.

## Q-34. The fine points of `move_file`, `rename_file` and `create_directory`

Decided (ADR-0017 §18–20): a move on one volume is a rename. A cross-volume move of a file is a copy and a delete, and the prompt shows the implied delete. A cross-volume move of a directory is refused, because the implied recursive delete falls under DR-6 and a partial move leaves two trees. An overwrite of an existing directory is refused in all cases. `create_directory` makes the missing parents, and the prompt shows the count.
