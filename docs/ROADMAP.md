# docs/ROADMAP.md — the queue of slices

Product: `winrig`. Canon: `AGENTS.md`. Cycle: `docs/IMPLEMENTATION_CYCLE.md`. Statuses: `pending` → `in progress` → `accepted` / `not accepted` / `blocked`.

| Slice | Goal | Requirements | Risky | Status |
|---|---|---|---|---|
| W1 | Configuration validation and a clear start refusal | TR-REL-07 | no | accepted |
| W2 | Host policy, TLS and path safety | TR-SEC-04/05/06, TR-REL-06 | yes | accepted |
| W3 | Secret redaction, truncation, audit fields | TR-SEC-02/03/08 | no | accepted |
| W4 | WinRM pool, password cache, lockout, audit | TR-SEC-01/07, TR-OBS-01/02 | yes | accepted |
| W5 | PowerShell generators and read-only tools | TR-REL-02..05 | no | accepted |
| W6 | Auth gate, streamable-HTTP `/mcp`, logging | TR-SEC-07, TR-REL-01 | yes | accepted |
| W7 | Modifying tools and confirmation | DR-5 | yes | accepted (except a live client, Q-05) |
| W8 | Security audit: injections, secret redaction, delete protection, locale | TR-SEC-02/04/07/09, TR-REL-06/07/08 | yes | accepted |
| W9 | Tests: HTTP integration `/mcp`, injections across all generators, the exact tool count | TR-OBS-02, DR-1 | no | accepted |
| W10 | Operations: CI, the release profile, cargo-deny, WINRIG_LOG_DIR, the TLS section | TR-REL-07 | no | accepted |
| W11 | Synchronization of the documents with the code | — | no | accepted |
| W12 | Account profile, CLI setup, stdio mode | TR-PRF-01..10, ADR-0009 | yes | accepted |
| W13 | The level of the client configuration write: global or project | TR-PRF-13, ADR-0012 | no | accepted |
| W14 | A field incident: the client configuration write, the state directory, the account form, the classification of transport errors | TR-SEC-10, TR-PRF-14/15/16 | yes | in progress |
| W15 | A file write to the host | TR-FS-01..05, ADR-0013 | yes | accepted |
| W16 | Execution of arbitrary commands | TR-EXE-01..04, ADR-0013 | yes | pending |
| W17 | Executable coverage of the tools and the confirmation channel | TR-REL-09 | no | accepted |
| W18 | Removal of the `winrm-rs` pin and a toolchain upgrade | Q-07 | yes | pending |
| W19 | Active Directory read and domain maintenance | TR-AD-01..05/16, ADR-0014 | no | pending |
| W20 | Accounts and group membership | TR-AD-06..09/12..15, ADR-0014 | yes | pending |
| W21 | Attribute editing by rules | TR-AD-10/11, ADR-0014 | yes | pending |
| W22 | Safe defaults: PowerShell quotes, the password on `connect`, loopback and TLS by default, the host roots, the audit of refusals | TR-SEC-04/06/12/13/14, TR-FS-06, TR-OBS-03, TR-PRF-17, ADR-0015 | yes | accepted |

## Phase criteria

A roadmap phase is complete when each slice is `accepted` or `blocked` with an entry in `docs/QUESTIONS.md`. A slice is `accepted` only when an independent reviewer gives the verdict "done" to all its acceptance criteria and the documentation matches the code.

## The result of the first phase

The code implements all seven slices. At the revision of the first audit `cargo test` was green (101 tests) and `cargo clippy --all-targets -- -D warnings` had no warnings. The current number of tests is 190 (see W12). An independent audit of the revision `1d5630a` found and closed several defects. The list holds a configuration panic on overflow and a missing reparse protection in `delete_directory`. It holds a removed UTF-8 preamble, a double audit, and an unredacted stderr on `connect`. The environment has no live Windows host (Q-08). The criteria that need a real host carry the mark "not verifiable" in `docs/REQUIREMENTS.md`. The list holds an NTLM connection, the behavior of reparse points and a live parse of the output.

The slices W4, W5 and W7 have an acceptance with a caveat. Their automatic tests run on the fake transport, and no test verified a live channel (Q-08). This does not block a slice, but the document names it explicitly.

## The second audit and the slices W8–W11

A second audit of the repository found defects that the first audit missed. The list holds a PowerShell injection in `compare_files` and a dead secret redaction on the main path `run_ps`. It holds a log silenced by the values `WINRIG_LOG_LEVEL=WARNING`/`CRITICAL`. It holds a missing protection and scan in `delete_file`, nested reparse points in `delete_directory`, and the locale of `whoami /priv`. It holds a lockout bypass by a change of the case of the user, an endless wait for a confirmation, and a missing CI. The slices W8 (code), W9 (tests), W10 (operations) and W11 (documents) close them. `docs/REQUIREMENTS.md` received new `AC-*`, and the document marks TR-SEC-08 and the duration in TR-OBS-01 explicitly as not implemented.

## Environment limits

There is no test Windows host (AGENTS.md §4). The criteria that need a live host get a check on the fake transport as far as possible.

## Further work outside the first phase

- SFTP tools (they depend on Posh-SSH on the Windows host) — a port of the PowerShell strings and the cache of the account data.
- The unported tools of the Python version and other capability gaps — see "What the product does not have" below. The list lives in one place there.
- The duration and, if necessary, the source of the call in the audit entry (TR-OBS-01).
- A replacement of the confirmation channel with `input_required` (SEP-2322), when the clients move to the revision `2026-07-28`: the revision removes elicitation (ADR-0006, Q-10). Clients without elicitation (opencode 1.18.31) stay fail-closed on the modifying tools.
- A pool or a reuse of the WinRM client for a session, instead of a new client for each call.
- An OS keyring as an alternative to the profile file for desktop scenarios (ADR-0009).

## What the product does not have

This section comes from the traces of live operation: the agent hit a missing capability and explained it to itself in a wrong way. The section lists what is absent **now**, and names which item is a decision and which item is a gap.

### Execution of arbitrary commands

There is no tool for arbitrary execution. All 37 tools carry a hard-coded PowerShell script from `src/ps.rs`. `SessionRegistry::run_ps` is an internal method and the server does not expose it as an MCP tool. Nothing can run: no third-party utility, no one-off script, no software installation.

The decision is to add it: slice W16, ADR-0013, and Q-14 has a decision. Before the operator made the decision, the absence of arbitrary execution was not a position of anybody, only a state of the code.

Separately, WinRM runs commands in a non-interactive session without a desktop. Therefore no user can see a GUI application: it starts invisible or it hangs. This limit is a property of the protocol, not of winrig, and it stays after W16.

### Files

The file tools only read: `list_directory`, `find_files`, `read_file`, `search_file_content`, `file_info`, `compare_files`. A delete is the only modifying tool.

Absent:
- a write of file content (`write_file`) — the decision is to add it, slice W15, ADR-0013;
- a creation of a directory, a copy, a move, a rename (`create_directory`, `copy_file`, `move_file`, `rename_file`);
- a file transfer to the host and back (file transfer, `docs/IMPLEMENTATION_CYCLE.md` §unported);
- work with archives (`compress_archive`, `expand_archive`).

### Active Directory

Work with the directory is absent in any form: no tool, no requirement, and no mention in this section until now. The tools answer about the host on which they run. Not one tool answers about the domain. The only item that exists now is the domain groups of the current session in `get_security_context`. They come from the token, not from the directory.

The cause is the protocol, not the architecture. NTLM gives a network logon on the host without delegable account data. Therefore a directory request from a host that is a domain member is a second hop to the domain controller, and it refuses (`An operations error occurred`). The same cause explains why the capability will not appear by itself together with `run_command`. An arbitrary command runs in the same session with the same token, and it hits the same wall.

The decision is to add it: the slices W19 (read and maintenance), W20 (accounts and membership), W21 (attributes by rules), ADR-0014, the assumption Q-15. The route is a session to the domain controller itself, where the request is local and no second hop exists.

No slice adds these, and the document calls them a decision, not a gap. The list holds a change of the topology (an FSMO role seizure, a metadata cleanup, a forced replication) and a delete of directory objects.

### Diagnostics of used space

No tool answers the question "what ate the disk". `get_disk_space` gives only volumes (`DeviceID`, `Total_GB`, `Free_GB`, `Used_Pct`). `find_files` returns `Select-Object -First 100` in the order of the walk, without a sort by size. Therefore it is not a workaround either. A plain `Get-ChildItem` with a grouping solves the task, and it needs no external analyzer. Two read-only tools come to mind: `get_directory_size` (first-level subdirectories in descending order) and `get_largest_files` (top-N in a subtree).

### Network

`invoke_http_request` is not ported. It is the subject of TR-SEC-08, whose criterion AC-SEC08-1 carries the mark "not verifiable" for this exact reason.

## W12. Account profile, CLI setup, stdio mode

Goal: the AD password does not lie in clear text. One binary works as an HTTP service and as a stdio process, with one profile for each process.

The code implements ADR-0009. The subcommands are `serve`, `stdio`, `setup`, `list`, `rotate` and `forget`. The profile holds authenticated ciphertext with a key from the profile token. Two secrets define the identity from the presented secret. `setup` writes the configurations of opencode, Claude Code, Codex and Cursor. The process holds a lock. The logs go into the state directory. The profile has a double lockout. The variables use the notation `WINRIG_*` (ADR-0010). `serve` accepts `--port`/`--host`/`--token`/`--auth-token` (ADR-0011).

Not verifiable by an automatic test: a live NTLM connection, the behavior of reparse points and the parse of the host output (Q-08). A property of the code (the HMAC mark) and a behavioral test confirm AC-PRF-53 (the absence of a second KDF). A counter of decryptions does not confirm it.

## W13. The level of the client configuration write

Goal: `setup --write-config` writes the server definition into the selected level, global or project, and does not guess the level in silence.

The code implements ADR-0012. The flag is `--scope global|project`. Without the flag the tool asks for the level in the terminal. In a non-interactive run the write refuses (fail-closed). The project level is the nearest git root from the current directory, or the directory itself. The paths are: opencode `<root>/opencode.json`, Claude Code `<root>/.mcp.json`, Codex `<root>/.codex/config.toml`, Cursor `<root>/.cursor/mcp.json`. For the opencode project level the profile token moves into `WINRIG_STATE_DIR` (`0600`) with the link `{file:...}`. For the other clients the profile token is inline, with a warning about a possible commit.

An independent reviewer gave the verdict "accepted": AC-PRF-60..63 "done", and the review found no disagreement between ADR-0012 and the code.

## W14. A field incident: the client configuration, the state directory, the account form

Goal: remove the defects that the first live connection revealed. All four came from a parse of a live refusal, not from a code reading. The client showed `MCP error -32000: Connection closed` and `authentication failed`, and neither of them described the real event.

The course of the incident and the real causes:

| Symptom at the client | Cause |
|---|---|
| `Connection closed` | the profile token in the configuration did not decrypt the profile |
| `NTLM authentication rejected (bad credentials or CBT mismatch)` | the profile held `contosoalice` — a lost `\`, so NTLM went with an empty domain |
| `Connection closed` (a second time) | `setup --write-config` added a second server `winrig` beside the existing `winrig-tm`; two processes for one profile. The second catches `ProcessLock::Locked` and exits with code 2 |
| `authentication failed: HTTP 500 Internal Server Error: ` | NTLM passed; the listener rejected the unencrypted SOAP body of the first request |

The content of the slice:

- **TR-SEC-10 (done).** `winrm-rs` puts both an NTLM refusal and any failed HTTP status into `AuthFailed`. The second item comes after the accepted password. But `session.rs` counted it as a credential failure: it cleared the password cache and moved the lockout counter. On the second triple it moved the profile into `PROFILE REFUSED` until a process restart (AC-PRF-56). A listener with a wrong configuration burned the profile. The code adds `TransportError::Rejected`. It explains an empty `HTTP 500` as a refusal of an unencrypted message and names the port 5986 and `AllowUnencrypted`. Criteria AC-SEC10-1..4.
- **TR-PRF-14 (done).** `setup --write-config` inserted an entry under the hard key `winrig` and did not look whether another key declared the same profile. A diagnosis of the consequence from the client is impossible: `prepare_profile` fails before the initialization of the logging. The error goes only to stderr, and the client shows `Connection closed`. Now the tool takes the key from the existing entry for the same profile. It does not touch an entry for another profile, and `--server-name` sets the name explicitly. Criteria AC-PRF-64/65.
- **TR-PRF-15 (done).** The client entry held the profile path `state_dir_for(name)`, and at startup `Locations::resolve` treats `WINRIG_STATE_DIR` as the root and adds the name a second time. The lock, `winrig.log` and `winrig-audit.log` moved one level below the profile token. The defect is worse than cosmetics: the lock directory depends on the form of the variable in the entry. Therefore two runs with different forms take different lock files and miss the guarantee "one process for each profile". The definition field has the new name `state_root`, and the token directory uses the same rule as the server. Criterion AC-PRF-66.
- **TR-PRF-16 (done).** `profile::create` checked only for a non-empty value, and `canonical_username` only lowers the case. An account without `\` and without `@` gave a profile with an empty domain in silence. The operator learned about it from an NTLM refusal. The code adds `ProfileError::InvalidAccount`. The refusal names the expected form and reminds about the quotes in a shell. Criterion AC-PRF-67.

One item stays open: `rotate` keeps the account name. Therefore a profile created before TR-PRF-16 stays with an empty domain. Only a second `setup --overwrite` corrects it. The operator gets no signal about it. `list` shows the name, but it gives the name no mark.

Not verifiable by an automatic test: the refusal of the listener to an unencrypted message and a live NTLM connection (Q-08). The classification of the error gets a check on the fake transport. The review takes the signature of an empty `HTTP 500` from the code of `winrm-rs`, not from an observation.

## W15. A file write to the host

Goal: the agent can write a file to a Windows host without a way to rewrite the system at the same time.

The content (ADR-0013): the tool `write_file`, off by default through `WINRIG_ALLOW_FILE_WRITE`. While the tool is off the server removes it from the router instead of hiding it from the list. It needs a confirmation by DR-5. It refuses by `is_protected_path` before a call to the host, with the same list that guards a delete. An overwrite needs an explicit `overwrite: true`. The default encoding is UTF-8 without a BOM, with the same list of encodings that `read_file` accepts.

The size hits the command line, not `MaxEnvelopeSize` as the first draft of the ADR supposed. The script goes to the host as the argument `powershell.exe -EncodedCommand <base64>`, and WinRS limits that argument to about 8191 characters. After the triple encoding, one call holds less than 2 KB of raw data. The encoding is base64 of the content, then UTF-16LE of the script, then base64 of the argument, about 3.5×. Therefore the write goes in chunks of 2000 bytes, exactly as in `winrm-rs::transfer`, where `CHUNK_SIZE` has the same reason. The write uses the existing seam `run_ps` and not `WinrmClient::upload_file`. The method of the crate takes a local file as input, and it passes by the audit, the redaction and the fake transport. The tool writes the chunks into a temporary file and replaces the target with a rename. Therefore a refusal in the middle leaves no truncated file. The default of `WINRIG_MAX_WRITE_BYTES` is 64 KiB. This limit is a property of patience, not of the protocol. It is 33 calls to the host, and the server creates a client for each call (Q-11).

The subject of the check is the frame, not the presence of the tool. TR-FS-01 keeps the tool off by default and undeclared. TR-FS-02 refuses a protected path before the network. TR-FS-03 allows an overwrite only by the flag. TR-FS-04 gives a clear refusal above the size limit. TR-FS-05 writes chunks and replaces the target by a rename.

Outside the slice: the check of the path length against `MAX_PATH` (260), which `winrm-rs` does on its side. On our side a long path gives a host error. And `create_directory` is outside, so the host refuses a write into a missing directory, not the policy.

## W16. Execution of arbitrary commands

Goal: close the class of one-off tasks that none of the 37 tools covers, from diagnostics to software installation.

The content (ADR-0013): the tool `run_command` with arbitrary PowerShell, off by default through `WINRIG_ALLOW_COMMAND_EXEC`. The allowlist of prefixes `WINRIG_ALLOWED_COMMANDS` has the same empty-list semantics as `WINRIG_ALLOWED_HOSTS`. A confirmation by DR-5 shows the full text of the command without truncation. The redaction of secrets works in the reply and always in the audit log. The timeout and the truncation of the output come from the existing settings. The slice adds no separate form "run an exe with arguments": that form is the same arbitrary run with a new escape surface.

The subject of the check: TR-EXE-01 keeps the tool off by default and undeclared. TR-EXE-02 refuses a command outside the allowlist before the network. TR-EXE-03 needs a confirmation, and a relaxation needs an explicit choice of the operator. TR-EXE-04 shows the full text of the command in the confirmation. TR-SEC-11 applies the relaxation only to "no channel to ask".

A separate part of the slice is `WINRIG_CONFIRM_FALLBACK` (ADR-0013 §19–23). A client without elicitation today makes all modifying tools dead, and a wait for Q-10 is not obligatory: the operator can take the risk. The relaxation attaches to `ElicitationError::CapabilityNotSupported`, "the client did not declare the channel". It does not apply to a user refusal, a cancel, a timeout (TR-REL-08) or a transport error. The scope is all modifying tools, not only `run_command`: a setting that permits arbitrary execution but forbids a file delete has no sense.

The check must cover all five branches of a channel error separately. Today `confirm()` tells four cases apart and puts the rest into a common `Err`, so the code must select `CapabilityNotSupported` explicitly.

The document records this as a consequence, not as an oversight. With `run_command` on and an empty allowlist, the path protection and the confirmation of modifying operations stop being guarantees of the product. They stay properties of the separate tools. One line of PowerShell bypasses both. This is the choice of the operator.

The slice breaks the W9 invariant "the exact tool count". The number of declared tools now depends on two settings, and the test must check both branches.

## W17. Executable coverage of the tools and the confirmation channel

Goal: a run must check the rule on which all the safety of modifying operations stands, not a code reading.

A review of the whole project found this: `grep -rn confirm tests/` gave no match. Not one of the 250 tests ran `WinrigServer::confirm`. Therefore a regression that returns `Ok(())` in the error branch would pass a green run and disable the confirmation in silence. At the same time `docs/QUESTIONS.md` (Q-05) claimed that a "test predicate" covered the channel. That false claim lived in the canon until W17.

The decision is `tests/tool_calls.rs`. A client and an MCP server start on `tokio::io::duplex`, and a fake `WinRmTransport` connects to the registry. An override of `ClientHandler::create_elicitation` sets the confirmation branches. The tests cover a yes, a refusal, a missing capability of the client and a timeout. The negative cases assert **the absence of a finished command in the transport**, not the text of the answer. A text can come also from a finished operation. Only `[dev-dependencies]` declares the features `rmcp/client` and `tokio/io-util`, so the release graph and `Cargo.lock` did not change.

A mutation checked the tests: a break of the relevant branches of `confirm` fails exactly the tests that it must. This check is not a formality. It showed that one assertion closed a different class of regressions than was supposed. The test had to become stronger by another sign.

A side find of the same kind: the "positive" checks of `tests/http_gate.rs` used `assert_ne!(status, UNAUTHORIZED)` and passed in silence on `400 Bad Request`. The requests carried no `Host` header, which the streamable-HTTP layer requires, and **they never reached the MCP service**. Five tests asserted "the gate passed" and proved nothing. Now the test asserts `200` and the presence of `protocolVersion` in the body.

One of the ten call sites of `require_confirmation!` has coverage. The macro is the same, so the other sites depend on it. TR-REL-09 names this explicitly, so that the coverage does not look wider than it is.

## W19. Active Directory read and domain maintenance

Goal: the agent answers questions about the domain, and not only about the host on which the command runs.

The route (ADR-0014): a session opens to the domain controller itself, so the directory request is local and no second NTLM hop exists. The transport, the session model and the authentication do not change. The AD tools are plain generators in `src/ps.rs` behind the existing seam `policy` → `session` → `run_ps`. The classes `System.DirectoryServices` query the directory, not the RSAT cmdlets: the cmdlets use ADWS and depend on an installed module and a running service.

The content is six tools. All of them only read and need no confirmation:

| Tool | Parameters | What it answers |
|---|---|---|
| `get_ad_object` | `kind: user\|group\|computer`, `identity` | the card of the object: the state of the account, the password dates, the last logon, the DN, the OU |
| `get_ad_membership` | `identity`, `direction: of_object\|members`, `recursive` | membership in both directions, nested through `LDAP_MATCHING_RULE_IN_CHAIN` |
| `find_ad_objects` | `query`, `kind`, the result ceiling | a search by name and `sAMAccountName` |
| `get_ad_domain_info` | — | a snapshot of the configuration: the domain, the forest, the levels, FSMO, the domain controller list, the trusts, the sites, the password policy and PSO |
| `get_ad_health` | — | the items that change with time: replication (the partners, the last good and bad attempt, the lag), the services NTDS/DNS/ADWS/W32Time, the state of SYSVOL |
| `get_ad_stale_objects` | `kind: user\|computer`, `older_than_days` | the stale objects by `lastLogonTimestamp` and `pwdLastSet` |

The grouping by `kind`/`direction` is the decision of ADR-0014 §10. Symmetric operations come together into one tool, because the choice of the model gets worse with several dozen declared tools. Operations with a different risk do not come together into the modes of one tool. On the write wave this rule works in the opposite direction.

The subject of the check is the frame, not the presence of the tools. TR-AD-01 checks the host role in the script, so a host that is a domain member gives a clear refusal, not a directory error. TR-AD-02 keeps a value inside the LDAP filter: an escape of RFC 4515 before the escape of PowerShell. TR-AD-03 names the result ceiling in the answer. TR-AD-04 makes the parse independent of the locale. TR-AD-05 gives no write to any tool.

The invariant "the exact tool count" from W9 moves. The number of declared tools becomes 44 instead of 38, and the number visible by default becomes 43 instead of 37. The same slice corrects the criterion AC-PRF-48 and both tests (`server::tests::tool_router_lists_registered_tools`, `tests/stdio_mode.rs::stdio_serves_mcp_over_clean_stdout`).

Outside the slice: a change of the topology of the domain and the forest (ADR-0014 §12) is not deferred. It does not belong to the product.

## W20. Accounts and group membership

Goal: the operator creates, disables and unlocks accounts and edits the membership in groups. The operator gets no way to seize the domain at the same time.

The content: `create_ad_user`, `create_ad_group`, `set_ad_account_state` (enable/disable), `unlock_ad_account`, `reset_ad_password`, `manage_ad_group_member` (`action: add|remove`), `move_ad_object`.

The frame (ADR-0014 §13–22): the tools are off by default through `WINRIG_ALLOW_AD_WRITE`, and while they are off the server does not declare them. A confirmation by DR-5 holds the DN in the text. One object for each call, and no operation by a filter. The server rejects protected objects before the network. The server redacts a password in the reply and always in the audit log. The documentation names the remaining exposure in the logs of the domain controller. A password change and an account creation need a secure channel. An account creation makes the account disabled in an explicit OU. The audit log shows the old value and the new value.

The slice is risky and does not come into the first wave by the decision of the operator. An account creation and each item that gives rights carry a risk of an immediate compromise of the domain. There is no reason to add them together with the read.

## W21. Attribute editing by rules

Goal: an edit of an arbitrary field of the directory where it is safe, and a refusal where it is not.

The content: `set_ad_attribute`, `clear_ad_attribute`.

The "rules" in the statement are a configuration, not the text of a tool description. `WINRIG_AD_WRITABLE_ATTRIBUTES` works as `WINRIG_ALLOWED_HOSTS` and `WINRIG_ALLOWED_COMMANDS`. An unconditional ban lies above it on the attributes that seize the domain in one call (TR-AD-10). An empty list means any attribute except those forbidden. This is a recognized refusal by the operator of the other guarantees, the same wording as for an empty `WINRIG_ALLOWED_COMMANDS` in ADR-0013.

## W22. Safe defaults and protected host roots

Goal: close four holes that a review of the revision `b79f60f` found, without a change of the architecture (ADR-0015, Q-16).

The content:

- **TR-SEC-12.** `ps::escape` doubles all five forms of the PowerShell single quote. The test passed over the `server.rs` scripts that reached the fake host. Before the correction it failed on `‘` in all the tools of services, the registry and the delete.
- **TR-SEC-13.** `connect` on the header path opens a session only with the password from the same request.
- **TR-SEC-14, TR-SEC-06, TR-PRF-17.** An empty host list gives only loopback, and `*` gives any host. `WINRIG_ALLOW_INSECURE_TLS` is `false` by default. `setup --allowed-hosts` writes the list into the client entry.
- **TR-FS-06, TR-SEC-04.** The scans of `write_file`, `delete_file` and `delete_directory` return the roots from the system variables of the host. The slice moved the scans from `server.rs` into the generators of `ps.rs`.
- **TR-OBS-03.** The audit log records the policy refusals with the entry `POLICY REFUSED`.

A mutation check: a disable of the root check fails three tests of the policy. A removal of the audit call fails the audit test on its level.

An independent review of the first draft of the slice returned it with two blockers. The host `evil.com/.corp.example` bypassed the suffix list, because `winrm-rs` cuts the string at `/`. The 8.3 names bypassed both the lexical list and the host roots. The slice closes both (ADR-0015 §7a, §13a) together with the remarks. The remarks hold a common grammar of the list with a start refusal and the administrative share as a local path. They hold the answer "a password is necessary" before the exposure of a foreign lockout. A second round found a bypass through the share `ADMIN$`, and the slice closes it together with `PRINT$`, `SYSVOL` and `NETLOGON`. A third round gave the verdict "accepted".

Remaining risks (ADR-0015): an open session runs commands without a second password. A junction and a symlink in the parents of a write target stay unrevealed. Not verifiable by an automatic test: the behavior of `GetUnresolvedProviderPathFromPSPath` and of the environment variables on a live host (Q-08).
