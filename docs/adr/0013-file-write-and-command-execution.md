# ADR-0013 — File write and execution of arbitrary commands

- Status: accepted
- Date: 2026-09-21
- Related: ADR-0002, ADR-0005, ADR-0006, ADR-0008, DR-5, Q-14

## Context

The product needs two capabilities that it does not have. It must write a file on the host. It must run an arbitrary command on the host. Until now all 37 tools carried prewritten PowerShell from `src/ps.rs`, and the file tools only read. `SessionRegistry::run_ps` stayed an internal method and did not go outside. The absence of arbitrary execution was not a decision of anyone: no ADR and no requirement declared it (Q-14).

The price is honest, and the decision must name it before, not after. Arbitrary execution goes around the other protections in one line. The host allowlist is checked at `connect`, and it does not touch the text of the command. The path protection `is_protected_path` lives inside `delete_file`/`delete_directory` and does not apply to what the operator writes in a script. The confirmation of modifying operations loses its sense if a tool that looks non-modifying can do anything. Thus the decision is not "add a tool". It is "add a tool together with a frame that keeps the other guarantees as far as possible".

A separate practical circumstance exists. The code implements the confirmation through elicitation. In clients without it (in particular opencode 1.18.31) the modifying tools stay fail-closed (ADR-0006, Q-10). A tool that strictly requires a confirmation does not work in such a client at all. This is not a reason to cancel the confirmation. It is a reason to give the operator an explicit way, written in the configuration, to take the risk on themselves.

## Decision

### General

1. **Both tools are modifying** and obey DR-5: the confirmation is mandatory, and the absence of a confirmation channel is a refusal, not a silent execution.
2. **Both are off by default.** `WINRIG_ALLOW_FILE_WRITE` and `WINRIG_ALLOW_COMMAND_EXEC` with the value `false`. The server does not declare a disabled tool in the tool list. The agent must not see a capability that it does not have, and must not build a plan on it.
3. **The redaction of secrets** follows the general rule (DR-4, TR-SEC-02). The body of the command and the contents of the file go through `redact` in the answer to the agent. They also go through `redact` unconditionally in the audit log.
4. **The audit log** writes separate events with the path or the text of the command. The existing `WINRIG_AUDIT_LOG_BODY` controls the appearance of the body in the audit log.

### `write_file`

5. **The path protection is reused.** A write at a path that `is_protected_path` considers protected is rejected before the call to the host — with the same list that guards deletion. A tool that can overwrite `C:\Windows\System32\...` is equivalent to deletion.
6. **An overwrite only with an explicit flag.** Without `overwrite: true` the server rejects a write into an existing file; this distinguishes creation from destruction and makes the intention visible in the confirmation.
7. **The default encoding is UTF-8 without a BOM**, as in `read_file`. Other encodings come from a parameter, from the same list that the read already takes.
8. **The write goes in pieces of 2000 bytes.** The script goes to the host as a command-line argument (`powershell.exe -EncodedCommand <base64>`), and WinRS limits the command line to about 8191 characters. The triple encoding gives about a 3.5-fold growth: base64 of the contents, then UTF-16LE of the script, then base64 for `-EncodedCommand`. Therefore less than 2 KB of raw data fits in one call. The same boundary and the same piece size exist in `winrm-rs::transfer` (`CHUNK_SIZE = 2000`), and the code chose them there for the same reason.
9. **The pieces go through the existing seam `run_ps`,** not through `WinrmClient::upload_file`. The input of the crate method is a local file, so the contents would first have to lie on the disk of winrig. That is an unnecessary leak for secrets. The method also goes past `SessionRegistry`, and thus past the audit log and the redaction of secrets. It also goes past the dummy transport on which all tests stand (AGENTS.md §4).
10. **The write goes into a temporary file next to the target, then the code renames the file.** The pieces are many, and a refusal in the middle would leave a cut file in the place of the real one. One `Move-Item -Force` replaces the target after the last piece; at a refusal the code deletes the temporary file, and the target stays untouched.
11. **The size limit** is `WINRIG_MAX_WRITE_BYTES`, by default 64 KiB. This is not a limit of the protocol, but a limit of patience. 2000 bytes for each call means 33 calls to the host for 64 KiB. `WinrmTransportImpl` creates a client for each call (Q-11). A megabyte would need more than five hundred calls and minutes of waiting. Large files are a task for `copy_file` and file transfer, not for this tool.

### `run_command`

12. **One form: PowerShell.** The code does not introduce a separate "run an exe with arguments": that is the same arbitrary run, but with a new escaping surface.
13. **The command allowlist.** `WINRIG_ALLOWED_COMMANDS` is a list of prefixes; an empty list means "any command", as in `WINRIG_ALLOWED_HOSTS`. A non-empty list rejects everything that does not begin with an allowed prefix, before the call to the host.
14. **The confirmation shows the full text of the command,** not its truncation: the operator confirms what will run.
15. **The timeout and the truncation of the output** come from the existing settings of the operation and `WINRIG_AUDIT_MAX_OUTPUT_CHARS`.

### Joint use

16. **A long script goes as a file and starts by name.** The WinRS limit of 8191 characters limits the command line, that is, the **input**. `write_file` puts a `.ps1` of any length on the host in pieces. `run_command` starts it with the short `& C:\Temp\job.ps1`, and the command line stays in the tens of characters. This is the standard way to run a script that does not fit in one call. The descriptions of both tools name it, so the agent does not invent it again. Thus the agent does not split the logic into disconnected commands.
17. **The output goes into a file for a different reason, and the reader must not mix it with the first.** The result comes back through the stream `Receive`, not through the command line: `winrm-rs` takes up to 64 MiB (`max_output_bytes`). winrig itself limits the output: `MAX_OUTPUT_CHARS = 60_000` characters in the answer to the agent, and `WINRIG_AUDIT_MAX_OUTPUT_CHARS` in the audit log. Therefore the route "the script writes the result into a file, then `read_file`" is justified for a result larger than 60 000 characters. It is also justified for long tasks that a separate call picks up. It is not justified "because the result does not fit in the command line in another way". The other side also has a ceiling: `read_file` gives no more than 500 lines for each call. A separate `download_file` does not exist, so a large file goes in ranges.
18. **The ADR admits: this composition breaks the command allowlist.** A non-empty `WINRIG_ALLOWED_COMMANDS` that allows the start of a script by path stops being a boundary. The name of the command is in the list, and the contents of the file are arbitrary. The same `write_file` changes the contents. The allowlist stays a protection from a random command, but not from an intention, and the documentation must describe it exactly so. The only setting that closes this path completely is `WINRIG_ALLOW_FILE_WRITE=false` with an enabled `run_command`, that is, the refusal of the composition itself.

### A client without elicitation

19. **`WINRIG_CONFIRM_FALLBACK` with the values `refuse` (default) and `proceed`.** With `proceed` the operation runs without a confirmation in exactly one case. The client did not declare elicitation at initialization, that is, the server has nothing to ask with. This is a conscious transfer of the risk to the operator, not a weakening of DR-5.
20. **The relaxation is tied to one error, not to the absence of an answer.** `rmcp` distinguishes the cases, and this distinction is important here:

    | Channel error | Meaning | With `proceed` |
    |---|---|---|
    | `CapabilityNotSupported` | the client did not declare elicitation | it runs |
    | `UserDeclined` | the user pressed "refuse" | refusal |
    | `UserCancelled` | the user closed the dialog | refusal |
    | `Service(Timeout)` | the channel was there, but no answer arrived | refusal (TR-REL-08) |
    | other errors | the state of the channel is unknown | refusal |

    The phrase "the user said no" and the phrase "there is nobody to ask" are different things, and no setting goes around the first.

21. **The area is all modifying tools, not only the two new ones.** Today in a client without elicitation `delete_file`, `kill_process`, `set_registry` and the others are equally dead. A setting with the area "only `run_command`" would mean that arbitrary execution is available, but a point deletion of a file is not. That is senseless, because the first includes the second.
22. **The audit log records the absence of a confirmation.** The event carries `confirmation=unsupported`, so that the log shows it. The operation went through the permanent agreement of the operator, not through the answer of a person at the moment.
23. **The setting names what replaces the confirmation.** In clients such as opencode a tool call goes through their own permission system. The permission uses keys of the form `winrig-tm_run_command` and values `ask`/`allow`/`deny`. winrig does not see this gate and cannot check it, so `proceed` is a statement of the operator that the gate is configured at the client. The documentation must also say the opposite. With `permission: "*": "allow"` nobody asks, and then an arbitrary command runs by the decision of the agent without the participation of a person.

## Consequences

- Q-14 is closed: the absence of arbitrary execution stops being an implicit property of the code.
- `docs/REQUIREMENTS.md` receives TR and AC for each of decisions 2, 5, 6, 8, 10 and 13. Exactly they form the subject of the check, and not the presence of the tool.
- The off state by default means that the number of declared tools stops being a constant. The test for the exact number of tools (W9) must take both settings into account.
- The ADR admits it directly. With `WINRIG_ALLOW_COMMAND_EXEC=true` and an empty `WINRIG_ALLOWED_COMMANDS` the path policy guarantees and the deletion protection guarantees stop being guarantees. They stay only for their own tools. This is a conscious choice of the operator, not a property that winrig keeps.
- `WINRIG_CONFIRM_FALLBACK=proceed` removes the fail-closed state from **all** modifying tools at once, including deletion. The combination is `proceed` + `WINRIG_ALLOW_COMMAND_EXEC=true` + an empty allowlist + `permission: allow` at the client. That combination means arbitrary execution on the host by the decision of the agent, without a single participation of a person. None of the four settings is on by default. The ADR names their joint meaning here, so that it does not collect in pieces from four places.
- Q-10 stops being blocking for operation: before the clients move to `input_required` the operator can work under their own responsibility instead of waiting. The move itself does not cancel this — with the appearance of the channel the server asks for the confirmation again, because `CapabilityNotSupported` stops occurring.
