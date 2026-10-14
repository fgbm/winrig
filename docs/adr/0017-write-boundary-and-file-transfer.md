# ADR-0017 — Write boundary and file transfer

- Status: accepted
- Date: 2026-10-14
- Related: ADR-0003, ADR-0005, ADR-0006, ADR-0008, ADR-0009, ADR-0013, ADR-0015, DR-3, DR-4, DR-5, DR-6, DR-7

## Context

Release 0.3.0 gives the operator more freedom of action on the host. The operator runs commands and scripts, writes and copies files, and transfers files in both directions. The operator decided this scope:

- GitHub #14 (`run_command` and the allowlist form);
- GitHub #13 (an operator allowlist of write paths);
- GitHub #12 (copy, move, rename and create a directory);
- GitHub #11 (file transfer in both directions).

ADR-0013 added `run_command` and `write_file`, and it left two things open. First, `write_file` refuses every path under the protected roots. The operator cannot permit a legitimate target, for example a database under `C:\ProgramData` or a drop-in directory under `C:\Program Files`. Second, ADR-0013 named the composition of `write_file` and `run_command`, but the product had no tool that runs a script as one operation. ADR-0013 §17 also named the absence of a download tool.

The operator's decision:

- The write boundary is an operator allowlist of write paths (`WINRIG_WRITE_ALLOW_PATHS`).
- The operator sets the allowed write paths only through an environment variable.
- System directories and volume roots have no hard ban. A read or a download from a system directory must work. A write or a copy into a system directory or a volume root works when the allowlist covers the path. Every doubtful action goes through the confirmation of DR-5. The prompt shows the operation and the resolved source and destination. It shows the size, the overwrite state, the host and the user. It also shows the warning for a system directory or a volume root and the effect line (W32 format). DR-6 is unchanged.
- `WINRIG_ALLOWED_COMMANDS` stays as ADR-0013 §13 defines it. An empty list means any command. `WINRIG_CONFIRM_FALLBACK` stays as ADR-0013 §19 defines it, with the default `refuse`.
- Every new capability is off by default and hidden from the tool list until its environment flag enables it.

The file transfer adds a write on the local side, on the computer that runs winrig. This is a new class of write, and AGENTS.md §4 must name it.

## Decision

### General

1. The scope of this ADR is six capabilities: `run_command` (W16, ADR-0013), `run_script` (new), the write allowlist, the file operations `copy_file`/`move_file`/`rename_file`/`create_directory`, a download, and an upload.
2. Each new modifying tool obeys DR-5. The confirmation is mandatory, and the absence of a confirmation channel is a refusal. `WINRIG_CONFIRM_FALLBACK` applies as ADR-0013 §19 defines it.
3. Each new capability is off by default and is not declared to the agent while it is off. The flags are in the table below.
4. The write allowlist is set only by the operator, through the environment.
5. DR-4 holds for every new tool. The content of a file, the text of a command and the text of a script never go into the audit log. The paths, the sizes and the hashes do.
6. DR-6 is unchanged. A recursive deletion still refuses a volume root, a system directory and a reparse point in any form of the path. The allowlist does not lift these refusals.

The new settings:

| Variable | Default | Purpose |
|---|---|---|
| `WINRIG_WRITE_ALLOW_PATHS` | empty | the operator allowlist of write paths (ADR-0017 §7) |
| `WINRIG_ALLOW_SCRIPT_EXEC` | `false` | enables `run_script` |
| `WINRIG_ALLOW_FILE_OPS` | `false` | enables `copy_file`, `move_file`, `rename_file` and `create_directory` |
| `WINRIG_ALLOW_FILE_DOWNLOAD` | `false` | enables `download_file` |
| `WINRIG_ALLOW_FILE_UPLOAD` | `false` | enables `upload_file` |
| `WINRIG_TRANSFER_DIR` | the transfer subdirectory of the state directory | the local endpoint of the file transfer |
| `WINRIG_MAX_TRANSFER_BYTES` | 256 MiB | the size ceiling of one download or upload |

### The write allowlist

7. **Semantics.** `WINRIG_WRITE_ALLOW_PATHS` is a comma-separated list of directories. An entry permits a target that lies inside it. The code normalizes the target and the entry with `policy::normalize_windows_path` (ADR-0003, ADR-0015 §10) and folds the case. A match is a prefix at a component boundary: `C:\ProgramData\Vendor` matches `C:\ProgramData\Vendor\db.sqlite` and does not match `C:\ProgramData\VendorX\db.sqlite`. An empty list keeps the current behavior: the protected roots stay closed.
8. **Two resolutions.** The code checks both resolutions of the target, as TR-FS-06 requires. An entry must cover the resolved path, not the requested text.
9. **The effect.** An entry lifts two refusals for the write-side file tools. The first is the lexical refusal of `PROTECTED_DIRS`. The second is the refusal of the roots that the host resolved (ADR-0015 §10). The tools are `write_file`, `copy_file`, `move_file`, `rename_file`, `create_directory` and `delete_file`.
10. **The refusals that stay.** Two refusals are bypass protections, not bans, and the allowlist does not lift them. A path with a component in the 8.3 form stays refused (TR-SEC-04, AC-SEC04-6). A target whose final component is a reparse point stays refused, because the write would leave the allowlisted directory. A junction or a symlink in a parent directory stays the named residual risk of ADR-0015.
11. **A system directory and a volume root are permitted.** The operator may put a system directory or a volume root into the allowlist. The code does not refuse such an entry at startup. The confirmation then carries an explicit warning line (§36).
12. **Precedence.** The lexical list `PROTECTED_DIRS` acts first, before the network, as before. The allowlist is the operator exception on top of it. A refusal that no entry covers stays a `POLICY REFUSED` audit entry (TR-OBS-03).
13. **The recursive deletion.** `delete_directory` does not consult the allowlist. DR-6 keeps its refusals in full.

### File operations

14. **The four tools.** `copy_file(source, target, overwrite=false)`, `move_file(source, target, overwrite=false)`, `rename_file(path, new_name, overwrite=false)` and `create_directory(path)`. All four are modifying and obey DR-5.
15. **An overwrite only with an explicit flag.** Without `overwrite: true` the server refuses a target that exists, before the call to the host. The server refuses an overwrite of an existing directory in all cases: the operator deletes the target first with `delete_directory`, which has the DR-6 protection.
16. **The target boundary.** The server checks the target against the write allowlist and the protected roots, as §9. The server does not refuse a source under a protected root: a read from a system directory must work.
17. **`copy_file` copies a directory recursively.** The prompt shows the counts of the files, the directories and the bytes from a scan of the host. A copy of a single file shows the size.
18. **`move_file` stays conservative.** On one volume the host renames the object. A directory move is then a rename, with no recursion. Across volumes the server copies the object and then deletes the source. For a file this is a copy and a delete. The server refuses a cross-volume move of a directory: the implied recursive delete falls under DR-6, and a partial move leaves two trees. The operator copies the directory and deletes the source with two calls.
19. **`rename_file` changes the last component.** The tool renames the object inside its own directory. A move to another directory is `move_file`. A rename stays on one volume.
20. **`create_directory` makes the missing parents.** The tool creates the final directory and each missing parent. The prompt shows the resolved path and the count of the created levels. Every created level must lie inside the write boundary.

### File transfer: the local side

21. **The local endpoint.** `WINRIG_TRANSFER_DIR` is a directory on the computer that runs winrig. In stdio mode the operator uses it directly. In HTTP mode the server isolates each user (DR-3) in a subdirectory `<WINRIG_TRANSFER_DIR>/<canonical-user>/`. A tool takes a relative name only. The server refuses a name with a separator escape, a `..` component or a resolved path outside the user directory. The server also refuses a symlink that leaves the directory.
22. **The private modes.** The transfer directory and its files use the modes of `src/private_fs.rs` (`0700`/`0600` on Unix, ADR-0009).
23. **A new local write.** The transfer is a write on the local filesystem. AGENTS.md §4 names it as an exception beside the client configuration write.
24. **The download.** `download_file(remote_path, name, overwrite=false)` reads the file on the host in chunks. Each chunk comes through a raw channel, not through the text reply of the tool. Therefore the 60 000-character truncation of the reply does not apply (ADR-0013 §17). The host reads the file with a shared read, so a file that another process holds open still works. The server writes the chunks into the transfer directory and compares the SHA-256 of the two sides. The reply carries the name, the size and the hash, not the content.
25. **The size ceiling.** `WINRIG_MAX_TRANSFER_BYTES` (default 256 MiB) refuses a larger file before the read. A resume of an interrupted transfer is not required.
26. **The upload.** `upload_file(name, remote_path, overwrite=false)` reads the file from the transfer directory and writes it to the host with the chunked mechanism of `write_file` (TR-FS-05): a temporary file and a rename. The server checks the SHA-256 of the two sides. The write allowlist, the protected-root refusal and the confirmation of `write_file` apply.
27. **No inline content.** A small file does not go into the tool result as base64. Every file goes into `WINRIG_TRANSFER_DIR`, and the reply carries the name, the size and the hash. Reason: the reply of the agent must not carry the content of a binary file, and one route keeps the redaction and the audit simple.
28. **Every download needs a confirmation.** A download moves data off the host, and the data may be personal. The confirmation holds the resolved remote path, the size, the hash and the local destination. A download under a protected or a system path carries the warning line of §36.

### `run_script`

29. **The tool.** `run_script(script, timeout_seconds=0)` runs a PowerShell script that is longer than one WinRS command line (ADR-0013 §16). The tool is decided here, not as an amendment to ADR-0013. Reason: the composition writes a file, runs it and deletes it, and this ADR owns the write mechanism and the write boundary. ADR-0013 receives a pointer.
30. **One confirmation.** The tool asks one confirmation for the whole operation: the upload of the script, the run and the delete of the temporary file. The prompt shows the whole script.
31. **The temporary file.** The server writes the script into a temporary `.ps1` in the session temp directory (`$env:TEMP`) with a random name. The file goes in chunks through the mechanism of `write_file`. The server deletes the file after the run and on every failure or timeout.
32. **The staging write.** The temporary file is the staging of the tool, not a target of the operator. The write boundary and the protected-root refusal do not apply to it. The confirmation names the path, and the audit records it.
33. **The size and the output.** The script obeys `WINRIG_MAX_WRITE_BYTES` (ADR-0013 §11). The output obeys the limits of `run_command`: `MAX_OUTPUT_CHARS` in the reply and `WINRIG_AUDIT_MAX_OUTPUT_CHARS` in the audit.
34. **The allowlist.** `run_script` is enabled by `WINRIG_ALLOW_SCRIPT_EXEC` alone. The prefix list `WINRIG_ALLOWED_COMMANDS` does not filter the script, because the server cannot prefix-check the text of a script in a meaningful way. The confirmation states this.

### The confirmation text

35. **The W32 format.** Every new modifying tool shows the host, the identity (the user of the request) and the tool. It shows the resolved source and destination, the size or the counts, the overwrite state and the effect line. The table below is the per-tool list.
36. **The warning line.** When the target lies in a system directory or is a volume root, the confirmation carries one explicit warning line that names the class.
37. **The body in full.** The text of a command and the text of a script appear in full, without truncation. The 200-character cap of TR-SEC-19 applies to the other fields, not to the body. Reason: the operator confirms what will run, and a cut script would confirm a different operation.

The per-tool list:

| Tool | Target | Details before the call | Undo |
|---|---|---|---|
| `run_command` | the host | the full command text | no |
| `run_script` | the host | the full script text and the temporary path | no |
| `copy_file` | the source and the target | the resolved paths, the counts of a directory copy, the overwrite state | no; the target is replaced |
| `move_file` | the source and the target | the resolved paths, the same-volume or cross-volume mode, the implied delete, the overwrite state | yes, by a move back |
| `rename_file` | the path and the new name | the resolved path and the new name, the overwrite state | yes, by a rename back |
| `create_directory` | the path | the resolved path and the count of the created levels | yes, by a delete |
| `download_file` | the remote path and the local destination | the resolved remote path, the size and the hash | no |
| `upload_file` | the local source and the remote path | the resolved remote path, the size and the hash, the overwrite state | no; the target is replaced |

### The audit

38. **The record.** Each new tool writes one audit entry. The entry holds the tool, the user, the host, the resolved paths and the result. It holds the size or the counts and the hash where it exists. It also holds the confirmation state, and it carries no content (DR-4).
39. **The exception.** An audit entry of a write under the allowlist names the entry that permitted it. Thus the log shows why a protected path was permitted.

## Consequences

- AGENTS.md §4 gains the local write of the file transfer as an exception.
- ADR-0013 receives a clarification: `write_file` consults the allowlist, and `run_script` lives in ADR-0017.
- `docs/REQUIREMENTS.md` receives TR and AC for each new tool, for the allowlist and for the confirmation text. The slices W33 to W38 in `docs/ROADMAP.md` carry them.
- The number of declared tools stops being a constant again. Each flag adds its tools, and the test of W9 must take every flag into account.
- The README table receives the new variables at implementation. The README marks each tool as modifying.
- The release is 0.3.0.
- **A residual risk, named directly.** The allowlist may cover a system directory or a volume root. The operator takes this decision, and the confirmation warns each time.
- **A residual risk, named directly.** A junction or a symlink in a parent directory of an allowlisted path stays unrevealed (ADR-0015). The code checks the final component (§10).
- **A residual risk, named directly.** The download moves data off the host into the transfer directory. The directory is private and isolated per user, and the audit records the path, the size and the hash.
