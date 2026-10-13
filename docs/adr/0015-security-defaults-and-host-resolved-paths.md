# ADR-0015 — PowerShell quotes, the password at `connect`, safe defaults and protected roots of the host

- Status: accepted
- Date: 2026-09-22
- Related: ADR-0001, ADR-0004, ADR-0005, ADR-0006, ADR-0008, ADR-0009, ADR-0012, ADR-0013, DR-3, DR-4, DR-6, DR-7

## Context

A review of the revision `b79f60f` found four holes that no previous slice closed:

1. `ps::escape` doubled only the ASCII apostrophe. PowerShell also counts `‘` U+2018, `’` U+2019, `‚` U+201A and `‛` U+201B as a single quote. Thus a path of the form `C:\x’; <command>; ’` closed the string and ran code through a tool that only reads, past the confirmation. The test `every_generator_escapes_single_quoted_free_text` checked only the ASCII quote and only the generators of `src/ps.rs`, and not the inline scripts of `src/server.rs`.
2. On the header path `connect` took the password from the cache by one name, `X-AD-User`. Any holder of the shared secret who gave another name without `X-AD-Password` opened a session with the password of another user. ADR-0001 closed this threat only from an external attacker.
3. An empty `WINRIG_ALLOWED_HOSTS` allowed any host, and `WINRIG_ALLOW_INSECURE_TLS` was `true` by default. An agent that received an instruction from data could call `connect` to a host of an attacker. That call would give the attacker the NTLMv2 answer of the domain account.
4. The path protection compared a string with a list where the system disk is fixed as `C:`. The protection did not cover Windows on another volume, and `write_file` did not ask the host at all.

## Decision

### PowerShell quotes (TR-SEC-12)

1. `ps::escape` doubles each of the five characters that PowerShell counts as a single quote: `'` U+0027, `‘` U+2018, `’` U+2019, `‚` U+201A, `‛` U+201B. The doubling of any of them inside a string in single quotes gives a literal character. Thus the value does not change, and the string does not close.
2. The test for the injection goes through all five characters. It covers not only the generators of `src/ps.rs`, but also the scripts that `src/server.rs` assembles.

### The password at `connect` (TR-SEC-13)

3. On the header path `connect` opens a session only with the password offered in `X-AD-Password` of the same request. A cached password by name is not sufficient. The refusal does not call the transport and does not move the lockout counter, because there was no password.
4. The profile path does not change: there the password comes together with the identity in each request.
5. `WINRIG_PASSWORD_TTL_SECONDS` keeps the previous behavior: an inactivity longer than TTL erases the password and closes the sessions of the user. Only the description changes: TTL no longer allows a call of `connect` without a password.

### Safe defaults (TR-SEC-14, TR-SEC-06)

6. An empty `WINRIG_ALLOWED_HOSTS` allows only loopback literals: `localhost`, the addresses `127.0.0.0/8` and `::1`, including in square brackets. The server does not resolve a name through DNS: a name that only points to loopback is not a loopback literal. This replaces ADR-0005 §3 in the part of the empty list.
7. The element `*` allows any host. It acts only as a separate element. The code does not introduce templates of the form `*.domain`, and an element with a leading dot still sets the suffix.
7a. The server rejects a host that is not a DNS name, an IP address or an IPv6 in square brackets, with any list, including `*`. `winrm-rs` cuts the string at `/`, `@`, `://` and `:port`, and the URL parser cuts at `?` and `#`. Thus `evil.com/.corp.example` matched the suffix `.corp.example`, and the connection together with the NTLMv2 answer went to `evil.com`. An independent review of the slice found this.
7b. The grammar of the list is the same for the variable and for `setup --allowed-hosts` (`policy::parse_allowed_hosts`). The code skips empty elements, and an invalid element in `WINRIG_ALLOWED_HOSTS` refuses startup with the name of the variable (DR-8). In the other case `*.corp.example` would silently allow nothing.
8. `WINRIG_ALLOW_INSECURE_TLS` is `false` by default. The default port, the derivation of `use_ssl` from the port and the format of `session_id` do not change.
9. `setup --write-config` takes `--allowed-hosts <comma-separated list>` with the same grammar as the variable, and writes `WINRIG_ALLOWED_HOSTS` into the server definition for all clients. A repeated `setup` without the flag removes the variable from the record: the server returns to the mode "only loopback".

### Protected roots of the host (TR-FS-06, TR-SEC-04)

10. Before the confirmation `write_file`, `delete_file` and `delete_directory` get the full path of the target and the protected roots. The protected roots come from the system variables of the host: `SystemRoot`, `ProgramFiles`, `ProgramFiles(x86)`, `ProgramData` and the parent of `PUBLIC` as the root of the profiles. The code rejects a path inside any root with the code `PATH_PROTECTED`. The deletion takes the path from `Get-Item`, as before. The write resolves the path two times, because it writes with two mechanisms. The pieces use .NET (`[IO.Path]::GetFullPath`, from the current directory of the process). The replacement of the target uses `Move-Item` (`GetUnresolvedProviderPathFromPSPath`, from the location of PowerShell). Both mechanisms work for a file that does not exist, and the code checks both.
11. The code skips an empty variable: `ProgramFiles(x86)` is absent on a 32-bit system lawfully. An empty `SystemRoot` is a refusal, because without it the check loses the main root.
12. The environment variables do not depend on the system language, so the check does not depend on the locale (AGENTS.md §6).
13. The lexical list `PROTECTED_DIRS` stays and acts first, before the network. The checks of the reparse points in `delete_directory` do not change.
13a. The write and the deletion reject a path with a component in the 8.3 form. `PROGRA~1` has a `~` after at least one character and before a digit. The rejection applies both in the requested form and in the form resolved by the host. The code cannot compare a short name with the list as a string, and only the host can expand it. The path resolution means from §10 do not expand short names.
13b. The code checks the administrative share `\\host\C$\...` by the lexical list and by the roots of the host as `C:\...`. The shares `ADMIN$` (this is `%SystemRoot%`), `PRINT$` (the driver directory inside it), and on a domain controller `SYSVOL` and `NETLOGON` (inside `%SystemRoot%\SYSVOL`) are protected completely.

### Audit log of refusals (TR-OBS-03)

14. A policy refusal goes into the audit log as a separate record `POLICY REFUSED`. The refusal covers a host, TLS, the absence of `X-AD-Password` and a protected path. The record holds the user, the tool, the refusal code and the reason. The record has no secrets.

## Consequences

- Compatibility breaks, so the release is 0.2.0. An empty `WINRIG_ALLOWED_HOSTS` no longer means "all hosts". The server rejects a call with `verify_cert=false` without an explicit `WINRIG_ALLOW_INSECURE_TLS=true`. The client records of the previous `setup` do not contain `WINRIG_ALLOWED_HOSTS`. `X-AD-Password` becomes mandatory for `connect` on the header path.
- ADR-0004 (the table of defaults), ADR-0005 §3 and §5, ADR-0006 §1 and ADR-0008 §1 receive a refinement from this decision.
- **A residual risk, named directly.** A session that is already open by the pair (user, `session_id`) runs commands without a second offer of the password. A holder of the shared secret can work in the session of another user while it is open, if the holder knows the `session_id`. Only a mandatory password in each request or a token for each operator closes this. Both variants are outside this decision.
- **A residual risk, named directly.** The resolution of a path normalizes it, but it does not expand a junction or a symlink in the parent directories. This decision does not catch a write into a directory that is in reality a reference to a protected root.
- **A residual risk, named directly.** On the header path the password from the request goes into the cache under the name `X-AD-User` before the checks. A change of the password in the cache closes the sessions of that name. A holder of the shared secret who gives another name with any password closes the sessions of another user. The holder also collects the failure counter of that user. This is a denial of service, not a capture. An open session holds its password, and the holder cannot open a new session without the correct password. The root of the risk is the same as in the first case: the name on the header path is not authenticated.
- **A residual risk, named directly.** Paths through `\\?\Volume{GUID}\...` and `\\?\GLOBALROOT\Device\...` do not reduce to a volume letter. Thus the code does not recognize the system directory lexically in such a record, and only the root of the volume is protected. This was so before this decision too.
- A refusal because of an unreadable scan or an empty `SystemRoot` does not go into the `POLICY REFUSED` audit log. That refusal comes from the host, not from the policy. The scan itself goes into the audit log as a command.
