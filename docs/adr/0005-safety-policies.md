# ADR-0005 — Policies of lockout, redaction, allowlist and idempotency

- Status: accepted
- Date: 2026-09-19
- Related: ADR-0002, ADR-0004, `docs/QUESTIONS.md` Q-01..Q-04

## Context

The requirements fixed the behavior, but not the numeric values and the semantics. The operator confirmed the parameters in the Python version. The project moves them as a decision, so the code and the tests have a source.

## Decision

1. **Lockout (Q-01).** After `WINRIG_LOCKOUT_ATTEMPTS` (3) failures of **a specific password**, the server does not present that password again for that user during `WINRIG_LOCKOUT_WINDOW_SECONDS` (1800). The failure is deterministic and does not go to AD. The lockout applies per user. The presentation of **another** password is not locked out. The window counts from the failure that reached the threshold.
2. **Redaction (Q-02).** `WINRIG_SECRET_REDACT_MIN_LENGTH` (4) controls only the redaction of **the answer to the agent**: the server does not redact shorter values there, so the useful output stays correct. **The audit log obeys DR-4 without conditions**: on the audit path the server removes the secret at any length (`min_length=1`).
3. **Allowlist (Q-03).** `WINRIG_ALLOWED_HOSTS` is a comma-separated list. An element is an exact name or IP address, without case sensitivity. An element that starts with `.` is a suffix. An empty value allows everything.
4. **Idempotency (Q-04).** A repeated modifying call asks for confirmation again and applies the operation again. There is no automatic deduplication.
5. **The boundaries of path protection (DR-6).** The protected items are the roots of any volume and the system directories. The roots of volumes include `X:\` in any notation, with `\\?\`, `\??\` and `\\?\Volume{…}\`. The system directories are `C:\Windows`, `System32`, `Program Files`, `Program Files (x86)`, `Users` and `ProgramData`, and **all their subtree**. The **root of a UNC share** `\\server\share` is also protected, exactly at the level of the share. The normalization copies `ntpath.normpath` from the CPython standard library. The protection of an unusual notation depends on that normalization.

## Consequences

This is a reversible assumption: each parameter comes through the environment, and the operator can change the values without a release of the code.

## Addition (ADR-0009)

6. **Double lockout of the profile.** After the lockout window ends, the same password can reach the failure threshold again. If the password came from the profile, the profile goes to a failed state. In stdio the process stops with code 3. In HTTP each subsequent `connect` with the profile answers with an error and does not use the transport, until a restart of the process. A successful `connect` resets the count of consecutive lockouts. The behavior for a password from a header is the same as before: the client can change the password by hand.

## Clarification (ADR-0015)

§3: an empty list no longer allows everything. It allows only loopback literals (`localhost`, `127.0.0.0/8`, `::1`) without a DNS resolution. A separate element `*` allows any host. §5: apart from the lexical list, a write and a delete also check the path that the host resolved. The check uses the roots from its system variables (`SystemRoot`, `ProgramFiles`, `ProgramFiles(x86)`, `ProgramData`, the parent of `PUBLIC`). Windows on another volume is therefore also protected.
