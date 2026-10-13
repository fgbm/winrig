# Security policy

`winrig` administers Windows hosts over WinRM and keeps the AD password in memory. A vulnerability here is not a defect of a utility. A bearer token is a key that at the same time gives access to the server and decrypts the password. Reports receive serious attention and stay private until a fix goes out.

## How to report a vulnerability

Do not open a public issue. Use the private GitHub channel:

**[Report a vulnerability](https://github.com/fgbm/winrig/security/advisories/new)** (Security → Advisories → Report a vulnerability)

If the channel is not available, open an issue that says only that you have a vulnerability report. Ask for a private contact, and do not put details in the text of the issue.

Include:

- the version (a release tag or the output of `winrig --version`) and the platform;
- what the attacker gets — reads a secret, reaches a host outside `WINRIG_ALLOWED_HOSTS`, runs a modification without confirmation, bypasses the secret redaction, and so on;
- the smallest reproduction that you have, with secrets replaced by placeholders;
- whether the default configuration is affected or an environment variable must be set.

The documentation already names some missing protections as accepted (see *Boundaries* below). A report about them is a question about the documentation, not a vulnerability.

## What to expect

- **Acknowledgement** within 5 working days.
- **Assessment** within 10 working days: whether the report is accepted, the severity and an approximate fix time.
- **Coordinated disclosure.** A fix is prepared in private and released; the advisory names the version in which it went out. The author is credited, unless they ask for the opposite. There is no paid reward.

## Boundaries

Inside the boundaries is everything that violates the domain rules of the project (`AGENTS.md` §3 and `docs/REQUIREMENTS.md`):

- a secret appears in a log, the audit, a reply to the agent, the configuration or a commit. The secret can be the AD password, a bearer token, a profile token or a secret inside a command;
- a request gets trust before the check of its secret, or one operator reads the session or the password cache of another;
- a host is reached outside `WINRIG_ALLOWED_HOSTS`, or the TLS check is downgraded while `WINRIG_ALLOW_INSECURE_TLS=false`;
- a modifying tool runs without explicit confirmation, or runs at all when the client cannot ask (it must refuse, fail-closed);
- a deletion or `write_file` reaches a protected path, including through a junction or a symlink;
- a value from a tool argument goes into the text of PowerShell instead of going as data.

Deliberately outside the boundaries are the recorded decisions of the product, not defects:

- **Plain HTTP on `/mcp`.** The binary has no TLS listener by decision. A bearer token is a key, and a deployment must put a TLS-terminating reverse proxy in front (`README.md`, section "Transport security"). A start on a non-loopback address without a proxy is an operator error.
- **The first request on a new WinRM connection carries the body in plain text.** The NTLM session key does not exist until the handshake completes. This is a property of WinRM over port 5985, and for this reason the documentation recommends port 5986 (`README.md`, section "Transport security").
- **The profile file on the disk.** It holds only the authenticated ciphertext; the key lives at the client and is never stored together with it. An attacker who already has both the file and the profile token is outside the threat model.
- **A password that an operator passes as a command-line argument.** It is visible in the process list; the documentation tells you to prefer the environment or the client configuration.
- **Residual exposure that the documentation names**, for example an AD password that reaches the domain controller's own logs at a password change.

## Supported versions

Fixes go to `main` and go out under a tag. Security fixes do not move to earlier tags; update to the latest release. Development happens on `main`, so a report may ask you to reproduce on it.
