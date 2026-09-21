# Security Policy

`winrig` administers Windows hosts over WinRM and holds an AD password in memory. A vulnerability here is not a bug in a utility: the bearer token is a key that both reaches the server and decrypts the password. Reports are taken seriously and handled privately until a fix ships.

## Reporting a vulnerability

Do not open a public issue. Use GitHub's private reporting channel:

**[Report a vulnerability](https://github.com/fgbm/winrig/security/advisories/new)** (Security → Advisories → Report a vulnerability)

If that channel is unavailable, open an issue that says only that you have a security report and ask for a private contact; do not include the details in the issue body.

Please include:

- the version (a release tag, or the output of `winrig --version`) and the platform;
- what an attacker gains — read a secret, reach a host outside `WINRIG_ALLOWED_HOSTS`, run an unconfirmed modification, escape redaction, and so on;
- the smallest reproduction you have, with secrets replaced by placeholders;
- whether the default configuration is affected or an environment variable must be set.

A report about a missing hardening measure that the documentation already names as accepted (see *Scope* below) is a documentation question, not a vulnerability.

## What to expect

- **Acknowledgement** within 5 working days.
- **Assessment** within 10 working days: whether it is accepted, its severity, and a rough fix timeline.
- **Coordinated disclosure.** A fix is prepared in private and released; the advisory names the version that fixes it. Credit is given unless you ask otherwise. There is no paid bounty.

## Scope

In scope — anything that breaks a Domain Rule of the project (`AGENTS.md` §3 and `docs/REQUIREMENTS.md`):

- a secret (AD password, bearer token, profile token, secret inside a command) reaching a log, the audit trail, a reply to the agent, a config file or a commit;
- a request being trusted before its secret is verified, or one operator reading another operator's session or password cache;
- a host reached outside `WINRIG_ALLOWED_HOSTS`, or TLS verification downgraded while `WINRIG_ALLOW_INSECURE_TLS=false`;
- a modifying tool executing without an explicit confirmation, or running at all when the client cannot prompt (it must fail closed);
- deletion or `write_file` escaping the protected-path list, including through a junction or symlink;
- a value from a tool argument escaping into the PowerShell command instead of being passed as data.

Explicitly out of scope — these are documented product decisions, not defects:

- **Plain HTTP on `/mcp`.** The binary has no TLS listener by design; the bearer token is a key and the deployment is required to put a TLS-terminating reverse proxy in front (`README.md`, *Transport security*). Running it on a non-loopback address without a proxy is an operator error.
- **The first request on a new WinRM connection carrying a cleartext body.** The NTLM session key does not exist until the handshake finishes; this is a property of WinRM over port 5985 and is why port 5986 is recommended (`README.md`, *Transport security*).
- **The profile file on disk.** It holds only authenticated ciphertext; the key lives with the client and is never stored with it. An attacker who already has both the file and the token is outside the threat model.
- **A password that an operator passes as a command-line argument.** It is visible in the process list; the documentation says to prefer the environment or the client config.
- **Residual exposure named in the documentation**, such as an AD password reaching the domain controller's own logs during a password reset.

## Supported versions

Fixes land on `main` and are released as a tag. Security fixes are not backported to earlier tags; upgrade to the latest release. Development happens on `main`, so a report may be asked to reproduce against it.
