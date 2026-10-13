# ADR-0009 — Account profile, CLI setup and stdio mode

- Status: accepted
- Date: 2026-09-20
- Related: ADR-0001, ADR-0004, ADR-0005, ADR-0006, ADR-0007, DR-1, DR-2, DR-4, DR-5

## Context

README offered to put the AD password as plain text in the configuration of each MCP client (`X-AD-Password` in `mcp.json`). This contradicts the goal "store the password nowhere as plain text": the client file goes into backups, synchronization and dotfiles repositories. The Python version gave the password through elicitation. ADR-0006 rejected this path: the MCP specification excludes secrets from elicitation, and revision `2026-07-28` deletes it.

The product is multi-user, but the usual local scenario is one account on one computer. The CLI setup must take the password one time and then show it to no operator, client or disk. The server must work from one binary both as an HTTP service (many projects) and as a local stdio process.

## Decision

1. **Account profile.** `winrig setup` takes a name of the form `DOMAIN\user` and a password without echo. The name is canonicalized as in `src/identity.rs`. The command generates a profile token from 32 random bytes. It writes one file per profile into the profile directory (`<name>.json`). The file holds the format version, the canonical name, the HKDF-SHA256 salt, the nonce and the authenticated XChaCha20-Poly1305 ciphertext. The account name is the AEAD associated data, so its substitution is detected. The command prints the profile token one time only. The server holds no key.
2. **Threat model.** The profile protects against the reading of the file, backups and the synchronization of client configurations. At rest on disk there is only ciphertext, and the key is at the client. The profile does **not** protect against an attacker who has access to the profile file and to the profile token under the same user. It also does not replace TLS. A leak of the bearer token on the network exposes the access to the server and the AD password.
3. **The secret is mandatory, but one of two.** Startup requires `WINRIG_AUTH_TOKEN` (the header path) or the profile token `WINRIG_TOKEN`. A match of `WINRIG_AUTH_TOKEN` with the profile token refuses startup: the profile key must not lie on the server.
4. **The offered secret determines the identity.** The profile token gives the profile identity. The server then ignores the `X-AD-*` headers with a warning, and it does not cache or log `X-AD-Password`. `WINRIG_AUTH_TOKEN` requires `X-AD-User`, as before (DR-1, DR-2). The profile token check after the first successful decryption is a comparison of an HMAC in constant time, without a second KDF.
5. **One profile per process.** One profile file, selected by name; with a single profile the name is optional, and with several profiles and no name startup refuses. The process holds a lock file in the state directory of the profile. A second process with the same profile refuses and advises the use of HTTP. Changes of the profile on disk apply from the next start.
6. **Directories.** Profiles use `platform-dirs`/`dirs-next` `config_dir` (`~/.config/winrig` on Linux, Roaming AppData on Windows, Application Support on macOS) with the override `WINRIG_PROFILE_DIR`. The state directory is `state_dir` with a fallback to the local data directory, and the override is `WINRIG_STATE_DIR`. Logs without `WINRIG_LOG_DIR` go to the profile subdirectory of the state directory.
7. **CLI.** The subcommands are `serve`, `stdio`, `setup`, `list`, `rotate` and `forget`. `setup` prints an MCP server JSON definition by default. With the flag `--write-config <client>` it writes that definition into the client configuration of opencode, Claude Code, Codex or Cursor. It does not touch other records. ADR-0012 defines the write scope (`--scope global|project`) and the project paths. For opencode the tool moves the profile token into a separate file with permissions `0600` and refers to it by `{file:...}`. `list` prints a table with the headings `NAME`, `USER`, `PATH`; `list --json` gives the same data in a machine-readable form. No format contains secrets.
8. **Double lockout of the profile.** A second set of the failure threshold with the same password in a new window turns the profile into a refusal state. In stdio the process exits with code 3. In HTTP the profile answers with an error without a call to the transport until a restart. A successful `connect` resets the count of consecutive lockouts.
9. **Permissions and errors.** Profile file permissions wider than `0600` on Unix give a warning, not a refusal. The log distinguishes "invalid token" and "damaged file"; the client gets 401 in both cases.
10. **TTL.** In the profile mode `WINRIG_PASSWORD_TTL_SECONDS` limits only the lifetime of the open password in memory. TTL does not cause a second input, because the password is restored from the profile.

## Consequences

- DR-1, DR-2 and DR-4 are restated in `AGENTS.md`. ADR-0004 receives a refinement: the profile file is not a configuration but a store of ciphertext, and the parameters still come from the environment.
- ADR-0005 §1 gains the rule of the double lockout of the profile. ADR-0007 §6 about systemd is removed: the project is cross-platform.
- New dependencies: `clap`, `rpassword`, `chacha20poly1305`, `hkdf`, `zeroize`, `rand`, `platform-dirs`. `cargo-deny` rejected `directories`: the transitive `option-ext` is under MPL-2.0, and this ADR does not weaken `deny.toml` for it.
- Modifying tools still require elicitation and stay fail-closed on clients without it (opencode 1.18.31 declares only `roots`). The README records this, and the roadmap holds it.
- The port of the 13 tools of the Python version, keyring and Docker stay outside the slice.
