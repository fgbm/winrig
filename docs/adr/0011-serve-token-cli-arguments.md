# ADR-0011 — CLI arguments can set the `serve` tokens

- Status: accepted
- Date: 2026-09-20
- Related: ADR-0001, ADR-0009, DR-1, DR-4

## Context

`serve` took secrets only from the environment (`WINRIG_TOKEN`, `WINRIG_AUTH_TOKEN`), but `--port`/`--host` already overrode the environment. The operator needed a way to give the profile token as an argument. Such a start occurs in a container, under a test supervisor or in one line without `export`. Many CLI servers do this (`--token`, `--api-key`).

The price of the arguments is known: the values of the arguments are visible in the process list (`ps`) and in the shell history. This is a conscious compromise, not a hidden leak, so the decision must name it.

## Decision

1. **`serve --token <TOKEN>`** sets the profile token and overrides `WINRIG_TOKEN`.
2. **`serve --auth-token <SECRET>`** sets the shared secret and overrides `WINRIG_AUTH_TOKEN`.
3. **Priority: CLI > env.** The server applies the flag after the reading of the configuration and before the check "at least one secret".
4. **The secret does not flow into diagnostics.** The code parses the argument into the type `SecretArg` with a manual `Debug` that prints `[REDACTED]`. Thus clap, the error messages and the logs do not expose the value. There is no direct logging of the value.
5. **Honesty in `--help`.** Both flags carry a warning: an argument secret is visible in the process list, and the operator must prefer the environment or the client configuration.
6. **Only `serve`.** The code leaves `stdio` as it is: there the profile token comes from the environment that the client of the start sets. The argument is not necessary. If necessary, a separate decision adds the flag.

## Consequences

- Coverage: `tests/cli_setup.rs::serve_token_flag_authenticates_profile` (the profile only by the flag), `serve_auth_token_flag_authenticates_header_path` (the header path only by the flag), `serve_token_flag_overrides_env` (the flag overrides an incorrect environment).
- The README received examples of both flags and a warning about the visibility in the process list.
- The code does not pass other secrets as arguments (`WINRIG_PASSWORD_TTL_SECONDS` is not a secret; the profile password is one). The operator enters the password in `setup`, or the password lies in the profile ciphertext. The server has no shared secret password.
