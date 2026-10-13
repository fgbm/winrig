# ADR-0006 — AD password through a header, elicitation only for confirmation

- Status: accepted
- Date: 2026-09-19
- Related: ADR-0001, ADR-0002, DR-1, DR-4, DR-5

## Context

The Python version asked for the AD password through MCP elicitation. The MCP specification states directly that elicitation is not for secrets, PII and credentials. Also, the protocol revision `2026-07-28` removes elicitation, and a client on that revision cannot enter a password. Elicitation as a confirmation channel for modifications (a boolean yes) stays permitted.

## Decision

1. The header `X-AD-Password` supplies the AD password, and the server keeps it in memory only, with an idle TTL. There is no separate request for a password through elicitation.
2. An elicitation request of the form `{ "confirm": bool }` confirms modifying operations. Only an explicit `true` is a confirmation.
3. If elicitation is not available, the server does not run the modifying operation and returns an answer with the `error` field (fail-closed, DR-5).

## Consequences

- The requirement of `X-AD-Password` makes the client setup a little more detailed. It removes the dependence on the protocol revision and does not pass the secret through a dialogue.
- Confirmation stays a channel that the client can revoke, without a weakening of the read-only tools.
- This is a difference from the Python version: there an operator could enter the password interactively; here only through a header.

## Clarification (ADR-0009)

The operator does not need to send the password in each request: `winrig setup` accepts it one time through the CLI and encrypts it into the profile. The client keeps the profile key. In the profile mode the server does not need `X-AD-Password` and ignores `X-AD-*`. The requirement "no secrets through elicitation" stays: the operator enters the password in the CLI, and elicitation stays only a channel for confirmation.

## Clarification (ADR-0015)

§1: on the header path `X-AD-Password` is obligatory for each `connect`. The password cache does not open a session from a name. The idle TTL still clears the password and closes the sessions of the user after inactivity.
