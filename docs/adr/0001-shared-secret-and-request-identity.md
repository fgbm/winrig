# ADR-0001 — Shared secret before trust and identity on each request

- Status: accepted
- Date: 2026-09-19
- Related: AGENTS.md §3 DR-1, DR-2

## Context

The header `X-AD-User` names the caller. It is also the key of the password cache and of the connection pool. If the server trusts the header without a check, any caller that reaches the port can use the name of another user. That caller then gets the password and the sessions of that user.

## Decision

1. Each request must present the shared secret `WINRIG_AUTH_TOKEN`. The secret is in the `Authorization: Bearer` header or the `X-MCP-Token` header. The server does not start without the secret.
2. The server accepts `X-AD-User` only after a successful check of the secret. The comparison is constant-time (`subtle::ConstantTimeEq`).
3. The identity of the user comes from the headers of the current request. The identity does not come from the task that made the MCP session.

## Consequences

- A port without the secret is useless to an attacker.
- Each tool gets the identity from the current request (`src/identity.rs`). The server reads the headers from `http::request::Parts` in the request extensions of `rmcp`.
