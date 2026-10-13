# ADR-0007 — Stack: `winrm-rs`, `rmcp`, `axum`, `tokio`

- Status: accepted
- Date: 2026-09-19
- Related: AGENTS.md §2, §5

## Context

The project needs an MCP server in Rust with remote PowerShell execution over WinRM/NTLM. The key requirements are a minimum of dependencies, low memory use, speed and no container. An own implementation of NTLM and WS-Management would be a large source of security risk.

## Decision

1. **WinRM/NTLM — the crate `winrm-rs`** (async, NTLMv2, `secrecy::SecretString`, `run_powershell`, the reuse of the shell). The project does not write an own implementation of SOAP+NTLM.
   - The version is `1.2.2`. The pin `=1.1.2` stayed while the branch 1.2.x needed rustc 1.98, which stable did not have. Version 1.98 came out on 2026-09-01, and the project removed the pin together with the rise of the MSRV to 1.98 (Q-07, slice W18). The check at the change: `auth/ntlm.rs` is identical between the versions, so the analysis of errors in `session::classify_auth_failure` (TR-SEC-10) stays correct. `CHUNK_SIZE` is still 2000, so `ps::WRITE_CHUNK_BYTES` needed no change.
   - The default output encoding is `65001` (UTF-8), so the preamble `[Console]::OutputEncoding` from the Python version is not necessary.
2. **MCP — the official SDK `rmcp`** with the transport `transport-streamable-http-server`; the macros `#[tool]`/`#[tool_router]`.
3. **HTTP — `axum`**; the MCP service embeds through `nest_service("/mcp", service)`.
4. **Runtime — `tokio`** (multi-thread).
5. **Identity — `http::request::Parts`** from the request extensions of `rmcp`; the headers of the current request are available in the context of the tool (DR-2). In stdio the identity comes from the profile (ADR-0009).
6. **The project does not use a container.** The deploy is one release binary in two modes, `serve` and `stdio` (ADR-0009).

## Consequences

- The project limits the set of dependencies to the transport layer and the MCP layer; there are no heavy frameworks.
- Kerberos and CredSSP (`winrm-rs`) are off by default: a feature turns them on only when necessary. CredSSP pulls in OpenSSL and the author marks it as a preview.
- The project introduces capabilities that `rmcp` does not have (for example, a different confirmation method) only through a new ADR.
