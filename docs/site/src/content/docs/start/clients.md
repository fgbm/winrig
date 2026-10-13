---
title: Clients
description: Configure opencode, Claude Code, Codex or Cursor, and choose the stdio mode or the HTTP mode.
---

There are two request forms. With a profile token, the secret is the profile token and the identity comes from the profile, so the request does not need `X-AD-User`. With a shared secret, the request must carry `WINRIG_AUTH_TOKEN` and `X-AD-User`. The server checks the token before it trusts `X-AD-User`, because this header is the key of the password and session cache in memory.

## Write the configuration

`setup --write-config <client>` writes the MCP server definition into the client configuration. The flag requires a scope:

- `--scope global` writes the user configuration.
- `--scope project` writes the current repository. The project scope finds the nearest parent directory with `.git` (with a fallback to the current directory).

Supported clients: `opencode`, `claude-code`, `codex`, `cursor`.

```bash
./target/release/winrig setup corp --user 'DOMAIN\user' --write-config opencode --scope global
./target/release/winrig setup corp --user 'DOMAIN\user' --write-config claude-code --scope project
```

The server definition includes `WINRIG_TOKEN`, `WINRIG_PROFILE_DIR` and `WINRIG_STATE_DIR`. The client therefore finds the profile even with non-standard directories.

## opencode

`setup --write-config opencode --scope global` writes `~/.config/opencode/opencode.json`. The profile token comes from a private file:

```json
{
  "mcp": {
    "winrig": {
      "type": "local",
      "command": ["/path/to/winrig", "stdio", "--profile", "corp"],
      "environment": { "WINRIG_TOKEN": "{file:~/.config/opencode/winrig-token}" },
      "disabled": false
    }
  }
}
```

The profile token goes into a separate file `0600` and a reference `{file:...}` inserts it. The profile token therefore never sits inside the client configuration. At the project scope, this file lives in `WINRIG_STATE_DIR`, not in the repository.

## Claude Code

`setup --write-config claude-code --scope global` writes the block `mcpServers` of the file `~/.claude.json`. The equivalent through the CLI:

```bash
claude mcp add winrig -- /path/to/winrig stdio --profile corp
```

## Codex

`setup --write-config codex --scope global` writes `~/.codex/config.toml`:

```toml
[mcp_servers.winrig]
command = "/path/to/winrig"
args = ["stdio", "--profile", "corp"]

[mcp_servers.winrig.env]
WINRIG_TOKEN = "<token from setup>"
```

## Cursor

`setup --write-config cursor --scope global` writes the block `mcpServers` of `~/.cursor/mcp.json`.

:::note
For the other three clients, the profile token goes into the client configuration as a value. At the project scope, the project usually commits such a file, so `setup` prints a warning and sets the file mode to `0600` on Unix.
:::

## stdio or HTTP

The stdio mode serves one local client. The HTTP mode serves several projects at the endpoint `/mcp` (default `127.0.0.1:8005`). Any MCP client works the same way. Use the stdio definition that `setup` printed, or point the client at the streamable-HTTP endpoint. Pass `Authorization: Bearer <token>`.

:::danger
The bearer token is a key. Anyone who intercepts it reaches the server and decrypts the AD password. Do not bind to a non-loopback address without a TLS-terminating reverse proxy in front. See the [security model](/winrig/security/model/).
:::

## Confirmation on clients without elicitation

The modifying tools get confirmation through MCP elicitation. They fail closed when the client cannot ask. opencode 1.18.31 declares only `roots`. The modifying tools therefore refuse to work there and say so, rather than act without confirmation. The read-only tools work normally.
