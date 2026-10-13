---
title: Quick start
description: Create a profile, write the client configuration, and run the first read and modifying tools.
---

This procedure creates an encrypted profile, writes the client configuration, and runs the first tools. The example uses the account `contoso\alice` and the profile `corp`.

## 1. Build or install the server

Install a release binary, or build the project one time:

```bash
cargo build --release
```

## 2. Create the profile

Create an encrypted profile. The command reads the password without echo and prints the profile token exactly one time:

```bash
./target/release/winrig setup corp --user 'DOMAIN\user'
```

:::danger
The profile token decrypts the profile. Save it at once. `setup` shows it one time.
:::

## 3. Write the client configuration

Either insert the printed MCP server definition into the client by hand, or let `setup` write it:

```bash
./target/release/winrig setup corp --user 'DOMAIN\user' --write-config opencode --scope global
./target/release/winrig setup corp --user 'DOMAIN\user' --write-config claude-code --scope project
```

`--write-config` requires a scope: `--scope global` for the user configuration, or `--scope project` for the current repository. Without the flag, `setup` asks in the terminal. In a non-interactive run, `setup` refuses and points to `--scope`.

See [Clients](/winrig/start/clients/) for the exact configuration of each client.

:::caution
A second entry for one profile starts a second process. The second process loses the profile lock and exits, and the client reports only `MCP error -32000: Connection closed`.
:::

## 4. Start the server

Start the server in one of the two modes:

```bash
# Local stdio process for one client (the profile token comes from the client environment).
WINRIG_TOKEN='<token from setup>' ./target/release/winrig stdio --profile corp

# HTTP service at 127.0.0.1:8005/mcp for several projects.
WINRIG_TOKEN='<token from setup>' ./target/release/winrig serve --profile corp
```

The server needs at least one secret. It refuses to start if it has neither a profile token nor a shared secret.

## 5. Open the first session

In the client, call the tool `connect` with the host name and the account. The tool opens a WinRM session and returns a `session_id`. Use HTTPS port 5986 with `use_ssl` when the hop to the host needs encryption.

## 6. Run the first read tool

Call a read-only tool, for example `get_system_info` or `list_directory`. The server returns the result to the agent. A read-only tool needs no confirmation.

## 7. Run a modifying operation

Call a modifying tool, for example `restart_service`. The tool asks the operator for confirmation through MCP elicitation. It runs only after the explicit "yes". Without a confirmation channel, the tool refuses to run (fail-closed).

:::note
`write_file` is off by default. Set `WINRIG_ALLOW_FILE_WRITE=true` to declare it. See the [tool reference](/winrig/reference/tools/).
:::

The full list of the environment variables is in the [configuration reference](/winrig/reference/configuration/).
