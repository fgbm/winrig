# ADR-0012 — The write scope of the client configuration: global or project

- Status: accepted
- Date: 2026-09-21
- Related: ADR-0009, DR-4

## Context

`setup --write-config <client>` always wrote the server definition into the global (user) client configuration: `~/.config/opencode/opencode.json`, `~/.claude.json`, `~/.codex/config.toml`, `~/.cursor/mcp.json`. This is wrong for a project that needs its own `winrig` on its own profile. The record acts on all projects of the computer, and several accounts in one global client file conflict by the name `winrig`. The clients support a project level: opencode uses `<project>/opencode.json`, Claude Code uses `<project>/.mcp.json`, Codex uses `<project>/.codex/config.toml` and Cursor uses `<project>/.cursor/mcp.json`.

The scope is a new dimension of the write, and the code does not derive it from the existing arguments by default. A silent choice of the global scope would repeat the previous behavior. It would contradict the expectation "my record is only in this project". Thus the operator sets the scope explicitly, and without the argument `setup` asks the operator.

## Decision

1. **The flag `--scope global|project`.** There is no default value: without the flag the code does not guess the scope.
2. **A question without the flag.** If the operator sets `--write-config` without `--scope`, and stdin is a terminal, `setup` asks `(g)lobal or (p)roject`. The code accepts `g`, `global`, `p` or `project` without attention to the letter case.
3. **Fail-closed without a terminal.** If stdin is not a terminal (a script, CI or a pipeline), the same case is a refusal. The message names `--scope global|project`. An automatic choice (even global) is forbidden: a silent write into the wrong place costs more than an explicit refusal.
4. **`setup` rejects `--scope` without `--write-config`.** There is nothing to write; this is a use error, not an ignored flag.
5. **The project root.** The project level writes into the nearest parent directory of the current directory that contains `.git`. The `.git` entry is a directory or a file of a worktree. If there is no such directory, the write goes into the current directory. Thus a start from a subdirectory of a monorepo arrives in the root of the repository.
6. **The project paths.** opencode uses `<root>/opencode.json`, Claude Code uses `<root>/.mcp.json`, Codex uses `<root>/.codex/config.toml` and Cursor uses `<root>/.cursor/mcp.json`. The global paths do not change.
7. **The opencode profile token at the project level** goes into the private state directory of the profile (`WINRIG_STATE_DIR`, file `0600`). The configuration refers to the absolute path `{file:...}`. The profile token file must not lie in the repository tree. The global opencode keeps the previous position of the profile token next to the global configuration.
8. **A warning about the inline profile token.** Claude Code, Codex and Cursor write the profile token as a value. At the project level the file usually goes into a commit. Thus after the write `setup` prints a warning that the configuration can go into the version control system. The code still makes the file `0600` on Unix. Opencode does not need the warning.
9. **A check before the creation of the profile.** The code resolves the scope (flag, question or refusal) before `profile::create`: a refusal leaves no created profile behind.

## Consequences

- ADR-0009 §7 gains a note: `--write-config` has a scope, not only a client.
- The README received a table of the project paths, the behavior of the prompt and the non-interactive refusal.
- Coverage: `client_config::tests` covers the project root, the project paths and the opencode profile token in the state directory. `app::tests` covers the resolution of the scope. `tests/cli_setup.rs` covers a project write, the refusals without the flag and without `--write-config`, and the warning.
- Clients whose project configuration goes into a commit stay a place for the inline profile token. This is an accepted compromise, and the warning names it.
- Outside the slice: the opencode V2 schema (`mcp.servers`), the "local" scope of Claude Code on the project path, and an environment variable for the scope.
