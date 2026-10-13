# English style guide (STE)

English text in winrig obeys ASD-STE100 Simplified Technical English, Issue 9. This guide is a project summary. It does not replace the standard. Get the full standard and the dictionary from the [ASD-STE100 website](https://www.asd-ste100.org).

This guide applies to documentation, ADRs, design documents and `README.md`. It also applies to UI text (MCP tool descriptions and tool parameter descriptions), CLI `--help`, error messages, log messages and commit messages.

This guide does not apply to code comments and doc comments. Those use plain short technical English. The rules are in AGENTS.md, section Code rules.

## 1. Words

1. Use words from the STE dictionary with their approved meaning only.
2. Use technical nouns and technical verbs from the [project glossary](#5-project-glossary) and from the field (for example "host", "session", "profile").
3. Use one word for one concept. Do not use synonyms.

<!-- vale off -->

4. Do not use phrasal verbs ("set up", "carry out"). Use one verb ("configure", "do").
5. Do not use contractions ("don't", "it's").
6. Do not use "please", "simply", "just", "easily" or "obviously".
7. Use "must" for a requirement. Do not use "should" for a requirement.

<!-- vale on -->

## 2. Sentences

1. A sentence in a procedure has 20 words or fewer.
2. A sentence in a description has 25 words or fewer.
3. A paragraph has 6 sentences or fewer.
4. Use the active voice. Write "The server sends the result", not "The result is sent".
5. Use the simple tenses: present, past, future.
6. Write one topic in each sentence.

## 3. Procedures

1. Write one instruction in each step.
2. Use the imperative: "Open the file".
3. If a condition applies, write the condition first: "If the agent is offline, do step 4".
4. Put a warning or a caution before the step that it applies to.
5. Number the steps.

## 4. Notes, warnings and cautions

| Type | Use |
|---|---|
| Warning | Risk of data loss or a security problem. |
| Caution | Risk of damage to the configuration or the service. |
| Note | Useful information. No risk. |

Write a warning as a short command, then the reason. Example: "Do not run `delete_directory` on a volume root. Data loss can occur."

## 5. Project glossary

<!-- vale off -->

| Term | Meaning | Do not use |
|---|---|---|
| host | The Windows computer that winrig connects to over WinRM | machine, remote server, target, node |
| computer | The operator's computer that runs winrig | machine, box |
| server | The winrig process (`serve` or `stdio`) | backend, daemon |
| client | The MCP client (Claude Code, OpenCode, Codex) | — |
| agent | The language model that calls tools through a client | bot, AI |
| operator | The person who uses the client and confirms operations | — |
| user | The AD account in whose name a tool runs (DR-2) | — |
| identity | The user that winrig gets from the secret of the request | principal, persona |
| account | An AD account | login (noun) |
| tool | An MCP tool of winrig (`connect`, `read_file`) | command (for this concept) |
| session | A WinRM session with a `session_id` | connection (for this concept) |
| connection | A TCP or HTTP connection | — |
| profile | The file with the password ciphertext (ADR-0009) | — |
| profile token | The secret from `setup` that decrypts the profile | key, token (alone) |
| shared secret | The value of `WINRIG_AUTH_TOKEN` for the header path | auth token (in text), token (alone) |
| secret | A password, a profile token or a shared secret | — |
| modifying operation | A tool call that changes the host (DR-5) | write operation, mutating, mutation |
| confirmation | The explicit "yes" of the operator before a modifying operation | approval, consent |
| host allowlist | The value of `WINRIG_ALLOWED_HOSTS` | whitelist, allow-list |
| command allowlist | The commands that `run_command` can run | whitelist |
| log | The operational log of the process (`WINRIG_LOG_*`) | — |
| audit log | The record of each tool call | audit trail |
| client configuration | The client file with the MCP server definition | config |
| directory | A file system directory | folder |
| share | An SMB share (`C$`, `ADMIN$`, `SYSVOL`) | — |
| reparse point | A junction or a symlink (DR-6) | — |
| domain controller | An AD domain controller | DC (in text) |
| lockout | The block on logon after `WINRIG_LOCKOUT_ATTEMPTS` failures | ban, block |
| slice | One unit of work in `docs/ROADMAP.md` | iteration, sprint |
| endpoint | The HTTP path `/mcp` | — |
| feature | A Cargo feature, for example `credssp` | — |

<!-- vale on -->

## 6. Review checklist

Use this checklist for each review of text:

- [ ] Each sentence has the correct maximum length.
- [ ] Each procedure step has one instruction in the imperative.
- [ ] The text uses the active voice.
- [ ] Each concept has one term from the glossary.
- [ ] There are no phrasal verbs, contractions or filler words.
- [ ] Warnings and cautions come before the steps.
- [ ] Vale shows no errors.
