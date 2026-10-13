---
title: Клиенты
description: Настройте opencode, Claude Code, Codex или Cursor и выберите режим stdio или HTTP.
---

Есть две формы запроса. С токеном профиля секрет — это токен профиля, а идентичность берётся из профиля, поэтому `X-AD-User` не нужен. С общим секретом запрос обязан нести `WINRIG_AUTH_TOKEN` и `X-AD-User`. Сервер проверяет токен прежде, чем доверяет `X-AD-User`: этот заголовок — ключ кэша паролей и сессий в памяти.

## Запишите конфигурацию

`setup --write-config <клиент>` записывает определение MCP-сервера в конфигурацию клиента. Флаг требует уровень:

- `--scope global` пишет пользовательскую конфигурацию.
- `--scope project` пишет текущий репозиторий. Project-уровень находит ближайший каталог-предок с `.git` (с откатом к текущему каталогу).

Поддерживаемые клиенты: `opencode`, `claude-code`, `codex`, `cursor`.

```bash
./target/release/winrig setup corp --user 'DOMAIN\user' --write-config opencode --scope global
./target/release/winrig setup corp --user 'DOMAIN\user' --write-config claude-code --scope project
```

Определение сервера включает `WINRIG_TOKEN`, `WINRIG_PROFILE_DIR` и `WINRIG_STATE_DIR`. Поэтому клиент находит профиль даже при нестандартных каталогах.

## opencode

`setup --write-config opencode --scope global` пишет `~/.config/opencode/opencode.json`. Токен профиля подставляется из приватного файла:

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

Токен профиля идёт в отдельный файл `0600`, а ссылка `{file:...}` подставляет его. Поэтому токен профиля никогда не лежит внутри конфигурации клиента. На project-уровне этот файл живёт в `WINRIG_STATE_DIR`, а не в репозитории.

## Claude Code

`setup --write-config claude-code --scope global` пишет блок `mcpServers` файла `~/.claude.json`. Эквивалент через CLI:

```bash
claude mcp add winrig -- /path/to/winrig stdio --profile corp
```

## Codex

`setup --write-config codex --scope global` пишет `~/.codex/config.toml`:

```toml
[mcp_servers.winrig]
command = "/path/to/winrig"
args = ["stdio", "--profile", "corp"]

[mcp_servers.winrig.env]
WINRIG_TOKEN = "<токен из setup>"
```

## Cursor

`setup --write-config cursor --scope global` пишет блок `mcpServers` файла `~/.cursor/mcp.json`.

:::note
Для остальных трёх клиентов токен профиля идёт в конфигурацию клиента значением. На project-уровне такой файл обычно коммитится, поэтому `setup` печатает предупреждение, а `winrig` выставляет файлу `0600` на Unix.
:::

## stdio или HTTP

Режим stdio обслуживает один локальный клиент. Режим HTTP обслуживает несколько проектов на конечной точке `/mcp` (по умолчанию `127.0.0.1:8005`). Любой MCP-клиент работает так же. Используйте stdio-определение, которое напечатал `setup`, либо направьте клиент на streamable-HTTP конечную точку. Передайте `Authorization: Bearer <token>`.

:::danger
Bearer-токен — это ключ. Кто его перехватит, тот достигнет сервера и расшифрует пароль AD. Не привязывайтесь к не-loopback адресу без TLS-терминирующего обратного прокси впереди. См. [модель безопасности](/winrig/ru/security/model/).
:::

## Подтверждения на клиентах без elicitation

Модифицирующие инструменты получают подтверждение через MCP elicitation. Они отказывают (fail-closed), когда клиент не может спросить. opencode 1.18.31 объявляет только `roots`. Поэтому модифицирующие инструменты отказываются там работать и говорят об этом, а не действуют без подтверждения. Инструменты только для чтения работают нормально.
