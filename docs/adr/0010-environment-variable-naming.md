# ADR-0010 — Единая нотация переменных окружения `WINRIG_*`

- Статус: принято
- Дата: 2026-09-20
- Связано: ADR-0004, ADR-0009, DR-8, TR-PRF-01..10

## Контекст

Имена переменных сложились из двух источников и не имели единого вида: от Python-версии остались `MCP_AUTH_TOKEN`, `MCPO_PORT` (с опечаткой в порядке букв), `LOG_DIR`, `ALLOWED_HOSTS`, `SECRET_REDACT_MIN_LENGTH`, а от профиля пришли `WINRIG_TOKEN`, `WINRIG_PROFILE`, `WINRIG_PROFILE_DIR`, `WINRIG_STATE_DIR`. Один и тот же продукт читал переменные с тремя разными префиксами и без префикса вовсе, единицы измерения в именах были непоследовательны (`..._SECONDS` у одних, ничего у других), а `AD_` смешивал доменную область с областью процесса.

## Решение

1. **Единый префикс `WINRIG_`.** Все переменные окружения начинаются с `WINRIG_`. Профильные `WINRIG_TOKEN`, `WINRIG_PROFILE`, `WINRIG_PROFILE_DIR`, `WINRIG_STATE_DIR` уже соответствовали и сохранены.
2. **Полная карта переименования.**

   | Старое имя | Новое имя |
   |---|---|
   | `MCP_AUTH_TOKEN` | `WINRIG_AUTH_TOKEN` |
   | `MCP_BIND_HOST` | `WINRIG_BIND_HOST` |
   | `MCPO_PORT` | `WINRIG_PORT` |
   | `AD_PASSWORD_IDLE_TTL_SECONDS` | `WINRIG_PASSWORD_TTL_SECONDS` |
   | `LOG_DIR` | `WINRIG_LOG_DIR` |
   | `LOG_LEVEL` | `WINRIG_LOG_LEVEL` |
   | `LOG_MAX_BYTES` | `WINRIG_LOG_MAX_BYTES` |
   | `LOG_BACKUP_COUNT` | `WINRIG_LOG_BACKUP_COUNT` |
   | `AUDIT_MAX_OUTPUT_CHARS` | `WINRIG_AUDIT_MAX_OUTPUT_CHARS` |
   | `AUDIT_LOG_BODY` | `WINRIG_AUDIT_LOG_BODY` |
   | `CONFIRM_TIMEOUT_SECONDS` | `WINRIG_CONFIRM_TIMEOUT_SECONDS` |
   | `AD_LOCKOUT_MAX_ATTEMPTS` | `WINRIG_LOCKOUT_ATTEMPTS` |
   | `AD_LOCKOUT_WINDOW_SECONDS` | `WINRIG_LOCKOUT_WINDOW_SECONDS` |
   | `SECRET_REDACT_MIN_LENGTH` | `WINRIG_SECRET_REDACT_MIN_LENGTH` |
   | `ALLOWED_HOSTS` | `WINRIG_ALLOWED_HOSTS` |
   | `ALLOW_INSECURE_TLS` | `WINRIG_ALLOW_INSECURE_TLS` |
   | `SFTP_CRED_IDLE_TTL_SECONDS` | `WINRIG_SFTP_CRED_TTL_SECONDS` |

3. **Чистый разрыв, а не совместимость.** Старые имена не читаются. Если задано любое старое имя, старт отказывает (код 2) и сообщает полный список найденных пар `старое -> новое` (DR-8). Так оператор не может решить, что значение применилось, когда оно проигнорировано.
4. **Суффиксы приведены.** Убраны доменные и избыточные префиксы (`AD_`, `AUDIT_` сохранён как область, но под общим префиксом), единицы измерения оставлены в имени там, где это размерность (`_SECONDS`, `_BYTES`, `_CHARS`, `_COUNT`). Порядок слов — от общей области к частной: `WINRIG_LOG_MAX_BYTES`, а не `LOG_MAX_BYTES`.
5. **Флаги CLI перекрывают окружение.** `serve --port`/`--host` уже перекрывают `WINRIG_PORT`/`WINRIG_BIND_HOST`; правило «CLI > env» сохраняется.

## Последствия

- Таблица переменных в README и ADR-0004 приведены к новым именам; `AGENTS.md`, ADR-0001/0005/0008/0009, `docs/REQUIREMENTS.md`, `docs/QUESTIONS.md` и `docs/ROADMAP.md` синхронизированы.
- Обновлены живые конфиги: `.env` сервера и определения клиентов должны использовать новые имена. Определения, которые пишет `setup`, уже содержат `WINRIG_*` (ADR-0009), поэтому перегенерировать нужно только ручные записи.
- Постоянная таблица старых имён живёт в `src/config.rs::RENAMED_VARIABLES` и покрыта тестом: каждое старое имя даёт отказ с новым.
- Новые переменные вводятся только с префиксом `WINRIG_`; исключений нет.
