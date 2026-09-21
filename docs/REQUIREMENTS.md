# docs/REQUIREMENTS.md — требования и критерии приёмки

Артефакт переносит в репозиторий `winrig` требования и критерии приёмки Python-версии. Идентификаторы `TR-*` и `AC-*` — стабильные.

## 1. Goal

Сервер выполняет операции предсказуемо и безопасно: не создаёт риска блокировки доменных учёток, не раскрывает секреты, не позволяет обойти защиту разрушительных операций, не деградирует под одним долгим запросом.

## 2. Требования

| ID | Требование |
|---|---|
| TR-SEC-01 | Заведомо отклонённый пароль не предъявляется повторно в окне блокировки; отказ без обращения к AD |
| TR-SEC-02 | Секрет и его производные формы не попадают в логи, аудит и конфигурацию. Аудит — безусловно и при любой длине (DR-4); порог `WINRIG_SECRET_REDACT_MIN_LENGTH` ограничивает только правку ответа агенту |
| TR-SEC-03 | Редактирование не искажает вывод при коротком/пустом секрете |
| TR-SEC-04 | Рекурсивное удаление отказывает для корней, системных каталогов и точек повторной обработки в любой форме записи пути, включая вложенные точки и момент удаления |
| TR-SEC-05 | Множество разрешённых хостов настраивается; недопустимый порт отвергается |
| TR-SEC-06 | Понижение проверки TLS управляется конфигурацией |
| TR-SEC-07 | Идентичность — по текущему запросу; кэши изолированы по пользователю; имя учётной записи канонизируется по регистру |
| TR-SEC-08 | Заголовки произвольного HTTP-запроса, включая авторизационные, редактируются в аудите. Требование относится к непортированному `invoke_http_request` и пока не имеет покрытия; см. ROADMAP |
| TR-SEC-09 | Поля аудита и текст подтверждения не позволяют подделать свою структуру |
| TR-SEC-10 | Отвергнутый хостом запрос отделён от отказа учётных данных: он не сбрасывает кэш пароля и не двигает счётчик блокировки. Пустой `HTTP 500` объясняется как отказ в нешифрованном сообщении |
| TR-REL-01 | Один запрос не блокирует обслуживание остальных |
| TR-REL-02 | Снимок производительности работает при любой локали |
| TR-REL-03 | Неизвестный уровень журнала событий отвергается, а не расширяет выборку |
| TR-REL-04 | Фильтр по источнику не теряет события из-за лимита до фильтра |
| TR-REL-05 | Отсутствие текста события не приводит к ошибке |
| TR-REL-06 | Литеральные пути со служебными символами не трактуются как шаблон |
| TR-REL-07 | Невалидная конфигурация даёт понятный отказ при старте |
| TR-REL-08 | Запрос подтверждения не висит бесконечно: истечение таймаута — отказ (fail-closed) |
| TR-SEC-11 | `WINRIG_CONFIRM_FALLBACK=proceed` выполняет модифицирующую операцию без подтверждения только когда клиент не объявил elicitation; отказ пользователя, отмена, таймаут и ошибка транспорта не обходятся никогда, а аудит помечает операцию как прошедшую без подтверждения. Не реализовано — срез W16 |
| TR-FS-01 | `write_file` выключен по умолчанию (`WINRIG_ALLOW_FILE_WRITE`) и в выключенном виде не объявляется агенту. |
| TR-FS-02 | Запись по защищённому пути отвергается до обращения к хосту, тем же списком, что охраняет удаление. |
| TR-FS-03 | Перезапись существующего файла только при явном `overwrite`. |
| TR-FS-04 | Содержимое сверх `WINRIG_MAX_WRITE_BYTES` отвергается внятным отказом до обращения к хосту. |
| TR-FS-05 | Запись идёт кусками не больше 2000 байт (предел командной строки WinRS) во временный файл, и цель заменяется переименованием: отказ на середине не оставляет обрезанный файл на месте целевого. |
| TR-EXE-01 | `run_command` выключен по умолчанию (`WINRIG_ALLOW_COMMAND_EXEC`) и в выключенном виде не объявляется агенту. Не реализовано — срез W16 |
| TR-EXE-02 | Команда вне непустого `WINRIG_ALLOWED_COMMANDS` отвергается до обращения к хосту. Список защищает от случайной команды, но не от намерения: вместе с `write_file` он обходится запуском положенного скрипта (ADR-0013 §18). Не реализовано — срез W16 |
| TR-EXE-03 | Выполнение требует подтверждения. Отсутствие канала подтверждения — отказ, если оператор не выбрал `WINRIG_CONFIRM_FALLBACK=proceed`. Не реализовано — срез W16 |
| TR-EXE-04 | В подтверждении показан полный текст команды, без усечения. Не реализовано — срез W16 |
| TR-REL-09 | Канал подтверждения и вызов инструментов проверяются исполняемым тестом через MCP, а не чтением кода: согласие выполняет операцию, отказ и отсутствие канала — нет. Покрыта одна площадка `require_confirmation!` из десяти; макрос един, поэтому остальные держатся на нём, а не на отдельной проверке |
| TR-OBS-01 | Аудит содержит инициатора, хост, действие, результат, длительность; секретов нет. Длительность пока не записывается — вынесено в ROADMAP |
| TR-OBS-02 | Редактирование и защита путей покрыты автотестами |
| TR-PRF-01 | `setup` запрашивает имя AD (канонизируется как в `identity`) и пароль без эха, генерирует случайный токен и печатает его ровно один раз |
| TR-PRF-02 | На диске в каталоге профилей лежит только аутентифицированный шифртекст; ключ выводится из токена и на сервере не хранится |
| TR-PRF-03 | Старт требует хотя бы один секрет; совпадение `WINRIG_AUTH_TOKEN` с токеном профиля отказывает старту |
| TR-PRF-04 | Один файл профиля на профиль, выбор по имени; при единственном профиле имя необязательно, при нескольких без имени — отказ |
| TR-PRF-05 | stdio-режим берёт идентичность из профиля и токен из `WINRIG_TOKEN`; stdout содержит только JSON-RPC |
| TR-PRF-06 | HTTP-режим принимает токен профиля (идентичность профиля, `X-AD-*` игнорируются) либо `WINRIG_AUTH_TOKEN` (требует `X-AD-User`) |
| TR-PRF-07 | Проверка токена после первой расшифровки не дороже константного сравнения |
| TR-PRF-08 | Процесс держит lock-файл в каталоге состояния профиля; второй процесс с тем же профилем отказывает |
| TR-PRF-09 | Журналы без `WINRIG_LOG_DIR` идут в каталог состояния ОС в подкаталог профиля |
| TR-PRF-10 | Кэш, TTL, блокировка и редакция секретов работают для пароля из профиля как для заголовка; вторая блокировка подряд переводит профиль в отказ |
| TR-PRF-11 | `serve` принимает токены аргументами `--token`/`--auth-token`, перекрывающими окружение; секрет не попадает в диагностику |
| TR-PRF-12 | Учётная запись `DOMAIN\user` делится на имя и домен до NTLM; UPN и голое имя не делятся, регистр не меняется |
| TR-PRF-13 | `setup --write-config` требует уровень `--scope global|project`: без флага уровень спрашивается в терминале, в неинтерактивном запуске запись отказывает; project-уровень пишется в корень проекта |
| TR-PRF-14 | `setup --write-config` не создаёт вторую запись на тот же профиль: существующая обновляется на месте с сохранением ключа; ключ задаётся явно через `--server-name` |
| TR-PRF-15 | `WINRIG_STATE_DIR` в записи клиента — корень каталога состояния: каталог профиля собирается ровно один раз, и токен лежит в нём же |
| TR-PRF-16 | Учётная запись без `\` и без `@` не создаёт профиль молча: отказ называет ожидаемую форму `DOMAIN\user` |
| TR-AD-01 | AD-инструмент выполняется только на хосте с ролью контроллера домена; на рядовом хосте — отказ, называющий причину, а не ошибка каталога. Не реализовано — срез W19 |
| TR-AD-02 | Значение из аргумента не может изменить структуру LDAP-фильтра: экранирование по RFC 4515 предшествует экранированию PowerShell. Не реализовано — срез W19 |
| TR-AD-03 | Число возвращаемых объектов ограничено сверху; достижение потолка названо в ответе, а не молча обрезано. Не реализовано — срез W19 |
| TR-AD-04 | Разбор не зависит от локали хоста: время форматируется кодом, роль и состояние учётной записи читаются числом и битами, состояние репликации берётся классами `System.DirectoryServices.ActiveDirectory`, а не разбором вывода `repadmin`/`dcdiag`. Не реализовано — срез W19 |
| TR-AD-05 | Инструменты первой волны только читают: ни один из них не меняет каталог. Не реализовано — срез W19 |
| TR-AD-06 | Запись в каталог выключена по умолчанию (`WINRIG_ALLOW_AD_WRITE`); в выключенном виде инструменты записи не объявляются агенту. Не реализовано — срез W20 |
| TR-AD-07 | Каждая запись требует подтверждения (DR-5); в тексте подтверждения стоит DN объекта, а не `sAMAccountName`. Не реализовано — срез W20 |
| TR-AD-08 | Модификация адресует ровно один объект, названный явно; изменение по фильтру или по результату поиска не поддерживается. Не реализовано — срез W20 |
| TR-AD-09 | Защищённые объекты отвергаются до обращения к хосту: `krbtgt`, встроенный `Administrator`, Domain/Enterprise/Schema Admins и прочие объекты с `adminCount=1`, контейнер Domain Controllers, сам объект домена. Не реализовано — срез W20 |
| TR-AD-10 | Запись в `ntSecurityDescriptor`, `sIDHistory`, `msDS-AllowedToActOnBehalfOfOtherIdentity`, `servicePrincipalName`, в `unicodePwd` минуя инструмент пароля и в `member`/`memberOf` минуя инструмент членства запрещена безусловно и никаким списком не открывается. Не реализовано — срез W21 |
| TR-AD-11 | Запись атрибута вне непустого `WINRIG_AD_WRITABLE_ATTRIBUTES` отвергается до обращения к хосту. Пустой список означает «любой атрибут, кроме запрещённых TR-AD-10» и прямо назван как отказ оператора от остальных гарантий. Не реализовано — срез W21 |
| TR-AD-12 | Пароль из аргумента редактируется в ответе и безусловно в аудите (DR-4). Остаточная экспозиция названа в документации: пароль попадает в журналы самого контроллера домена, и winrig на это не влияет. Не реализовано — срез W20 |
| TR-AD-13 | Смена пароля и создание учётной записи требуют защищённого канала до контроллера домена; нешифрованное соединение — отказ. Не реализовано — срез W20 |
| TR-AD-14 | Создание учётной записи требует явно указанного OU и создаёт учётку отключённой, пока пароль не установлен. Не реализовано — срез W20 |
| TR-AD-15 | Аудит записи фиксирует DN, имя атрибута, прежнее и новое значение. Не реализовано — срез W20 |
| TR-AD-16 | Инструменты обслуживания только читают; изменение топологии (захват роли FSMO, чистка метаданных, принудительная репликация) и удаление объектов каталога в продукт не входят (ADR-0014 §12, §23) |

## 3. Критерии приёмки

| ID | Given/When | Then | Покрытие в winrig |
|---|---|---|---|
| AC-SEC01-1 | 3 отказа, 4-й `connect` тем же паролем в окне | отказ, ноль попыток транспорта, отдельная запись аудита | `session::tests::lockout_blocks_fourth_attempt_without_transport` |
| AC-SEC01-2 | после 3 отказов другой пароль | попытка доходит до транспорта | `session::tests::different_password_bypasses_lockout` |
| AC-SEC01-3 | A заблокирован, B с корректным паролем | B подключается, A остаётся заблокирован | `session::tests::sessions_are_isolated_per_user` + ключ по пользователю |
| AC-SEC01-4 | окно истекло | тот же пароль снова доходит до транспорта | `session::tests::lockout_window_expiry_allows_same_password_again` |
| AC-SEC01-5 | тот же пользователь в другом регистре после 3 отказов | остаётся заблокирован | `identity::tests::canonical_username_folds_case` |
| AC-SEC02-1 | секрет в команде | отсутствует в ответе агенту во всех формах; в аудите — безусловно | `session::tests::run_ps_redacts_secret_from_reply_and_audit`, `session::tests::run_ps_redacts_session_password_without_explicit_redactions`, `session::tests::command_audit_body_redacts_below_reply_threshold`, `session::tests::connect_failure_stderr_is_redacted` |
| AC-SEC03-1 | секрет < 4 символов | вывод не искажён | `executor::tests::secret_below_threshold_preserves_output` |
| AC-SEC03-2 | пустой секрет | редактирование no-op | `executor::tests::empty_secret_and_empty_list_are_noops` |
| AC-SEC04-1 | `C:/Windows`, `c:\windows\`, `\\?\C:\`, `F:\`, корень UNC | решение политики — отказ (что инструмент его вызывает, доказано чтением кода, не тестом) | `policy::tests::protected_*`, `policy::tests::delete_scan_refuses_host_resolved_protected_path` |
| AC-SEC04-2 | ReparsePoint (junction/symlink) в корне | отказ до удаления | `policy::tests::delete_scan_refuses_reparse_point` |
| AC-SEC04-3 | ReparsePoint внутри поддерева | отказ до удаления и повторная проверка в команде удаления | `policy::tests::delete_scan_refuses_nested_reparse_point`, генератор `delete_directory` |
| AC-SEC04-4 | путь без расширения разрешился в каталог (`delete_file`) | отказ | `policy::tests::file_delete_refuses_directory_and_protected_path` |
| AC-SEC05-1 | allowlist пуст | подключение разрешено | `policy::tests::host_allowed_variants` |
| AC-SEC05-2 | хост вне allowlist | отказ до сети | `policy::tests::decision_wrappers` |
| AC-SEC05-3 | порт вне 1..65535 | отказ до сети, сессия не создана | `policy::tests::validate_port_range_and_passthrough` |
| AC-SEC06-2 | `WINRIG_ALLOW_INSECURE_TLS=false` + `verify_cert=false` | отказ до сети | `policy::tests::tls_decisions` |
| AC-SEC07-1 | сессия A, запрос `X-AD-User: B` | видны только объекты B | `session::tests::sessions_are_isolated_per_user` |
| AC-SEC07-2 | запрос без `X-AD-User` на пути общего секрета | 401, инструменты не выполняются | `tests/http_gate.rs::request_with_token_but_without_user_is_rejected`, `tests/http_gate.rs::request_without_token_is_rejected` |
| AC-SEC08-1 | `Authorization` в аудите | в аудите отсутствует | **Не проверяемо**: инструмент `invoke_http_request` не портирован (TR-SEC-08) |
| AC-SEC09-1 | перевод строки в `X-AD-User` | аудит не подделан | `auth::tests::crlf_username_is_unsafe`; `executor::tests::escape_log_field_*` |
| AC-SEC09-2 | перевод строки в аргументе подтверждения | диалог не подделан | `executor::tests::sanitize_prompt_value_*` |
| AC-SEC10-1 | `AuthFailed("HTTP 500 Internal Server Error: ")` | не отказ учётных данных; текст называет 5986 и `AllowUnencrypted` | `session::tests::empty_500_is_not_an_auth_failure` |
| AC-SEC10-2 | `AuthFailed("HTTP 503 ...: busy")` | не отказ учётных данных; статус сохранён, подсказка не приписана | `session::tests::other_http_status_is_rejected_without_the_hint` |
| AC-SEC10-3 | `AuthFailed("NTLM authentication rejected ...")` | остаётся отказом учётных данных | `session::tests::ntlm_rejection_stays_an_auth_failure` |
| AC-SEC10-4 | шесть отвергнутых запросов профилем | кэш пароля цел, профиль не отвергнут, блокировка не включилась | `session::tests::rejected_request_keeps_cached_password`, `session::tests::rejected_request_never_refuses_profile` |
| AC-FS-01 | конфигурация по умолчанию | `write_file` не объявлен и маршрута не имеет; с `WINRIG_ALLOW_FILE_WRITE=true` появляется. На проводе 37 против 38 | `config::tests::defaults_are_applied`, `config::tests::file_write_is_switched_by_the_operator`, `server::tests::write_file_is_absent_until_the_operator_enables_it`, `server::tests::disabled_write_file_has_no_route`, `tests/stdio_mode.rs::write_file_appears_only_when_enabled` |
| AC-FS-02 | путь `C:\Windows\System32\config` | решение политики — отказ до сети, код `PATH_PROTECTED`, причина называет запись (вызов из инструмента доказан чтением кода) | `policy::tests::write_is_refused_on_protected_paths`, `policy::tests::write_refusal_names_writing`, `server::tests::policy_refuses_protected_write_before_transport` |
| AC-FS-03 | существующий файл без `overwrite` | отказ с кодом `FILE_EXISTS`, запись не начата; создание нового и явная перезапись проходят | `policy::tests::overwrite_is_required_only_for_an_existing_file` |
| AC-FS-06 | тело файла в команде | в аудит и ответ уходит отредактированным: редактируется аргумент `FromBase64String`, то есть ровно то, что в команде и лежит | `server::tests::base64_payload_is_extracted_for_redaction` |
| AC-FS-04 | содержимое больше `WINRIG_MAX_WRITE_BYTES` | отказ до сети, назван фактический размер и предел; счёт в байтах, не в символах | `ps::tests::plan_refuses_content_above_the_limit`, `ps::tests::plan_counts_bytes_not_characters`, `config::tests::max_write_bytes_must_hold_at_least_one_chunk` |
| AC-FS-05 | содержимое 5000 байт | три куска по 2000 плюс одна замена; первый кусок создаёт, прочие дописывают; кусок помещается в командную строку WinRS; цель заменяется переименованием при любой кодировке, а не пишется на месте; уборка достаёт оба временных файла; имя временного файла не повторяется между вызовами | `ps::tests::plan_splits_content_and_ends_with_one_commit`, `ps::tests::first_chunk_creates_and_the_rest_append`, `ps::tests::a_full_chunk_fits_the_winrs_command_line`, `ps::tests::commit_renames_for_utf8_and_converts_otherwise`, `ps::tests::commit_never_writes_the_target_in_place`, `ps::tests::abort_removes_the_temporary_file_quietly`, `ps::tests::abort_removes_the_staged_file_too`, `server::tests::temporary_suffix_differs_between_calls` |
| AC-REL03-1 | неизвестный `level` | ошибка со списком, команда не отправлена | `ps::tests::get_event_log_rejects_unknown_level` |
| AC-REL04-1 | источник задан | фильтр до лимита | `ps::tests::get_event_log_source_filter_does_not_precap` |
| AC-REL05-1 | событие с пустым сообщением | инструмент не падает | PS-команда `get_event_log` ветвится по `$_.Message` (живой хост — «не проверяемо», Q-08) |
| AC-REL06-1 | путь с `[` `]` | адресуется литерально | `-LiteralPath` во всех генераторах `ps.rs`; `ps::tests::registry_generators_use_literal_path` |
| AC-REL07-1 | `WINRIG_LOG_LEVEL=BOGUS` | код ≠ 0, названа переменная, без traceback | `config::tests::invalid_log_level_names_variable`; код 2 проверен прогоном бинаря, автотеста нет |
| AC-REL07-2 | нецелая целочисленная переменная | код ≠ 0, названа переменная | `config::tests::invalid_integer_names_variable` |
| AC-REL07-3 | все переменные корректны | старт успешен | `config::tests::defaults_preserved`, `tests/http_gate.rs` (initialize проходит `/mcp`) |
| AC-REL07-4 | `WINRIG_LOG_LEVEL=WARNING` | журнал не глушится: директива `warn` | `config::tests::log_level_filter_directives_match_env_filter_levels` |
| AC-REL07-5 | задано старое имя переменной (`MCPO_PORT`, `LOG_DIR`, …) | код 2, сообщение перечисляет `старое -> новое` | `config::tests::renamed_variables_are_rejected_with_the_new_name`, `config::tests::several_renamed_variables_are_listed_together`, `tests/cli_setup.rs::legacy_env_name_refuses_startup` |
| AC-REL08-1 | подтверждение не приходит | отказ по таймауту, операция не выполнена | `tests/tool_calls.rs::timeout_refuses_and_does_not_execute` |
| AC-REL09-1 | клиент подтверждает модифицирующий вызов | операция выполняется, транспорт получил команду | `tests/tool_calls.rs::confirmed_modification_executes` |
| AC-REL09-2 | клиент отклоняет подтверждение | операция не выполняется, ответ `cancelled`, транспорт команды не получил | `tests/tool_calls.rs::declined_modification_does_not_execute` |
| AC-REL09-3 | клиент не объявил elicitation | отказ, операция не выполнена (fail-closed, DR-5) | `tests/tool_calls.rs::client_without_elicitation_is_refused` |
| AC-REL09-4 | read-only инструмент через MCP | вызов проходит без подтверждения и доходит до транспорта | `tests/tool_calls.rs::read_only_tool_needs_no_confirmation` |
| AC-OBS01-2 | `WINRIG_AUDIT_LOG_BODY=0` | только метаданные | `config::tests::audit_defaults_and_reads` + `session.rs` |
| AC-OBS02-1 | свободный текст в генераторе | кавычка удвоена, сырой ввод не проходит | `ps::tests::every_generator_escapes_single_quoted_free_text`; `ps::tests::compare_files_does_not_interpolate_paths_in_double_quotes` |
| AC-OBS02-2 | список инструментов | ровно 37 уникальных имён | `server::tests::tool_router_lists_registered_tools`, `tests/stdio_mode.rs::stdio_serves_mcp_over_clean_stdout` |

## 3a. Критерии приёмки профиля и CLI (ADR-0009)

| ID | Given/When | Then | Покрытие в winrig |
|---|---|---|---|
| AC-PRF-01 | `setup` получает имя, пользователя и пароль | файл `<name>.json` создан, токен напечатан один раз, пароля в файле нет, права `0600` | `profile::tests::create_writes_only_ciphertext`, `tests/cli_setup.rs::setup_prints_token_once_and_never_the_password` |
| AC-PRF-02 | верный токен | возвращены каноническое имя и пароль | `profile::tests::load_with_correct_token` |
| AC-PRF-03 | поиск токена в каталоге | совпадений нет | `profile::tests::token_is_absent_from_disk` |
| AC-PRF-04 | один профиль, `WINRIG_TOKEN` задан, stdio без имени | `initialize` проходит, журнал указывает профиль | `paths::tests::single_profile_is_default`, `tests/stdio_mode.rs::stdio_serves_mcp_over_clean_stdout` |
| AC-PRF-05 | stdio, `connect` на фиктивном транспорте | транспорт получил имя и пароль профиля; аудит пишет `identity=profile` | `session::tests::profile_identity_reaches_transport`, `session::tests::origin_label_distinguishes_sources` |
| AC-PRF-06 | HTTP с токеном профиля без `X-AD-User`; `serve --port/--host` | ответ не 401; флаги перекрывают окружение | `tests/http_gate.rs::profile_token_without_user_reaches_the_service`, `tests/cli_setup.rs::serve_port_flag_overrides_env` |
| AC-PRF-07 | HTTP с общим секретом, `X-AD-User` и паролем | работает; сессии изолированы | `tests/http_gate.rs::header_path_still_works_with_profile_bound`, `session::tests::sessions_are_isolated_per_user` |
| AC-PRF-08 | `WINRIG_LOG_DIR` не задан | журналы в каталоге состояния профиля | `paths::tests::state_dir_is_per_profile`, `paths::tests::state_dir_override_wins`, `app::tests::log_dir_prefers_explicit_override` |
| AC-PRF-09 | `WINRIG_LOG_DIR` задан | журналы в `WINRIG_LOG_DIR` | `app::tests::log_dir_prefers_explicit_override` |
| AC-PRF-10 | `list` при двух профилях; `list --json` | таблица с заголовками либо JSON, без секретов | `profile::tests::list_exposes_no_secrets`, `profile::tests::profile_files_use_json_extension`, `tests/cli_setup.rs::list_prints_table_with_headers`, `tests/cli_setup.rs::list_json_is_valid_and_secret_free`, `tests/cli_setup.rs::list_json_empty_directory` |
| AC-PRF-11 | `rotate` | новый токен работает, старый нет, имя сохранено | `profile::tests::rotate_changes_token_only` |
| AC-PRF-12 | `forget` | файл удалён | `profile::tests::forget_is_idempotent` |
| AC-PRF-13 | пароль из профиля отвергнут 3 раза | блокировка, без транспорта | `session::tests::lockout_applies_to_profile_password` |
| AC-PRF-14 | вывод содержит пароль профиля | аудит и ответ без секрета | `session::tests::run_ps_redacts_secret_from_reply_and_audit`, `session::tests::run_ps_redacts_profile_password` |
| AC-PRF-15 | `setup --write-config <client>` | запись добавлена, другие не тронуты, для opencode ссылка на файл; повторная запись заменяет, а не дублирует | `client_config::tests::opencode_preserves_other_entries`, `client_config::tests::mcp_servers_clients_write_stdio_entry`, `client_config::tests::codex_replaces_only_its_own_section`, `client_config::tests::codex_rewrite_replaces_env_section`, `client_config::tests::mcp_servers_rewrite_replaces_entry`, `client_config::tests::codex_broken_file_is_reported_not_overwritten`, `client_config::tests::unreadable_config_is_reported_not_overwritten`, `client_config::tests::inline_token_config_is_private`, `client_config::tests::definition_carries_directories`, `tests/cli_setup.rs::write_config_preserves_other_entries` |
| AC-PRF-20 | два профиля без имени | отказ, перечислены имена | `paths::tests::ambiguous_selection_is_rejected`, `app::tests::ambiguous_profile_is_refused` |
| AC-PRF-21 | любая подкоманда | пароля нет ни в stdout, ни в stderr; токены не выводятся через Debug | `tests/cli_setup.rs::setup_prints_token_once_and_never_the_password`, `tests/stdio_mode.rs::stdio_with_wrong_token_refuses`, `config::tests::debug_redacts_tokens` |
| AC-PRF-22 | stdio, ошибки и журнал | stdout только JSON-RPC | `tests/stdio_mode.rs::stdio_serves_mcp_over_clean_stdout` |
| AC-PRF-23 | метаданные шифрования испорчены | пароль не восстановим | `profile::tests::stripped_crypto_metadata_is_unrecoverable` |
| AC-PRF-24 | повторный `setup` без `--overwrite` | отказ, файл не изменён | `profile::tests::create_twice_without_overwrite_fails`, `tests/cli_setup.rs::setup_twice_without_overwrite_refuses` |
| AC-PRF-25 | права `0644` на Unix | предупреждение, не отказ | `profile::tests::loose_permissions_warn_but_load` |
| AC-PRF-26 | `DOMAIN\Alice` | канонизация совпадает с заголовком | `profile::tests::canonical_username_matches_identity` |
| AC-PRF-27 | имя с символами пути | отказ, файлов вне каталога нет | `paths::tests::invalid_profile_names_are_rejected`, `paths::tests::path_traversal_creates_nothing`, `app::tests::rotate_and_forget_reject_path_names` |
| AC-PRF-30 | `forget` несуществующего | успех, «удалять нечего» | `profile::tests::forget_is_idempotent` |
| AC-PRF-31 | ротация | временных файлов не осталось | `profile::tests::rotation_leaves_no_temp_files` |
| AC-PRF-32 | повторная загрузка | файл не изменён | `profile::tests::repeated_load_keeps_file_unchanged` |
| AC-PRF-33 | ротация на диске при работе процесса | старый токен продолжает работать, новый — нет | `auth::tests::rotation_on_disk_does_not_affect_bound_profile` |
| AC-PRF-34 | `forget` на диске при работе процесса | до перезапуска работает | `auth::tests::forgetting_on_disk_does_not_affect_bound_profile` |
| AC-PRF-40 | неверный токен | отказ, журнал `invalid profile token`, без значения | `profile::tests::wrong_token_is_invalid_token_error`, `app::tests::profile_bind_reason_distinguishes_failures`, `tests/http_gate.rs::wrong_profile_token_is_rejected` |
| AC-PRF-41 | повреждённый файл | отказ, журнал `profile file corrupt`, клиенту 401/код 2 | `profile::tests::corrupt_file_is_distinct_error`, `auth::tests::corrupt_profile_is_a_distinct_error`, `app::tests::profile_bind_reason_distinguishes_failures`, `tests/cli_setup.rs::corrupt_profile_refuses_stdio` |
| AC-PRF-42 | stdio без `WINRIG_TOKEN` | код 2, stdout пуст | `app::tests::missing_profile_token_names_variable`, `tests/stdio_mode.rs::stdio_without_token_refuses` |
| AC-PRF-43 | профиль не найден | код 2, имя и каталог | `paths::tests::missing_profile_is_reported`, `app::tests::missing_profile_is_reported_by_locations` |
| AC-PRF-44 | каталог профилей нельзя подготовить | отказ с путём | `tests/stdio_mode.rs::unusable_profile_dir_refuses_setup` |
| AC-PRF-45 | пустое имя или пароль | отказ, файла нет | `profile::tests::empty_input_is_rejected` |
| AC-PRF-46 | версия формата выше известной | отказ, файл не изменён | `profile::tests::unsupported_version_is_reported` |
| AC-PRF-47 | ни профиля, ни `WINRIG_AUTH_TOKEN` | код 2, сообщение о двух способах | `tests/cli_setup.rs::serve_without_secret_refuses`, `config::tests::no_secret_is_accepted_by_parser` (парсер не отвергает; решение принимает точка входа) |
| AC-PRF-48 | `tools/list` | ровно 37 уникальных имён | `server::tests::tool_router_lists_registered_tools`, `tests/stdio_mode.rs::stdio_serves_mcp_over_clean_stdout` |
| AC-PRF-49 | заголовки без секрета | 401, транспорт не вызван | `tests/http_gate.rs::headers_without_token_are_rejected_even_with_profile` |
| AC-PRF-50 | `WINRIG_AUTH_TOKEN` равен токену профиля | старт отказывает | `app::tests::auth_token_equal_to_profile_key_is_refused` |
| AC-PRF-51 | токен профиля и заголовки вместе | идентичность профиля, заголовки игнорируются | `identity::tests::profile_identity_wins_over_headers` |
| AC-PRF-52 | `WINRIG_AUTH_TOKEN` без `X-AD-User` | 401 | `tests/http_gate.rs::request_with_token_but_without_user_is_rejected` |
| AC-PRF-53 | серия неверных токенов, затем верный | верный работает; проверка не повторяет KDF | `tests/http_gate.rs::profile_token_stays_valid_after_failures` (поведенчески); отсутствие повторного KDF — свойство кода (HMAC-метка) |
| AC-PRF-54 | второй процесс с тем же профилем | код 2, совет про HTTP, первый жив | `tests/stdio_mode.rs::second_process_on_same_profile_refuses_then_clears`, `paths::tests::second_process_lock_is_refused` |
| AC-PRF-55 | процесс завершён, lock снят | новый процесс проходит рукопожатие | `tests/stdio_mode.rs::second_process_on_same_profile_refuses_then_clears` |
| AC-PRF-56 | вторая блокировка подряд | stdio код 3, HTTP отказ, транспорт не вызван, шесть вызовов всего | `session::tests::profile_password_rejected_twice_is_refused`, `session::tests::header_password_does_not_refuse_profile`, `app::tests::stdio_outcome_maps_refusal_to_code_three`; end-to-end код 3 требует отказа живого AD — не проверяемо без хоста (Q-08) |
| AC-PRF-57 | успешный `connect` после блокировки | счёт подряд сброшен | `session::tests::successful_connect_resets_lockout_streak` |
| AC-PRF-59 | учётная запись `contoso\alice` уходит в NTLM | имя `alice`, домен `contoso`, без обратного слэша в имени | `session::tests::split_account_handles_all_forms`, `session::tests::credentials_for_splits_domain` |
| AC-PRF-58 | `serve --token`/`--auth-token` без переменных окружения; флаг против неверного env | аутентификация проходит; значение из флага побеждает; секрет не виден в выводе | `tests/cli_setup.rs::serve_token_flag_authenticates_profile`, `tests/cli_setup.rs::serve_auth_token_flag_authenticates_header_path`, `tests/cli_setup.rs::serve_token_flag_overrides_env` |
| AC-PRF-60 | `--write-config` без `--scope`, stdin не терминал | код 2, сообщение называет `--scope`, профиль и конфиг не созданы | `app::tests::resolve_scope_non_interactive_refuses_without_flag`, `tests/cli_setup.rs::write_config_without_scope_refuses_non_interactive` |
| AC-PRF-61 | `--write-config opencode --scope project` из подкаталога git-репозитория | запись в `<git-root>/opencode.json`; токен — файл `0600` в `WINRIG_STATE_DIR/<profile>`; в дереве проекта токена нет | `client_config::tests::find_project_root_walks_up_to_git`, `client_config::tests::project_config_paths_per_client`, `client_config::tests::opencode_project_token_goes_to_state_dir`, `tests/cli_setup.rs::write_config_project_writes_to_git_root` |
| AC-PRF-62 | явный `--scope global` либо `--scope project` | запись идёт в путь уровня, вопрос не задаётся | `app::tests::resolve_scope_prefers_explicit`, `tests/cli_setup.rs::write_config_preserves_other_entries`, `tests/cli_setup.rs::write_config_project_writes_to_git_root` |
| AC-PRF-63 | `--scope` без `--write-config` | код 2, ничего не записано | `tests/cli_setup.rs::scope_without_write_config_refuses` |
| AC-PRF-64 | тот же профиль уже объявлен под ключом `winrig-tm` | запись обновлена на месте, ключ сохранён, дубля нет; запись на другой профиль не тронута | `client_config::tests::opencode_updates_the_existing_entry_for_the_same_profile`, `client_config::tests::opencode_leaves_entries_for_other_profiles_alone`, `client_config::tests::mcp_servers_updates_the_existing_entry_for_the_same_profile` |
| AC-PRF-65 | `--server-name winrig-prod` | ключом записи становится указанное имя | `client_config::tests::explicit_server_name_is_used_as_the_key` |
| AC-PRF-66 | запись конфига с корнем состояния | `WINRIG_STATE_DIR` равен корню, ссылка на токен указывает в `<корень>/<профиль>` | `client_config::tests::state_dir_in_the_entry_is_the_root`, `client_config::tests::opencode_project_token_goes_to_state_dir` |
| AC-PRF-67 | `--user contosoalice` | отказ, профиль не создан, текст называет `DOMAIN\user`; `DOMAIN\user` и UPN проходят | `profile::tests::account_without_a_separator_is_refused`, `profile::tests::domain_and_upn_accounts_are_accepted` |

## 4. Решённые параметры (ADR-0005)

Порог блокировки 3, окно 1800 с, минимальная длина редактирования 4, allowlist по умолчанию пуст (разрешать всё), TLS-понижение по умолчанию разрешено, идемпотентность модификаций сохраняется. Носитель конфигурации — переменные окружения (ADR-0004). Двойная блокировка профиля — ADR-0009.
