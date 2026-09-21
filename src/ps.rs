//! Генерация PowerShell-команд для инструментов (чистые функции).
//!
//! Команды не зависят от локали хоста и от транспорта, поэтому строятся и
//! тестируются здесь, без Windows-хоста. Значения экранируются для вставки в
//! строку PowerShell в одинарных кавычках ([`escape`]).

use serde_json::Value;

/// Экранирует значение для вставки в PowerShell-строку в одинарных кавычках.
#[must_use]
pub fn escape(value: &str) -> String {
    value.replace('\'', "''")
}

/// Уровни журнала событий: имя инструмента → числовой уровень.
const EVENT_LEVELS: [(&str, &str); 4] = [
    ("critical", "1"),
    ("error", "2"),
    ("warning", "3"),
    ("info", "4"),
];

/// Известные кодировки для чтения файлов.
pub const VALID_ENCODINGS: [&str; 8] = [
    "ascii",
    "bigendianunicode",
    "default",
    "oem",
    "unicode",
    "utf7",
    "utf8",
    "utf32",
];

/// Сколько сырых байт содержимого уходит в один вызов (TR-FS-05, ADR-0013 §8).
///
/// Скрипт едет на хост аргументом `powershell.exe -EncodedCommand <base64>`, а
/// WinRS ограничивает командную строку примерно 8191 символом. Тройное
/// кодирование (base64 содержимого → UTF-16LE скрипта → base64 аргумента) даёт
/// около 3.5-кратного роста, поэтому больше 2 КБ в вызов не помещается.
/// `winrm-rs::transfer` выбрал ту же величину по той же причине.
pub const WRITE_CHUNK_BYTES: usize = 2000;

/// Кодирует байты в base64 для вставки в PowerShell-строку.
#[must_use]
pub fn encode_base64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Выражение .NET-кодировки для завершающей конвертации.
///
/// Имена — те же, что принимает `read_file`; `utf8` сюда не попадает, потому
/// что для него конвертации нет вовсе (файл переносится байт в байт).
fn dotnet_encoding(key: &str) -> Option<&'static str> {
    Some(match key {
        "ascii" => "[Text.Encoding]::ASCII",
        "bigendianunicode" => "[Text.Encoding]::BigEndianUnicode",
        "default" => "[Text.Encoding]::Default",
        "oem" => {
            "[Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)"
        }
        "unicode" => "[Text.Encoding]::Unicode",
        "utf7" => "[Text.Encoding]::UTF7",
        "utf32" => "[Text.Encoding]::UTF32",
        _ => return None,
    })
}

/// Один кусок содержимого во временный файл (TR-FS-05).
///
/// Первый кусок создаёт файл, остальные дописывают. Куски — сырые байты, а не
/// текст: граница на 2000 байт может разрезать многобайтовый символ, и склеить
/// его обратно можно только побайтово.
#[must_use]
pub fn write_chunk(temp_path: &str, chunk_base64: &str, first: bool) -> String {
    let safe = escape(temp_path);
    // В алфавите base64 кавычки нет, но функция публичная, а модуль обещает
    // экранировать каждое значение, попадающее в строку в одинарных кавычках.
    let safe_chunk = escape(chunk_base64);
    if first {
        format!(
            "$bytes = [Convert]::FromBase64String('{safe_chunk}'); \
             [IO.File]::WriteAllBytes('{safe}', $bytes)"
        )
    } else {
        format!(
            "$bytes = [Convert]::FromBase64String('{safe_chunk}'); \
             $f = [IO.File]::Open('{safe}', 'Append'); \
             $f.Write($bytes, 0, $bytes.Length); $f.Close()"
        )
    }
}

/// Заменяет цель временным файлом (TR-FS-05).
///
/// Для `utf8` это переименование: содержимое уже лежит байт в байт, каким его
/// прислал агент, без BOM. Для прочих кодировок временный файл читается как
/// UTF-8 и записывается в цель нужной кодировкой — конвертация делается один
/// раз в конце, потому что по кускам она разъехалась бы на границе символа.
///
/// # Errors
///
/// Текст ошибки, если кодировка не из [`VALID_ENCODINGS`].
pub fn write_commit(temp_path: &str, path: &str, encoding: &str) -> Result<String, String> {
    let key = encoding.trim().to_lowercase();
    if !VALID_ENCODINGS.contains(&key.as_str()) {
        return Err(format!(
            "Invalid encoding '{encoding}'. Valid: {}",
            VALID_ENCODINGS.join(", ")
        ));
    }
    let safe_temp = escape(temp_path);
    let safe_path = escape(path);
    let Some(dotnet) = dotnet_encoding(&key) else {
        return Ok(format!(
            "Move-Item -LiteralPath '{safe_temp}' -Destination '{safe_path}' -Force -ErrorAction Stop; \
             Write-Output 'File written successfully'"
        ));
    };
    // Конвертация идёт во второй временный файл, и только потом цель
    // заменяется переименованием. Запись сразу в цель усекла бы её в начале, и
    // отказ на этом шаге оставил бы обрезанный файл на месте настоящего
    // (TR-FS-05).
    let safe_staged = escape(&format!("{temp_path}.enc"));
    Ok(format!(
        "$text = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes('{safe_temp}')); \
         [IO.File]::WriteAllText('{safe_staged}', $text, {dotnet}); \
         Move-Item -LiteralPath '{safe_staged}' -Destination '{safe_path}' -Force -ErrorAction Stop; \
         Remove-Item -LiteralPath '{safe_temp}' -Force -ErrorAction SilentlyContinue; \
         Write-Output 'File written successfully'"
    ))
}

/// Полный план записи: куски во временный файл и завершающая замена.
///
/// План строится целиком до первого обращения к хосту, поэтому предел размера
/// и неизвестная кодировка отвергаются до сети (TR-FS-04). Временный путь
/// передаётся снаружи, чтобы план был воспроизводим в тестах.
///
/// # Errors
///
/// Текст ошибки, если содержимое больше `max_bytes` или кодировка неизвестна.
pub fn write_plan(
    path: &str,
    temp_path: &str,
    content: &str,
    encoding: &str,
    max_bytes: usize,
) -> Result<Vec<String>, String> {
    let bytes = content.as_bytes();
    if bytes.len() > max_bytes {
        return Err(format!(
            "content is {} bytes, above the limit of {max_bytes}; \
             raise WINRIG_MAX_WRITE_BYTES or write less",
            bytes.len()
        ));
    }
    // Кодировку проверяем до кусков: иначе отказ придёт после того, как часть
    // файла уже уехала на хост.
    let commit = write_commit(temp_path, path, encoding)?;
    let mut plan: Vec<String> = bytes
        .chunks(WRITE_CHUNK_BYTES)
        .enumerate()
        .map(|(index, chunk)| write_chunk(temp_path, &encode_base64(chunk), index == 0))
        .collect();
    if plan.is_empty() {
        // Пустое содержимое — всё равно файл, а не пропуск записи.
        plan.push(write_chunk(temp_path, "", true));
    }
    plan.push(commit);
    Ok(plan)
}

/// Убирает временные файлы после отказа (TR-FS-05).
///
/// Их два: файл кусков и промежуточный файл конвертации, который появляется
/// для кодировок, отличных от `utf8`.
#[must_use]
pub fn write_abort(temp_path: &str) -> String {
    let safe = escape(temp_path);
    let safe_staged = escape(&format!("{temp_path}.enc"));
    format!(
        "Remove-Item -LiteralPath '{safe}' -Force -ErrorAction SilentlyContinue; \
         Remove-Item -LiteralPath '{safe_staged}' -Force -ErrorAction SilentlyContinue"
    )
}

/// Сообщает, существует ли цель: для отказа без `overwrite` (TR-FS-03).
#[must_use]
pub fn write_precheck(path: &str) -> String {
    let safe = escape(path);
    format!(
        "if (Test-Path -LiteralPath '{safe}') {{ Write-Output 'EXISTS' }} \
         else {{ Write-Output 'ABSENT' }}"
    )
}

/// Хосты/учётки: усекает число до `cap` включительно.
fn cap(value: i64, low: i64, high: i64) -> i64 {
    value.clamp(low, high)
}

/// `list_directory` — содержимое каталога.
#[must_use]
pub fn list_directory(path: &str) -> String {
    let safe = escape(path);
    format!(
        "Get-ChildItem -LiteralPath '{safe}' -Force -ErrorAction Stop \
         | Sort-Object LastWriteTime -Descending \
         | Select-Object -First 200 Mode, LastWriteTime, Length, Name \
         | Format-Table -AutoSize | Out-String -Width 300"
    )
}

/// `find_files` — рекурсивный поиск по маске.
#[must_use]
pub fn find_files(path: &str, pattern: &str, max_depth: i64, include_size: bool) -> String {
    let safe_path = escape(path);
    let safe_pattern = escape(pattern);
    let depth = cap(max_depth, 0, 10);
    let cols = if include_size {
        "FullName, Length, LastWriteTime"
    } else {
        "FullName, LastWriteTime"
    };
    format!(
        "Get-ChildItem -LiteralPath '{safe_path}' -Recurse -Filter '{safe_pattern}' \
         -Depth {depth} -ErrorAction SilentlyContinue \
         | Select-Object -First 100 {cols} \
         | Format-Table -AutoSize | Out-String -Width 300"
    )
}

/// `read_file` — чтение файла диапазоном или с конца.
///
/// # Errors
///
/// Возвращает текст ошибки при неизвестной кодировке или неверном диапазоне.
pub fn read_file(
    path: &str,
    start_line: i64,
    end_line: i64,
    tail: bool,
    encoding: &str,
) -> Result<String, String> {
    let enc_key = encoding.trim().to_lowercase();
    if !VALID_ENCODINGS.contains(&enc_key.as_str()) {
        return Err(format!(
            "Invalid encoding '{encoding}'. Valid: {}",
            VALID_ENCODINGS.join(", ")
        ));
    }
    let safe = escape(path);
    if tail {
        let count = cap(end_line, 1, 500);
        return Ok(format!(
            "$lines = @(Get-Content -LiteralPath '{safe}' -Tail {count} -Encoding {enc_key} -ErrorAction Stop); \
             $n = 1; $lines | ForEach-Object {{ '{{0,6}}|{{1}}' -f ($n++), $_ }}; \
             Write-Output (\"--- tail: last $($lines.Count) lines ---\")"
        ));
    }
    let start = start_line.max(1);
    if end_line < start {
        return Err("end_line must be >= start_line".to_owned());
    }
    let end = if end_line - start + 1 > 500 {
        start + 499
    } else {
        end_line
    };
    Ok(read_file_range(&safe, start, end, &enc_key))
}

fn read_file_range(safe: &str, start: i64, end: i64, enc: &str) -> String {
    let skip = start - 1;
    format!(
        "$lines = @(Get-Content -LiteralPath '{safe}' -TotalCount {end} -Encoding {enc} -ErrorAction Stop); \
         $n = {start}; $lines | Select-Object -Skip {skip} | \
         ForEach-Object {{ '{{0,6}}|{{1}}' -f ($n++), $_ }}; \
         Write-Output (\"--- lines {start} to {end}, read $($lines.Count) lines ---\")"
    )
}

/// `search_file_content` — grep-подобный поиск.
#[must_use]
pub fn search_file_content(
    path: &str,
    pattern: &str,
    file_filter: &str,
    max_results: i64,
    context_lines: i64,
    modified_after_hours: i64,
) -> String {
    let safe_path = escape(path);
    let safe_pattern = escape(pattern);
    let safe_filter = escape(file_filter);
    let result_cap = cap(max_results, 1, 100);
    let ctx = cap(context_lines, 0, 10);
    let ctx_arg = if ctx > 0 {
        format!(" -Context {ctx},{ctx}")
    } else {
        String::new()
    };
    let time_filter = if modified_after_hours > 0 {
        format!(
            "| Where-Object {{ $_.LastWriteTime -gt (Get-Date).AddHours(-{modified_after_hours}) }} "
        )
    } else {
        String::new()
    };
    let (fmt_file, fmt_single) = if ctx > 0 {
        ("| Out-String -Width 300", "| Out-String -Width 300")
    } else {
        (
            "| ForEach-Object { \"$($_.Path):$($_.LineNumber)|$($_.Line)\" }",
            "| ForEach-Object { \"$($_.LineNumber)|$($_.Line)\" }",
        )
    };
    format!(
        "$t = Get-Item -LiteralPath '{safe_path}' -ErrorAction Stop; \
         if ($t.PSIsContainer) {{ \
         Get-ChildItem -LiteralPath '{safe_path}' -Recurse -File -Filter '{safe_filter}' \
         -ErrorAction SilentlyContinue {time_filter}\
         | Select-String -Pattern '{safe_pattern}' -SimpleMatch{ctx_arg} -ErrorAction SilentlyContinue \
         | Select-Object -First {result_cap} {fmt_file} \
         }} else {{ \
         Select-String -LiteralPath '{safe_path}' -Pattern '{safe_pattern}' -SimpleMatch{ctx_arg} -ErrorAction Stop \
         | Select-Object -First {result_cap} {fmt_single} \
         }}"
    )
}

/// `file_info` — метаданные файла или каталога.
#[must_use]
pub fn file_info(path: &str) -> String {
    let safe = escape(path);
    format!(
        "Get-Item -LiteralPath '{safe}' -Force -ErrorAction Stop \
         | Select-Object FullName, \
         @{{N='SizeBytes';E={{$_.Length}}}}, \
         @{{N='SizeKB';E={{[math]::Round($_.Length/1KB,2)}}}}, \
         @{{N='Created';E={{$_.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')}}}}, \
         @{{N='Modified';E={{$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')}}}}, \
         @{{N='Accessed';E={{$_.LastAccessTime.ToString('yyyy-MM-dd HH:mm:ss')}}}}, \
         Attributes | ConvertTo-Json -Compress"
    )
}

/// `compare_files` — построчное сравнение двух файлов.
///
/// Пути печатаются только через уже вычисленные переменные хоста, а не
/// подставляются в строку в двойных кавычках: `$(...)` внутри двойных кавычек
/// PowerShell раскрывает, поэтому литеральный путь мог бы выполнить код.
#[must_use]
pub fn compare_files(path_a: &str, path_b: &str, max_diffs: i64) -> String {
    let safe_a = escape(path_a);
    let safe_b = escape(path_b);
    let diff_cap = cap(max_diffs, 1, 200);
    format!(
        "$a = Get-Content -LiteralPath '{safe_a}' -ErrorAction Stop; \
         $b = Get-Content -LiteralPath '{safe_b}' -ErrorAction Stop; \
         Write-Output ('File A: {safe_a} (' + $a.Count + ' lines)'); \
         Write-Output ('File B: {safe_b} (' + $b.Count + ' lines)'); Write-Output ''; \
         $diff = Compare-Object -ReferenceObject $a -DifferenceObject $b -ErrorAction Stop; \
         if (-not $diff) {{ Write-Output 'Files are identical.' }} else {{ \
         Write-Output ($diff.Count.ToString() + ' differences found:'); Write-Output ''; \
         $diff | Select-Object -First {diff_cap} \
         @{{N='Line';E={{$_.InputObject}}}}, \
         @{{N='Source';E={{if($_.SideIndicator -eq '=>'){{'B (only)'}}else{{'A (only)'}}}}}} \
         | Format-Table -AutoSize -Wrap | Out-String -Width 300 }}"
    )
}

/// `get_event_log` — чтение журнала событий.
///
/// # Errors
///
/// Возвращает текст ошибки при неизвестном уровне (TR-REL-03).
pub fn get_event_log(
    log_name: &str,
    level: &str,
    hours_back: i64,
    source: &str,
    count: i64,
) -> Result<String, String> {
    let safe_log = escape(log_name);
    let result_cap = cap(count, 1, 100);
    let hours = cap(hours_back, 1, 720);
    let level_key = level.trim().to_lowercase();
    let Some(position) = EVENT_LEVELS.iter().position(|(name, _)| *name == level_key) else {
        return Err(format!(
            "Invalid level '{level}'. Valid: Critical, Error, Warning, Info"
        ));
    };
    let levels = EVENT_LEVELS[..=position]
        .iter()
        .map(|(_, number)| *number)
        .collect::<Vec<_>>()
        .join(",");
    let filter = format!(
        "@{{LogName='{safe_log}'; Level={levels}; StartTime=(Get-Date).AddHours(-{hours})}}"
    );
    let get_events = if source.trim().is_empty() {
        format!(
            "Get-WinEvent -FilterHashtable {filter} -MaxEvents {result_cap} -ErrorAction SilentlyContinue"
        )
    } else {
        let safe_source = escape(source.trim());
        format!(
            "Get-WinEvent -FilterHashtable {filter} -ErrorAction SilentlyContinue \
             | Where-Object {{ $_.ProviderName -like '{safe_source}' }} \
             | Select-Object -First {result_cap}"
        )
    };
    Ok(format!(
        "$ev = @({get_events}); \
         if ($ev.Count -eq 0) {{ Write-Output 'No events matched: log={safe_log}, level={level_key} and higher, last {hours}h'; exit 0 }}; \
         $ev | ForEach-Object {{ \
         \"$($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) [$($_.LevelDisplayName)] ($($_.ProviderName)) ID:$($_.Id)\"; \
         \"  $(if ($_.Message) {{ $_.Message.Substring(0,[Math]::Min($_.Message.Length,400)) }} else {{ '' }})\"; \
         \"---\" }}"
    ))
}

/// `get_services` — список служб (сводка или детально).
#[must_use]
pub fn get_services(name_filter: &str, status_filter: &str, detail: bool) -> String {
    let mut where_clauses: Vec<String> = Vec::new();
    let sf = status_filter.trim().to_lowercase();
    if sf == "running" || sf == "stopped" {
        where_clauses.push(format!("$_.Status -eq '{}'", capitalize(&sf)));
    }
    if !name_filter.trim().is_empty() {
        let safe = escape(name_filter.trim());
        where_clauses.push(format!(
            "($_.Name -like '{safe}' -or $_.DisplayName -like '{safe}')"
        ));
    }
    let where_clause = if where_clauses.is_empty() {
        String::new()
    } else {
        format!("| Where-Object {{ {} }} ", where_clauses.join(" -and "))
    };
    if !detail {
        return format!(
            "Get-Service -ErrorAction SilentlyContinue {where_clause}\
             | Sort-Object Status, Name | Select-Object Name, Status, StartType, DisplayName \
             | Format-Table -AutoSize | Out-String -Width 300"
        );
    }
    format!(
        "@(Get-Service -ErrorAction SilentlyContinue {where_clause}\
         | ForEach-Object {{ $svc = $_; \
         $wmi = Get-CimInstance Win32_Service -Filter \"Name='$($svc.Name)'\" -ErrorAction SilentlyContinue; \
         [PSCustomObject]@{{ name=$svc.Name; display_name=$svc.DisplayName; \
         status=[string]$svc.Status; start_type=[string]$svc.StartType; \
         binary_path=$wmi.PathName; service_account=$wmi.StartName; \
         pid=if($wmi.ProcessId){{$wmi.ProcessId}}else{{$null}}; \
         description=$wmi.Description }} }}) | ConvertTo-Json -Compress -Depth 3"
    )
}

fn capitalize(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

/// `list_processes` — процессы с сортировкой.
#[must_use]
pub fn list_processes(name_filter: &str, sort_by: &str, top: i64) -> String {
    let result_cap = cap(top, 1, 100);
    let sort_prop = if sort_by.trim().to_lowercase() == "cpu" {
        "CPU"
    } else {
        "WorkingSet64"
    };
    let name_where = if name_filter.trim().is_empty() {
        String::new()
    } else {
        format!(
            "| Where-Object {{ $_.ProcessName -like '{}' }} ",
            escape(name_filter.trim())
        )
    };
    format!(
        "Get-Process -ErrorAction SilentlyContinue {name_where}\
         | Sort-Object {sort_prop} -Descending | Select-Object -First {result_cap} \
         Id, ProcessName, @{{N='CPU_s';E={{[math]::Round($_.CPU,1)}}}}, \
         @{{N='Mem_MB';E={{[math]::Round($_.WorkingSet64/1MB,1)}}}}, \
         @{{N='Handles';E={{$_.HandleCount}}}}, \
         @{{N='Started';E={{if($_.StartTime){{$_.StartTime.ToString('yyyy-MM-dd HH:mm')}}else{{'N/A'}}}}}} \
         | Format-Table -AutoSize | Out-String -Width 300"
    )
}

/// `get_system_info` — сводка о системе.
#[must_use]
pub fn get_system_info() -> String {
    "$os = Get-CimInstance Win32_OperatingSystem; \
     $cs = Get-CimInstance Win32_ComputerSystem; \
     [PSCustomObject]@{ ComputerName=$env:COMPUTERNAME; OS=$os.Caption; Version=$os.Version; \
     BuildNumber=$os.BuildNumber; LastBoot=$os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss'); \
     Uptime=((Get-Date)-$os.LastBootUpTime).ToString('d\\.hh\\:mm\\:ss'); \
     TotalRAM_GB=[math]::Round($cs.TotalPhysicalMemory/1GB,1); \
     FreeRAM_GB=[math]::Round($os.FreePhysicalMemory/1MB,1); \
     CPUs=$cs.NumberOfLogicalProcessors; Domain=$cs.Domain; TimeZone=(Get-TimeZone).Id \
     } | ConvertTo-Json -Compress"
        .to_owned()
}

/// `get_disk_space` — место на фиксированных дисках.
#[must_use]
pub fn get_disk_space() -> String {
    "Get-CimInstance Win32_LogicalDisk -Filter \"DriveType=3\" \
     | Select-Object DeviceID, @{N='Total_GB';E={[math]::Round($_.Size/1GB,1)}}, \
     @{N='Free_GB';E={[math]::Round($_.FreeSpace/1GB,1)}}, \
     @{N='Used_Pct';E={[math]::Round(($_.Size-$_.FreeSpace)/$_.Size*100,1)}} \
     | Format-Table -AutoSize | Out-String -Width 200"
        .to_owned()
}

/// `get_registry` — чтение раздела или значения реестра.
#[must_use]
pub fn get_registry(key: &str, value_name: &str) -> String {
    let mut k = key.trim().to_owned();
    if k.to_uppercase().starts_with("HKEY_") {
        k = format!("Registry::{k}");
    }
    let safe_key = escape(&k);
    if value_name.trim().is_empty() {
        format!(
            "Get-ItemProperty -LiteralPath '{safe_key}' -ErrorAction Stop \
             | Select-Object * -ExcludeProperty PS* | ConvertTo-Json -Compress"
        )
    } else {
        let safe_val = escape(value_name.trim());
        format!(
            "Get-ItemProperty -LiteralPath '{safe_key}' -Name '{safe_val}' -ErrorAction Stop \
             | Select-Object -Property '{safe_val}' | ConvertTo-Json -Compress"
        )
    }
}

/// `get_network_config` — конфигурация сетевых адаптеров.
#[must_use]
pub fn get_network_config() -> String {
    "Get-NetIPConfiguration -ErrorAction SilentlyContinue \
     | Select-Object InterfaceAlias, @{N='Status';E={$_.NetAdapter.Status}}, \
     @{N='IPv4';E={($_.IPv4Address.IPAddress) -join ','}}, \
     @{N='Gateway';E={($_.IPv4DefaultGateway.NextHop) -join ','}}, \
     @{N='DNS';E={($_.DNSServer.ServerAddresses) -join ','}} \
     | Format-Table -AutoSize | Out-String -Width 300"
        .to_owned()
}

/// `get_environment_variables` — переменные окружения.
///
/// # Errors
///
/// Возвращает текст ошибки при неизвестной области видимости.
pub fn get_environment_variables(name_filter: &str, scope: &str) -> Result<String, String> {
    let sc = match scope.trim().to_lowercase().as_str() {
        "machine" => "Machine",
        "user" => "User",
        "process" => "Process",
        _ => return Err("scope must be 'Machine', 'User', or 'Process'".to_owned()),
    };
    let name_where = if name_filter.trim().is_empty() {
        String::new()
    } else {
        format!(
            "| Where-Object {{ $_.Name -like '{}' }} ",
            escape(name_filter.trim())
        )
    };
    Ok(format!(
        "[Environment]::GetEnvironmentVariables('{sc}').GetEnumerator() \
         | Select-Object Name, Value {name_where}| Sort-Object Name \
         | Format-Table -AutoSize -Wrap | Out-String -Width 300"
    ))
}

/// `get_certificates` — сертификаты личного хранилища.
///
/// # Errors
///
/// Возвращает текст ошибки при неизвестном хранилище.
pub fn get_certificates(store: &str, days_until_expiry: i64) -> Result<String, String> {
    let st = match store.trim().to_lowercase().as_str() {
        "localmachine" => "LocalMachine",
        "currentuser" => "CurrentUser",
        _ => return Err("store must be 'LocalMachine' or 'CurrentUser'".to_owned()),
    };
    let expiry_filter = if days_until_expiry > 0 {
        format!("| Where-Object {{ $_.NotAfter -lt (Get-Date).AddDays({days_until_expiry}) }} ")
    } else {
        String::new()
    };
    Ok(format!(
        "Get-ChildItem -Path 'Cert:\\{st}\\My' -ErrorAction Stop {expiry_filter}\
         | Select-Object @{{N='Subject';E={{$_.Subject.Substring(0,[Math]::Min($_.Subject.Length,80))}}}}, \
         @{{N='Expires';E={{$_.NotAfter.ToString('yyyy-MM-dd')}}}}, \
         @{{N='DaysLeft';E={{[math]::Round(($_.NotAfter-(Get-Date)).TotalDays)}}}}, Thumbprint \
         | Sort-Object DaysLeft | Format-Table -AutoSize | Out-String -Width 300"
    ))
}

/// `test_network` — ICMP-ping или TCP-проверка порта.
#[must_use]
pub fn test_network(target: &str, port: i64) -> String {
    let safe_target = escape(target);
    if port > 0 {
        return format!(
            "$r = Test-NetConnection -ComputerName '{safe_target}' -Port {port} -WarningAction SilentlyContinue; \
             [PSCustomObject]@{{ Target=$r.ComputerName; RemoteAddress=[string]$r.RemoteAddress; \
             Port=$r.RemotePort; TcpTestSucceeded=$r.TcpTestSucceeded; RTT_ms=$r.PingReplyDetails.RoundtripTime \
             }} | ConvertTo-Json -Compress"
        );
    }
    format!(
        "Test-Connection -ComputerName '{safe_target}' -Count 3 -ErrorAction Stop \
         | Select-Object @{{N='Target';E={{$_.Address}}}}, \
         @{{N='RTT_ms';E={{$_.ResponseTime}}}}, @{{N='TTL';E={{$_.TimeToLive}}}} \
         | Format-Table -AutoSize | Out-String -Width 200"
    )
}

/// `get_tcp_connections` — активные TCP-соединения.
#[must_use]
pub fn get_tcp_connections(state_filter: &str, port_filter: i64) -> String {
    let mut where_parts: Vec<String> = Vec::new();
    let sf = state_filter.trim().to_lowercase();
    if sf != "all" {
        let ps_state = match sf.as_str() {
            "listen" => "Listen",
            "timewait" => "TimeWait",
            "closewait" => "CloseWait",
            "finwait1" => "FinWait1",
            "finwait2" => "FinWait2",
            "synreceived" => "SynReceived",
            "bound" => "Bound",
            _ => "Established",
        };
        where_parts.push(format!("$_.State -eq '{ps_state}'"));
    }
    if port_filter > 0 {
        where_parts.push(format!(
            "($_.LocalPort -eq {port_filter} -or $_.RemotePort -eq {port_filter})"
        ));
    }
    let where_clause = if where_parts.is_empty() {
        String::new()
    } else {
        format!("| Where-Object {{ {} }} ", where_parts.join(" -and "))
    };
    format!(
        "Get-NetTCPConnection -ErrorAction SilentlyContinue {where_clause}\
         | Select-Object @{{N='Local';E={{\"$($_.LocalAddress):$($_.LocalPort)\"}}}}, \
         @{{N='Remote';E={{\"$($_.RemoteAddress):$($_.RemotePort)\"}}}}, State, \
         @{{N='PID';E={{$_.OwningProcess}}}}, \
         @{{N='Process';E={{(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}}} \
         | Sort-Object Remote | Format-Table -AutoSize | Out-String -Width 300"
    )
}

/// `resolve_dns_name` — разрешение имени.
///
/// # Errors
///
/// Возвращает текст ошибки при неизвестном типе записи.
pub fn resolve_dns_name(name: &str, record_type: &str, dns_server: &str) -> Result<String, String> {
    const VALID: [&str; 9] = ["A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT"];
    let rt = record_type.trim().to_uppercase();
    if !VALID.contains(&rt.as_str()) {
        return Err(format!(
            "Invalid record_type '{record_type}'. Valid: {}",
            VALID.join(", ")
        ));
    }
    let safe_name = escape(name);
    let server_arg = if dns_server.trim().is_empty() {
        String::new()
    } else {
        format!(" -Server '{}'", escape(dns_server.trim()))
    };
    Ok(format!(
        "Resolve-DnsName -Name '{safe_name}' -Type {rt}{server_arg} -ErrorAction Stop \
         | Select-Object Name, Type, TTL, @{{N='Data';E={{ \
         if($_.IPAddress){{$_.IPAddress}} elseif($_.NameHost){{$_.NameHost}} \
         elseif($_.NameExchange){{\"$($_.NameExchange) (pri:$($_.Preference))\"}} \
         elseif($_.NameTarget){{\"$($_.NameTarget):$($_.Port)\"}} \
         elseif($_.Strings){{$_.Strings -join ' '}} elseif($_.PrimaryServer){{$_.PrimaryServer}} else{{'N/A'}} }}}} \
         | Format-Table -AutoSize | Out-String -Width 300"
    ))
}

/// Проверяет, что входной JSON — объект, и извлекает строковое поле.
#[must_use]
pub fn json_str(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Проверяет, что входной JSON — объект, и извлекает целочисленное поле.
#[must_use]
pub fn json_i64(value: &Value, key: &str, default: i64) -> i64 {
    value.get(key).and_then(Value::as_i64).unwrap_or(default)
}

/// Проверяет, что входной JSON — объект, и извлекает булево поле.
#[must_use]
pub fn json_bool(value: &Value, key: &str, default: bool) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(default)
}

/// `get_perf_snapshot` — локаленезависимый снимок производительности (TR-REL-02).
#[must_use]
pub fn get_perf_snapshot(interval_sec: i64, process_filter: &str) -> String {
    let cap_interval = cap(interval_sec, 1, 10);
    let proc_block = if process_filter.trim().is_empty() {
        "$procData = @(); ".to_owned()
    } else {
        format!(
            "$procData = @(Get-CimInstance Win32_PerfFormattedData_PerfProc_Process \
             -ErrorAction SilentlyContinue | Where-Object {{ $_.Name -like '{}' }} \
             | ForEach-Object {{ [PSCustomObject]@{{ name=$_.Name; \
             cpu_pct=[math]::Round([double]$_.PercentProcessorTime,1); \
             mem_mb=[math]::Round([double]$_.WorkingSet/1MB,1); \
             handles=[int]$_.HandleCount; threads=[int]$_.ThreadCount; \
             io_read_kbs=[math]::Round([double]$_.IOReadBytesPersec/1KB,1); \
             io_write_kbs=[math]::Round([double]$_.IOWriteBytesPersec/1KB,1) }} }}); ",
            escape(process_filter.trim())
        )
    };
    format!(
        "$cpu = Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter \"Name='_Total'\" -ErrorAction SilentlyContinue; \
         $mem = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory -ErrorAction SilentlyContinue; \
         $sys = Get-CimInstance Win32_PerfFormattedData_PerfOS_System -ErrorAction SilentlyContinue; \
         $dsk = Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter \"Name='_Total'\" -ErrorAction SilentlyContinue; \
         $net = Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkInterface -ErrorAction SilentlyContinue; \
         $tcp = Get-CimInstance Win32_PerfFormattedData_Tcpip_TCPv4 -ErrorAction SilentlyContinue; \
         $prc = Get-CimInstance Win32_PerfFormattedData_PerfProc_Process -Filter \"Name='_Total'\" -ErrorAction SilentlyContinue; \
         $netBytes = [double](($net | Measure-Object -Property BytesTotalPersec -Sum).Sum); \
         {proc_block}\
         $r = [ordered]@{{ timestamp=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); samples=1; interval_sec={cap_interval}; \
         cpu=[ordered]@{{ total_pct=[math]::Round([double]$cpu.PercentProcessorTime,2); \
         kernel_pct=[math]::Round([double]$cpu.PercentPrivilegedTime,2); queue_length=[int]$sys.ProcessorQueueLength }}; \
         memory=[ordered]@{{ available_mb=[math]::Round([double]$mem.AvailableMBytes,2); \
         committed_pct=[math]::Round([double]$mem.PercentCommittedBytesInUse,2); pages_per_sec=[math]::Round([double]$mem.PagesPersec,2) }}; \
         disk=[ordered]@{{ busy_pct=[math]::Round([double]$dsk.PercentDiskTime,2); \
         queue_length=[math]::Round([double]$dsk.CurrentDiskQueueLength,2); \
         read_mbs=[math]::Round([double]$dsk.DiskReadBytesPersec/1MB,2); \
         write_mbs=[math]::Round([double]$dsk.DiskWriteBytesPersec/1MB,2) }}; \
         network=[ordered]@{{ throughput_mbs=[math]::Round($netBytes/1MB,2); tcp_established=[int]$tcp.ConnectionsEstablished }}; \
         system=[ordered]@{{ total_threads=[int]$sys.Threads; total_handles=[int]$prc.HandleCount }} }}; \
         if($procData.Count -gt 0){{$r['processes']=@($procData)}}; $r | ConvertTo-Json -Depth 3 -Compress"
    )
}

/// `get_scheduled_tasks` — запланированные задачи.
#[must_use]
pub fn get_scheduled_tasks(name_filter: &str, include_disabled: bool) -> String {
    let mut parts: Vec<String> = Vec::new();
    if !include_disabled {
        parts.push("$_.State -ne 'Disabled'".to_owned());
    }
    if name_filter.trim().is_empty() {
        parts.push("$_.TaskPath -notlike '\\Microsoft\\*'".to_owned());
    } else {
        parts.push(format!(
            "$_.TaskName -like '{}'",
            escape(name_filter.trim())
        ));
    }
    format!(
        "Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {{ {} }} \
         | ForEach-Object {{ $info = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue; \
         [PSCustomObject]@{{ Name=$_.TaskName; State=[string]$_.State; \
         LastRun=if($info.LastRunTime -and $info.LastRunTime.Year -gt 1999){{$info.LastRunTime.ToString('yyyy-MM-dd HH:mm')}}else{{'Never'}}; \
         LastResult=if($info){{$info.LastTaskResult}}else{{'N/A'}}; \
         NextRun=if($info.NextRunTime -and $info.NextRunTime.Year -gt 1999){{$info.NextRunTime.ToString('yyyy-MM-dd HH:mm')}}else{{'None'}} }} }} \
         | Sort-Object Name | Format-Table -AutoSize | Out-String -Width 300",
        parts.join(" -and ")
    )
}

/// `get_local_users` — локальные учётные записи.
#[must_use]
pub fn get_local_users() -> String {
    "Get-LocalUser -ErrorAction Stop | Select-Object Name, Enabled, \
     @{N='LastLogon';E={if($_.LastLogon){$_.LastLogon.ToString('yyyy-MM-dd HH:mm')}else{'Never'}}}, \
     @{N='PasswordExpires';E={if($_.PasswordExpires){$_.PasswordExpires.ToString('yyyy-MM-dd')}else{'Never'}}}, \
     Description | Sort-Object Name | Format-Table -AutoSize -Wrap | Out-String -Width 300"
        .to_owned()
}

/// `get_security_context` — контекст безопасности сессии (whoami /all).
///
/// `whoami /priv /fo csv /nh` печатает строки без заголовка, поэтому разбор не
/// зависит от языка системы: колонки берутся по позиции, а `Enabled` считается
/// только для английского `Enabled`. Сырое значение состояния сохраняется, и
/// агент видит локализованную строку как есть.
#[must_use]
pub fn get_security_context() -> String {
    "$wi = [Security.Principal.WindowsIdentity]::GetCurrent(); \
     $wp = New-Object Security.Principal.WindowsPrincipal($wi); \
     $elevated = $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); \
     $groups = $wi.Groups | ForEach-Object { try { $_.Translate([Security.Principal.NTAccount]).Value } catch { $_.Value } } | Sort-Object; \
     $privs = whoami /priv /fo csv /nh 2>$null \
     | ConvertFrom-Csv -Header 'PrivilegeName','PrivilegeState' \
     | Select-Object @{N='Privilege';E={$_.PrivilegeName}}, @{N='State';E={$_.PrivilegeState}}, \
     @{N='Enabled';E={$_.PrivilegeState -eq 'Enabled'}}; \
     [PSCustomObject]@{ Identity=$wi.Name; SID=$wi.User.Value; AuthType=$wi.AuthenticationType; \
     IsElevated=$elevated; IntegrityLevel=if($elevated){'High'}else{'Medium'}; \
     Groups=$groups; GroupCount=$groups.Count; Privileges=@($privs) } | ConvertTo-Json -Compress -Depth 3"
        .to_owned()
}

/// `get_permissions` — ACL файла или каталога.
#[must_use]
pub fn get_permissions(path: &str) -> String {
    let safe = escape(path);
    format!(
        "$acl = Get-Acl -LiteralPath '{safe}' -ErrorAction Stop; \
         Write-Output (\"Owner: \" + $acl.Owner); Write-Output ''; \
         $acl.Access | Select-Object @{{N='Identity';E={{$_.IdentityReference}}}}, AccessControlType, \
         @{{N='Rights';E={{$_.FileSystemRights}}}}, @{{N='Inherited';E={{$_.IsInherited}}}} \
         | Format-Table -AutoSize -Wrap | Out-String -Width 300"
    )
}

/// `get_dns_cache` — кэш DNS-клиента.
#[must_use]
pub fn get_dns_cache(name_filter: &str) -> String {
    let name_where = if name_filter.trim().is_empty() {
        String::new()
    } else {
        format!(
            "| Where-Object {{ $_.Entry -like '{}' }} ",
            escape(name_filter.trim())
        )
    };
    format!(
        "Get-DnsClientCache -ErrorAction SilentlyContinue {name_where}\
         | Select-Object Entry, @{{N='Type';E={{$_.Type}}}}, @{{N='TTL_s';E={{$_.TimeToLive}}}}, @{{N='Data';E={{$_.Data}}}} \
         | Sort-Object Entry | Select-Object -First 100 | Format-Table -AutoSize | Out-String -Width 300"
    )
}

/// `get_installed_software` — установленное ПО (64- и 32-бит).
#[must_use]
pub fn get_installed_software(name_filter: &str) -> String {
    let name_where = if name_filter.trim().is_empty() {
        String::new()
    } else {
        format!(
            "| Where-Object {{ $_.DisplayName -like '{}' }} ",
            escape(name_filter.trim())
        )
    };
    format!(
        "$paths = @('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', \
         'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'); \
         $paths | ForEach-Object {{ Get-ItemProperty $_ -ErrorAction SilentlyContinue }} \
         | Where-Object {{ $_.DisplayName }} {name_where}\
         | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate \
         | Sort-Object DisplayName -Unique | Format-Table -AutoSize -Wrap | Out-String -Width 300"
    )
}

/// `get_user_groups` — членство в локальных группах.
#[must_use]
pub fn get_user_groups(username: &str) -> String {
    if username.trim().is_empty() {
        return "Get-LocalGroup -ErrorAction SilentlyContinue | ForEach-Object { $g = $_.Name; \
             $members = (Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name) -join ', '; \
             [PSCustomObject]@{Group=$g; Members=if($members){$members}else{'(empty)'}} } \
             | Format-Table -AutoSize -Wrap | Out-String -Width 300"
            .to_owned();
    }
    let safe_user = escape(username.trim());
    format!(
        "$u = '{safe_user}'; Write-Output '=== Local Group Memberships ==='; $found = @(); \
         Get-LocalGroup -ErrorAction SilentlyContinue | ForEach-Object {{ \
         $members = Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue; \
         $match = $members | Where-Object {{ $_.Name -eq $u -or $_.Name -like \"*\\$u\" }}; \
         if ($match) {{ $found += [PSCustomObject]@{{Group=$_.Name; Description=$_.Description}} }} }}; \
         if ($found) {{ $found | Format-Table -AutoSize -Wrap | Out-String -Width 300 }} \
         else {{ Write-Output '  (not a member of any local groups)' }}; Write-Output ''; \
         Write-Output 'TIP: For full AD group membership of the current session, use get_security_context.'"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_doubles_single_quotes() {
        assert_eq!(escape("C:\\O'Brien"), "C:\\O''Brien");
        assert_eq!(escape("plain"), "plain");
    }

    #[test]
    fn list_directory_uses_literal_path() {
        let cmd = list_directory("C:\\Users");
        assert!(cmd.contains("-LiteralPath 'C:\\Users'"));
        assert!(cmd.contains("Select-Object -First 200"));
    }

    #[test]
    fn find_files_caps_depth_and_literal_path() {
        let cmd = find_files("C:\\Apps", "*.log", 99, true);
        assert!(cmd.contains("-Depth 10"));
        assert!(cmd.contains("-LiteralPath 'C:\\Apps'"));
        assert!(cmd.contains("FullName, Length, LastWriteTime"));
    }

    #[test]
    fn read_file_rejects_unknown_encoding() {
        let error = read_file("C:\\a.txt", 1, 10, false, "koi8").expect_err("bad encoding");
        assert!(error.contains("utf8"));
    }

    #[test]
    fn read_file_rejects_reversed_range() {
        let error = read_file("C:\\a.txt", 10, 5, false, "UTF8").expect_err("reversed");
        assert!(error.contains("end_line"));
    }

    #[test]
    fn read_file_tail_uses_tail_switch() {
        let cmd = read_file("C:\\a.log", 1, 50, true, "UTF8").expect("valid");
        assert!(cmd.contains("-Tail 50"));
    }

    #[test]
    fn get_event_log_rejects_unknown_level() {
        let error = get_event_log("System", "verbose", 24, "", 25).expect_err("bad level");
        assert!(error.contains("Invalid level"));
    }

    #[test]
    fn get_event_log_builds_level_prefix() {
        let cmd = get_event_log("System", "warning", 24, "", 25).expect("valid");
        // warning включает critical, error, warning -> 1,2,3
        assert!(cmd.contains("Level=1,2,3"));
    }

    #[test]
    fn get_event_log_source_filter_does_not_precap() {
        let cmd = get_event_log("Application", "error", 24, "*SQL*", 10).expect("valid");
        assert!(cmd.contains("-like '*SQL*'"));
        assert!(cmd.contains("Select-Object -First 10"));
    }

    #[test]
    fn get_environment_variables_rejects_unknown_scope() {
        assert!(get_environment_variables("", "galaxy").is_err());
    }

    #[test]
    fn get_certificates_rejects_unknown_store() {
        assert!(get_certificates("My", 30).is_err());
        assert!(get_certificates("LocalMachine", 30).is_ok());
    }

    #[test]
    fn resolve_dns_name_rejects_unknown_type() {
        assert!(resolve_dns_name("example.com", "ZZ", "").is_err());
        assert!(resolve_dns_name("example.com", "a", "").is_ok());
    }

    #[test]
    fn get_registry_prefixes_hkey_forms() {
        assert!(
            get_registry("HKEY_LOCAL_MACHINE\\SOFTWARE", "")
                .contains("Registry::HKEY_LOCAL_MACHINE")
        );
        assert!(get_registry("HKLM:\\SOFTWARE", "").contains("-LiteralPath 'HKLM:\\SOFTWARE'"));
    }

    #[test]
    fn registry_generators_use_literal_path() {
        // AC-REL06-1: литеральные пути со служебными символами не трактуются
        // как шаблон, поэтому `-Path` недопустим, только `-LiteralPath`.
        let read = get_registry("HKLM:\\SOFTWARE\\App[1]", "");
        assert!(read.contains("-LiteralPath '"), "{read}");
        assert!(!read.contains("-Path '"), "{read}");
    }

    #[test]
    fn test_network_switches_between_ping_and_tcp() {
        assert!(test_network("host", 0).contains("Test-Connection"));
        assert!(test_network("host", 443).contains("Test-NetConnection"));
    }

    #[test]
    fn tcp_connections_default_to_established() {
        let cmd = get_tcp_connections("Established", 0);
        assert!(cmd.contains("$_.State -eq 'Established'"));
    }

    #[test]
    fn compare_files_does_not_interpolate_paths_in_double_quotes() {
        // Инъекция: путь в двойных кавычках раскрывает $(...) в PowerShell.
        for (a, b) in [
            ("C:\\a$(calc).txt", "C:\\b.txt"),
            ("C:\\a.txt", "C:\\b$(calc).txt"),
        ] {
            let cmd = compare_files(a, b, 5);
            assert!(
                !cmd.contains("\"File A:") && !cmd.contains("\"File B:"),
                "path must not sit in a double-quoted string: {cmd}"
            );
            assert!(
                cmd.contains("-LiteralPath '"),
                "LiteralPath preserved: {cmd}"
            );
        }
    }

    #[test]
    fn get_security_context_avoids_localized_csv_headers() {
        // whoami /priv /fo csv на локализованной Windows даёт не-английские
        // заголовки; парсим без заголовка с явными позициями.
        let cmd = get_security_context();
        assert!(cmd.contains("/nh"), "header-less output expected: {cmd}");
        assert!(
            cmd.contains("ConvertFrom-Csv -Header"),
            "explicit headers expected: {cmd}"
        );
    }

    /// TR-FS-05: кусок помещается в командную строку WinRS. 2000 сырых байт
    /// дают около 2700 символов base64, скрипт после UTF-16LE и повторного
    /// base64 растёт примерно в 3.5 раза — и обязан остаться под 8191.
    #[test]
    fn a_full_chunk_fits_the_winrs_command_line() {
        let content = vec![b'A'; WRITE_CHUNK_BYTES];
        let b64 = encode_base64(&content);
        let script = write_chunk("C:\\Temp\\winrig.part", &b64, true);
        let encoded_len = script.encode_utf16().count() * 2 * 4 / 3;
        assert!(
            encoded_len < 8191,
            "chunk script would exceed the WinRS command line: {encoded_len}"
        );
    }

    /// TR-FS-05: первый кусок создаёт временный файл, последующие дописывают.
    /// Дописывающий кусок не имеет права начинать файл заново.
    #[test]
    fn first_chunk_creates_and_the_rest_append() {
        let first = write_chunk("C:\\Temp\\p", "QUJD", true);
        assert!(first.contains("WriteAllBytes"), "{first}");
        assert!(!first.contains("Append"), "{first}");
        let next = write_chunk("C:\\Temp\\p", "QUJD", false);
        assert!(next.contains("Append"), "{next}");
        assert!(!next.contains("WriteAllBytes"), "{next}");
    }

    /// TR-FS-05: цель заменяется переименованием, а не пишется по кускам.
    /// Для utf8 конвертации нет вовсе — файл переносится байт в байт.
    #[test]
    fn commit_renames_for_utf8_and_converts_otherwise() {
        let utf8 = write_commit("C:\\Temp\\p", "C:\\out.txt", "utf8").expect("valid");
        assert!(utf8.contains("Move-Item"), "{utf8}");
        assert!(!utf8.contains("Text.Encoding"), "byte-exact: {utf8}");

        let unicode = write_commit("C:\\Temp\\p", "C:\\out.txt", "unicode").expect("valid");
        assert!(unicode.contains("Text.Encoding"), "{unicode}");
        assert!(unicode.contains("WriteAllText"), "{unicode}");
    }

    /// TR-FS-05: конвертация не пишет в цель напрямую. Иначе цель усекается в
    /// начале записи, и отказ на этом шаге оставляет обрезанный файл.
    #[test]
    fn commit_never_writes_the_target_in_place() {
        for encoding in VALID_ENCODINGS {
            let command = write_commit("C:\\Temp\\p", "C:\\out.txt", encoding).expect("valid");
            assert!(
                !command.contains("WriteAllText('C:\\out.txt'"),
                "{encoding} writes the target in place: {command}"
            );
            assert!(
                command.contains("Move-Item"),
                "{encoding} must replace the target by rename: {command}"
            );
        }
    }

    /// TR-FS-05: уборка достаёт и промежуточный файл конвертации, иначе после
    /// отказа рядом с целью остаётся мусор.
    #[test]
    fn abort_removes_the_staged_file_too() {
        let command = write_abort("C:\\Temp\\p");
        assert!(command.contains("C:\\Temp\\p"), "{command}");
        assert!(command.contains("C:\\Temp\\p.enc"), "{command}");
    }

    /// Кодировка берётся из того же перечня, что у чтения (ADR-0013 §7).
    #[test]
    fn commit_rejects_unknown_encoding() {
        let error = write_commit("C:\\Temp\\p", "C:\\out.txt", "koi8-r").expect_err("unknown");
        assert!(error.contains("koi8-r"), "{error}");
        for encoding in VALID_ENCODINGS {
            write_commit("C:\\Temp\\p", "C:\\out.txt", encoding)
                .unwrap_or_else(|error| panic!("{encoding} must be accepted: {error}"));
        }
    }

    /// TR-FS-05: план — это куски плюс ровно одна завершающая замена.
    #[test]
    fn plan_splits_content_and_ends_with_one_commit() {
        let content = "x".repeat(5000);
        let plan =
            write_plan("C:\\out.txt", "C:\\out.part", &content, "utf8", 64 * 1024).expect("valid");
        // 5000 байт при куске 2000 — три куска, затем замена.
        assert_eq!(plan.len(), 4, "{plan:#?}");
        assert!(plan[0].contains("WriteAllBytes"));
        assert!(plan[1].contains("Append"));
        assert!(plan[2].contains("Append"));
        assert!(plan[3].contains("Move-Item"));
    }

    /// TR-FS-04: предел проверяется до сети и назван в отказе вместе с
    /// фактическим размером — иначе агент не поймёт, насколько сокращать.
    #[test]
    fn plan_refuses_content_above_the_limit() {
        let content = "x".repeat(5000);
        let error = write_plan("C:\\out.txt", "C:\\out.part", &content, "utf8", 4096)
            .expect_err("above the limit");
        assert!(error.contains("5000"), "{error}");
        assert!(error.contains("4096"), "{error}");
    }

    /// Пустое содержимое создаёт пустой файл, а не пропускает запись.
    #[test]
    fn plan_creates_an_empty_file() {
        let plan = write_plan("C:\\out.txt", "C:\\out.part", "", "utf8", 64 * 1024).expect("valid");
        assert_eq!(plan.len(), 2, "{plan:#?}");
        assert!(plan[0].contains("WriteAllBytes"));
        assert!(plan[1].contains("Move-Item"));
    }

    /// Размер считается в байтах, а не в символах: кириллица в UTF-8 вдвое
    /// длиннее, и предел обязан считать именно байты.
    #[test]
    fn plan_counts_bytes_not_characters() {
        let content = "я".repeat(1500); // 3000 байт в UTF-8
        let error = write_plan("C:\\out.txt", "C:\\out.part", &content, "utf8", 2500)
            .expect_err("above the limit");
        assert!(error.contains("3000"), "{error}");
    }

    /// TR-FS-05: уборка удаляет временный файл и молчит, если его уже нет.
    #[test]
    fn abort_removes_the_temporary_file_quietly() {
        let command = write_abort("C:\\Temp\\p");
        assert!(command.contains("Remove-Item"), "{command}");
        assert!(command.contains("SilentlyContinue"), "{command}");
    }

    #[test]
    fn every_generator_escapes_single_quoted_free_text() {
        // Инъекция: свободный текст, попавший в строку PowerShell в одинарных
        // кавычках, обязан удваивать кавычку во всех генераторах.
        let evil = "x' ; Remove-Item -Recurse C:\\ ; '";
        let commands = vec![
            list_directory(evil),
            find_files(evil, evil, 5, true),
            read_file(evil, 1, 10, false, "UTF8").expect("valid"),
            search_file_content(evil, evil, evil, 10, 0, 0),
            file_info(evil),
            compare_files(evil, evil, 5),
            get_event_log(evil, "error", 24, evil, 10).expect("valid"),
            get_services(evil, "all", true),
            list_processes(evil, "memory", 10),
            get_registry(evil, evil),
            get_environment_variables(evil, "machine").expect("valid"),
            test_network(evil, 443),
            get_tcp_connections("established", 1),
            resolve_dns_name(evil, "A", evil).expect("valid"),
            get_perf_snapshot(2, evil),
            get_scheduled_tasks(evil, false),
            get_user_groups(evil),
            get_permissions(evil),
            get_dns_cache(evil),
            get_installed_software(evil),
            write_chunk(evil, evil, true),
            write_chunk(evil, evil, false),
            write_commit(evil, evil, "utf8").expect("valid"),
            write_commit(evil, evil, "unicode").expect("valid"),
            write_abort(evil),
            write_precheck(evil),
        ];
        for command in commands {
            assert!(
                !command.contains(evil),
                "unescaped free text in command: {command}"
            );
            // Если текст вообще попал в команду, его кавычка обязана быть
            // удвоена; генераторы с enum-фильтром просто не принимают текст.
            assert!(
                !command.contains("x'") || command.contains("x''"),
                "single quote was not doubled: {command}"
            );
        }
    }
}
