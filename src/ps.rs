//! PowerShell command generators for the tools (pure functions).
//!
//! The commands do not depend on the host locale or on the transport, so they
//! are built and tested here without a Windows host. Values are escaped before
//! they enter a PowerShell single-quoted string ([`escape`]).

use serde_json::Value;

/// Characters that PowerShell treats as a string delimiter (TR-SEC-12).
///
/// The PowerShell tokenizer ends a single-quoted string not only at the ASCII
/// apostrophe but also at the typographic quotes: `‘` U+2018, `’` U+2019,
/// `‚` U+201A and `‛` U+201B. Doubling any of them inside the string yields the
/// literal character.
pub const SINGLE_QUOTES: [char; 5] = ['\'', '\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}'];

/// Doubles each delimiter in a value so it stays literal inside a single-quoted string.
#[must_use]
pub fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if SINGLE_QUOTES.contains(&c) {
            out.push(c);
        }
        out.push(c);
    }
    out
}

/// Numeric values that Get-WinEvent expects for each level name.
const EVENT_LEVELS: [(&str, &str); 4] = [
    ("critical", "1"),
    ("error", "2"),
    ("warning", "3"),
    ("info", "4"),
];

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

/// Raw content bytes carried by one call (TR-FS-05, ADR-0013 §8).
///
/// The script travels to the host as the argument of
/// `powershell.exe -EncodedCommand <base64>`, and WinRS caps the command line
/// at about 8191 characters. Triple encoding (content base64, then script
/// UTF-16LE, then argument base64) grows the payload about 3.5 times, so more
/// than 2 KB does not fit one call. `winrm-rs::transfer` picked the same value
/// for the same reason.
pub const WRITE_CHUNK_BYTES: usize = 2000;

#[must_use]
pub fn encode_base64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Maps an encoding key to the .NET type used for the final conversion.
///
/// The keys are the same that `read_file` accepts; `utf8` is absent because it
/// needs no conversion at all (the file moves byte for byte).
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

/// One content chunk into the temporary file (TR-FS-05).
///
/// The first chunk creates the file and the rest append. Chunks are raw bytes,
/// not text: the 2000-byte boundary can split a multi-byte character, and only
/// a byte-wise join can reassemble it.
#[must_use]
pub fn write_chunk(temp_path: &str, chunk_base64: &str, first: bool) -> String {
    let safe = escape(temp_path);
    // The base64 alphabet has no quote character, but the function is public
    // and the module promises to escape every value that enters a single-quoted
    // string.
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

/// Replaces the target with the temporary file (TR-FS-05).
///
/// For `utf8` this is a rename: the content is already byte-for-byte what the
/// agent sent, without a BOM. For other encodings the temporary file is read as
/// UTF-8 and written to the target in the requested encoding. The conversion
/// happens once at the end; per chunk it would break at a character boundary.
///
/// # Errors
///
/// An error text when the encoding is not in [`VALID_ENCODINGS`].
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
    // The conversion goes into a second temporary file, and only then the
    // target is replaced by a rename. Writing straight to the target would
    // truncate it first, and a failure at this step would leave a truncated
    // file in place of the real one (TR-FS-05).
    let safe_staged = escape(&format!("{temp_path}.enc"));
    Ok(format!(
        "$text = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes('{safe_temp}')); \
         [IO.File]::WriteAllText('{safe_staged}', $text, {dotnet}); \
         Move-Item -LiteralPath '{safe_staged}' -Destination '{safe_path}' -Force -ErrorAction Stop; \
         Remove-Item -LiteralPath '{safe_temp}' -Force -ErrorAction SilentlyContinue; \
         Write-Output 'File written successfully'"
    ))
}

/// The full plan: content chunks into the temporary file and the final replacement.
///
/// The plan is built entirely before the first host call, so the size limit and
/// an unknown encoding are rejected before the network (TR-FS-04). The caller
/// passes the temporary path so the plan is reproducible in tests.
///
/// # Errors
///
/// An error text when the content exceeds `max_bytes` or the encoding is
/// unknown.
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
    // The encoding is checked before the chunks: otherwise the refusal comes
    // after part of the file already reached the host.
    let commit = write_commit(temp_path, path, encoding)?;
    let mut plan: Vec<String> = bytes
        .chunks(WRITE_CHUNK_BYTES)
        .enumerate()
        .map(|(index, chunk)| write_chunk(temp_path, &encode_base64(chunk), index == 0))
        .collect();
    if plan.is_empty() {
        // Empty content is still a file, not a skipped write.
        plan.push(write_chunk(temp_path, "", true));
    }
    plan.push(commit);
    Ok(plan)
}

/// Removes the temporary files after a failure (TR-FS-05).
///
/// There are two: the chunk file and the staged conversion file that appears
/// for encodings other than `utf8`.
#[must_use]
pub fn write_abort(temp_path: &str) -> String {
    let safe = escape(temp_path);
    let safe_staged = escape(&format!("{temp_path}.enc"));
    format!(
        "Remove-Item -LiteralPath '{safe}' -Force -ErrorAction SilentlyContinue; \
         Remove-Item -LiteralPath '{safe_staged}' -Force -ErrorAction SilentlyContinue"
    )
}

/// The `Roots` property of the scans: protected roots from the host system
/// variables (TR-FS-06, ADR-0015 §10–12).
///
/// Environment variables do not depend on the system language, so the check is
/// locale-independent (AGENTS.md §6). The profile root is not in the variables,
/// so the parent of `PUBLIC` is used. A missing variable yields `null` and the
/// parser skips it; an empty `SystemRoot` is rejected.
pub const HOST_ROOTS: &str = "Roots=[PSCustomObject]@{ SystemRoot=$env:SystemRoot; \
     ProgramFiles=$env:ProgramFiles; ProgramFilesX86=${env:ProgramFiles(x86)}; \
     ProgramData=$env:ProgramData; \
     Users=$(if ($env:PUBLIC) { Split-Path -Parent $env:PUBLIC } else { $null }) }";

/// The write target scan: both path resolutions, existence and the host roots
/// (TR-FS-03, TR-FS-06).
///
/// .NET writes the chunks and `Move-Item` replaces the target, and they resolve
/// a relative path from different directories, so the host returns both
/// resolutions. Any error stops the script and the tool refuses (fail-closed).
#[must_use]
pub fn write_scan(path: &str) -> String {
    let safe = escape(path);
    format!(
        "$ErrorActionPreference = 'Stop'; \
         $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath('{safe}'); \
         $net = [IO.Path]::GetFullPath('{safe}'); \
         [PSCustomObject]@{{ FullName=$full; DotNetFullName=$net; \
         Exists=[bool](Test-Path -LiteralPath '{safe}'); {HOST_ROOTS} }} \
         | ConvertTo-Json -Compress"
    )
}

/// The scan of a file to delete: the host-resolved path, the directory flag and
/// the host roots (DR-6, TR-SEC-04).
#[must_use]
pub fn delete_file_scan(path: &str) -> String {
    let safe = escape(path);
    format!(
        "$item = Get-Item -LiteralPath '{safe}' -Force -ErrorAction Stop; \
         [PSCustomObject]@{{ FullName=$item.FullName; IsDirectory=[bool]$item.PSIsContainer; \
         SizeBytes=if($item.PSIsContainer){{$null}}else{{$item.Length}}; \
         Modified=$item.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'); {HOST_ROOTS} }} \
         | ConvertTo-Json -Compress"
    )
}

/// The scan of a directory to delete: the host path, reparse points at the root
/// and in the subtree, the item count up to `limit` and the host roots (DR-6,
/// ADR-0005 §5, TR-SEC-04).
#[must_use]
pub fn delete_directory_scan(path: &str, limit: i64) -> String {
    let safe = escape(path);
    format!(
        "$item = Get-Item -LiteralPath '{safe}' -Force -ErrorAction Stop; \
         if (-not $item.PSIsContainer) {{ throw 'Path is a file — use delete_file instead' }}; \
         $isReparse = [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint); \
         $files = @(Get-ChildItem -LiteralPath '{safe}' -Recurse -File -Force -ErrorAction SilentlyContinue | Select-Object -First {limit}); \
         $dirs = @(Get-ChildItem -LiteralPath '{safe}' -Recurse -Directory -Force -ErrorAction SilentlyContinue | Select-Object -First {limit}); \
         $nestedReparse = [bool](@($dirs | Where-Object {{ [bool]($_.Attributes -band [IO.FileAttributes]::ReparsePoint) }}).Count -gt 0); \
         [PSCustomObject]@{{ FullName=$item.FullName; IsReparsePoint=$isReparse; NestedReparsePoint=$nestedReparse; \
         FileCount=$files.Count; DirCount=$dirs.Count; TotalItems=($files.Count + $dirs.Count); {HOST_ROOTS} }} \
         | ConvertTo-Json -Compress"
    )
}

/// Clamps a number into the inclusive range `low`..=`high`.
fn cap(value: i64, low: i64, high: i64) -> i64 {
    value.clamp(low, high)
}

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

/// # Errors
///
/// Returns an error text for an unknown encoding or an invalid range.
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

/// Compares two files line by line.
///
/// The paths are printed only through host variables that were already
/// computed, never interpolated into a double-quoted string: PowerShell expands
/// `$(...)` inside double quotes, so a literal path could execute code.
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

/// # Errors
///
/// Returns an error text for an unknown level (TR-REL-03).
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

#[must_use]
pub fn get_disk_space() -> String {
    "Get-CimInstance Win32_LogicalDisk -Filter \"DriveType=3\" \
     | Select-Object DeviceID, @{N='Total_GB';E={[math]::Round($_.Size/1GB,1)}}, \
     @{N='Free_GB';E={[math]::Round($_.FreeSpace/1GB,1)}}, \
     @{N='Used_Pct';E={[math]::Round(($_.Size-$_.FreeSpace)/$_.Size*100,1)}} \
     | Format-Table -AutoSize | Out-String -Width 200"
        .to_owned()
}

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

/// # Errors
///
/// Gives an error text for an unknown scope.
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

/// # Errors
///
/// Gives an error text for an unknown store.
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

/// # Errors
///
/// Returns an error text for an unknown record type.
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

#[must_use]
pub fn json_str(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

#[must_use]
pub fn json_i64(value: &Value, key: &str, default: i64) -> i64 {
    value.get(key).and_then(Value::as_i64).unwrap_or(default)
}

#[must_use]
pub fn json_bool(value: &Value, key: &str, default: bool) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(default)
}

/// A locale-independent performance snapshot (TR-REL-02).
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

#[must_use]
pub fn get_local_users() -> String {
    "Get-LocalUser -ErrorAction Stop | Select-Object Name, Enabled, \
     @{N='LastLogon';E={if($_.LastLogon){$_.LastLogon.ToString('yyyy-MM-dd HH:mm')}else{'Never'}}}, \
     @{N='PasswordExpires';E={if($_.PasswordExpires){$_.PasswordExpires.ToString('yyyy-MM-dd')}else{'Never'}}}, \
     Description | Sort-Object Name | Format-Table -AutoSize -Wrap | Out-String -Width 300"
        .to_owned()
}

/// Session security context from whoami /all.
///
/// `whoami /priv /fo csv /nh` prints rows without a header, so the parse is
/// locale-independent: the columns are taken by position, and `Enabled` is true
/// only for the English `Enabled`. The raw state value is kept, so the agent
/// sees the localized string as it is.
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

/// Installed software from both the 64-bit and the 32-bit uninstall keys.
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
        // warning includes critical, error and warning -> 1,2,3
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
        // AC-REL06-1: a literal path with wildcard characters is not treated as
        // a pattern, so `-Path` is not allowed here, only `-LiteralPath`.
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
        // Injection: a path in double quotes expands $(...) in PowerShell.
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
        // whoami /priv /fo csv on a localized Windows yields non-English
        // headers; the parse uses no header and explicit positions.
        let cmd = get_security_context();
        assert!(cmd.contains("/nh"), "header-less output expected: {cmd}");
        assert!(
            cmd.contains("ConvertFrom-Csv -Header"),
            "explicit headers expected: {cmd}"
        );
    }

    /// TR-FS-05: one chunk fits the WinRS command line. 2000 raw bytes give
    /// about 2700 base64 characters, and the script grows about 3.5 times after
    /// UTF-16LE and a second base64, so it must stay under 8191.
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

    /// TR-FS-05: the first chunk creates the temporary file, later ones append.
    /// An appending chunk must not start the file over.
    #[test]
    fn first_chunk_creates_and_the_rest_append() {
        let first = write_chunk("C:\\Temp\\p", "QUJD", true);
        assert!(first.contains("WriteAllBytes"), "{first}");
        assert!(!first.contains("Append"), "{first}");
        let next = write_chunk("C:\\Temp\\p", "QUJD", false);
        assert!(next.contains("Append"), "{next}");
        assert!(!next.contains("WriteAllBytes"), "{next}");
    }

    /// TR-FS-05: the target is replaced by a rename, not written in chunks.
    /// For utf8 there is no conversion at all; the file moves byte for byte.
    #[test]
    fn commit_renames_for_utf8_and_converts_otherwise() {
        let utf8 = write_commit("C:\\Temp\\p", "C:\\out.txt", "utf8").expect("valid");
        assert!(utf8.contains("Move-Item"), "{utf8}");
        assert!(!utf8.contains("Text.Encoding"), "byte-exact: {utf8}");

        let unicode = write_commit("C:\\Temp\\p", "C:\\out.txt", "unicode").expect("valid");
        assert!(unicode.contains("Text.Encoding"), "{unicode}");
        assert!(unicode.contains("WriteAllText"), "{unicode}");
    }

    /// TR-FS-05: the conversion never writes to the target directly. Otherwise
    /// the target is truncated first and a failure leaves a partial file.
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

    /// TR-FS-05: the cleanup also reaches the staged conversion file; otherwise
    /// a failure leaves garbage next to the target.
    #[test]
    fn abort_removes_the_staged_file_too() {
        let command = write_abort("C:\\Temp\\p");
        assert!(command.contains("C:\\Temp\\p"), "{command}");
        assert!(command.contains("C:\\Temp\\p.enc"), "{command}");
    }

    /// The encoding comes from the same list as the read path (ADR-0013 §7).
    #[test]
    fn commit_rejects_unknown_encoding() {
        let error = write_commit("C:\\Temp\\p", "C:\\out.txt", "koi8-r").expect_err("unknown");
        assert!(error.contains("koi8-r"), "{error}");
        for encoding in VALID_ENCODINGS {
            write_commit("C:\\Temp\\p", "C:\\out.txt", encoding)
                .unwrap_or_else(|error| panic!("{encoding} must be accepted: {error}"));
        }
    }

    /// TR-FS-05: the plan is the chunks plus exactly one final replacement.
    #[test]
    fn plan_splits_content_and_ends_with_one_commit() {
        let content = "x".repeat(5000);
        let plan =
            write_plan("C:\\out.txt", "C:\\out.part", &content, "utf8", 64 * 1024).expect("valid");
        // 5000 bytes at a 2000-byte chunk give three chunks, then the replacement.
        assert_eq!(plan.len(), 4, "{plan:#?}");
        assert!(plan[0].contains("WriteAllBytes"));
        assert!(plan[1].contains("Append"));
        assert!(plan[2].contains("Append"));
        assert!(plan[3].contains("Move-Item"));
    }

    /// TR-FS-04: the limit is checked before the network and the refusal names
    /// the actual size; otherwise the agent cannot tell how much to cut.
    #[test]
    fn plan_refuses_content_above_the_limit() {
        let content = "x".repeat(5000);
        let error = write_plan("C:\\out.txt", "C:\\out.part", &content, "utf8", 4096)
            .expect_err("above the limit");
        assert!(error.contains("5000"), "{error}");
        assert!(error.contains("4096"), "{error}");
    }

    /// Empty content creates an empty file, not a skipped write.
    #[test]
    fn plan_creates_an_empty_file() {
        let plan = write_plan("C:\\out.txt", "C:\\out.part", "", "utf8", 64 * 1024).expect("valid");
        assert_eq!(plan.len(), 2, "{plan:#?}");
        assert!(plan[0].contains("WriteAllBytes"));
        assert!(plan[1].contains("Move-Item"));
    }

    /// The size counts bytes, not characters: Cyrillic is twice as long in
    /// UTF-8, and the limit must count bytes.
    #[test]
    fn plan_counts_bytes_not_characters() {
        let content = "я".repeat(1500); // 3000 байт в UTF-8
        let error = write_plan("C:\\out.txt", "C:\\out.part", &content, "utf8", 2500)
            .expect_err("above the limit");
        assert!(error.contains("3000"), "{error}");
    }

    /// TR-FS-05: the cleanup removes the temporary file and stays silent when it is gone.
    #[test]
    fn abort_removes_the_temporary_file_quietly() {
        let command = write_abort("C:\\Temp\\p");
        assert!(command.contains("Remove-Item"), "{command}");
        assert!(command.contains("SilentlyContinue"), "{command}");
    }

    /// TR-SEC-12: PowerShell ends a single-quoted string at any of the five
    /// characters, not only at the ASCII apostrophe.
    #[test]
    fn escape_doubles_every_single_quote_form() {
        for quote in SINGLE_QUOTES {
            let value = format!("a{quote}b");
            assert_eq!(escape(&value), format!("a{quote}{quote}b"), "{quote:?}");
        }
        assert_eq!(
            escape("a\u{2018}b\u{2019}c"),
            "a\u{2018}\u{2018}b\u{2019}\u{2019}c"
        );
    }

    #[test]
    fn every_generator_escapes_single_quoted_free_text() {
        for quote in SINGLE_QUOTES {
            assert_generators_escape(quote);
        }
    }

    /// Injection: free text that enters a PowerShell single-quoted string must
    /// double the quote in every generator (AC-OBS02-1, AC-SEC12-1).
    fn assert_generators_escape(quote: char) {
        let evil = format!("x{quote} ; Remove-Item -Recurse C:\\ ; {quote}");
        let evil = evil.as_str();
        let opened = format!("x{quote}");
        let doubled = format!("x{quote}{quote}");
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
            write_scan(evil),
            delete_file_scan(evil),
            delete_directory_scan(evil, 10),
        ];
        for command in commands {
            assert!(
                !command.contains(evil),
                "unescaped free text in command: {command}"
            );
            // If the text enters the command at all, its quote must be doubled;
            // generators with an enum filter simply do not take the text.
            assert!(
                !command.contains(&opened) || command.contains(&doubled),
                "single quote {quote:?} was not doubled: {command}"
            );
        }
    }

    /// AC-FS-07: the roots come from the host environment variables, not from
    /// localized directory names, and reach all three scans.
    #[test]
    fn scans_read_protected_roots_from_the_environment() {
        for variable in [
            "$env:SystemRoot",
            "$env:ProgramFiles",
            "${env:ProgramFiles(x86)}",
            "$env:ProgramData",
            "$env:PUBLIC",
        ] {
            assert!(HOST_ROOTS.contains(variable), "{variable}");
        }
        for command in [
            write_scan("D:\\App\\x"),
            delete_file_scan("D:\\App\\x"),
            delete_directory_scan("D:\\App", 10),
        ] {
            assert!(command.contains(HOST_ROOTS), "{command}");
            assert!(command.contains("ConvertTo-Json"), "{command}");
        }
    }

    /// AC-FS-07: the write scan returns both path resolutions and stops at the
    /// first error, so a refusal does not look like an empty success.
    #[test]
    fn write_scan_resolves_the_path_both_ways() {
        let command = write_scan("x.ps1");
        assert!(
            command.starts_with("$ErrorActionPreference = 'Stop'"),
            "{command}"
        );
        assert!(
            command.contains("GetUnresolvedProviderPathFromPSPath('x.ps1')"),
            "{command}"
        );
        assert!(
            command.contains("[IO.Path]::GetFullPath('x.ps1')"),
            "{command}"
        );
        assert!(command.contains("DotNetFullName="), "{command}");
        assert!(
            command.contains("Test-Path -LiteralPath 'x.ps1'"),
            "{command}"
        );
    }
}
