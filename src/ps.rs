//! PowerShell command generators for the tools (pure functions).
//!
//! The commands do not depend on the host locale or on the transport, so they
//! are built and tested here without a Windows host. Values are escaped before
//! they enter a PowerShell single-quoted string ([`escape`]).

use serde_json::Value;

/// Characters that PowerShell accepts as a single quote (TR-SEC-12).
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

/// WinRS caps the command line at about 8191 characters (the `cmd.exe` limit).
pub const WINRS_COMMAND_LINE_LIMIT: usize = 8191;
/// The `powershell.exe -EncodedCommand ` prefix that `winrm-rs` puts before the
/// payload; the prefix counts against the same command line.
const LAUNCHER_PREFIX_CHARS: usize = "powershell.exe -EncodedCommand ".len();
/// Safety margin for the encoding estimate and for a quote in the path.
const COMMAND_LINE_MARGIN: usize = 256;
/// The smallest chunk a write still splits into. Below this the write becomes a
/// long series of calls for little gain (TR-FS-04).
const MIN_WRITE_CHUNK_BYTES: usize = 256;

/// The upper bound of one content chunk (TR-FS-05, ADR-0013 §8).
///
/// The script travels to the host as the argument of
/// `powershell.exe -EncodedCommand <base64>`, and WinRS caps the command line
/// at about 8191 characters. Triple encoding (content base64, then script
/// UTF-16LE, then argument base64) grows the payload about 3.5 times. The
/// preamble (TR-REL-10), the temporary path and the launcher prefix all count
/// against the same limit, so the actual chunk is smaller for a long path
/// (`max_chunk_bytes`). This value is the maximum, chosen so a full chunk fits
/// with more than 256 characters of margin in the worst case.
pub const WRITE_CHUNK_BYTES: usize = 1536;

// A common key such as `HKLM\SOFTWARE` holds thousands of subkeys. The cap keeps
// one answer readable; the tool fetches one extra key to set the `truncated` flag.
const REGISTRY_SUBKEY_LIMIT: usize = 500;

/// Counts the preamble and the launcher prefix next to the script.
pub fn command_line_chars(script: &str) -> usize {
    let units = crate::session::PREAMBLE.encode_utf16().count() + script.encode_utf16().count();
    // `-EncodedCommand` takes UTF-16LE bytes as base64: 4 characters for each
    // 3 bytes, rounded up.
    LAUNCHER_PREFIX_CHARS + 4 * (units * 2).div_ceil(3)
}

/// True when one command line holds the script with the margin left.
fn fits_command_line(script: &str) -> bool {
    command_line_chars(script) <= WINRS_COMMAND_LINE_LIMIT - COMMAND_LINE_MARGIN
}

/// The largest content chunk that still fits one command line for this path.
///
/// The escaped temporary path is fixed, so only the chunk decides the length.
fn max_chunk_bytes(temp_path: &str) -> usize {
    max_chunk_bytes_with(temp_path, |path, chunk| write_chunk(path, chunk, false))
}

/// The largest chunk whose command, built by `command`, still fits one command
/// line. The command varies (create, append, `CreateNew`), so the search uses the
/// real builder instead of an estimate.
fn max_chunk_bytes_with(temp_path: &str, command: impl Fn(&str, &str) -> String) -> usize {
    let mut lo = 0usize;
    let mut hi = WRITE_CHUNK_BYTES;
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        let bytes = vec![0u8; mid];
        if fits_command_line(&command(temp_path, &encode_base64(&bytes))) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

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
            "$ErrorActionPreference = 'Stop'; \
             $bytes = [Convert]::FromBase64String('{safe_chunk}'); \
             [IO.File]::WriteAllBytes('{safe}', $bytes)"
        )
    } else {
        format!(
            "$ErrorActionPreference = 'Stop'; \
             $bytes = [Convert]::FromBase64String('{safe_chunk}'); \
             $f = [IO.File]::Open('{safe}', 'Append'); \
             try {{ $f.Write($bytes, 0, $bytes.Length) }} finally {{ $f.Close() }}"
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
            "Invalid encoding '{encoding}'. Valid values: {}",
            VALID_ENCODINGS.join(", ")
        ));
    }
    let safe_temp = escape(temp_path);
    // The `-Destination` parameter expands a wildcard, so the replacement uses the
    // `[IO.File]` class instead (ADR-0017 §18).
    let Some(dotnet) = dotnet_encoding(&key) else {
        let replace = replace_target_command(temp_path, path);
        return Ok(format!(
            "$ErrorActionPreference = 'Stop'; {replace}; Write-Output 'File written successfully'"
        ));
    };
    // The conversion goes into a second temporary file, and only then the
    // target is replaced by a rename. Writing straight to the target would
    // truncate it first, and a failure at this step would leave a truncated
    // file in place of the real one (TR-FS-05).
    let staged = format!("{temp_path}.enc");
    let safe_staged = escape(&staged);
    let replace = replace_target_command(&staged, path);
    Ok(format!(
        "$ErrorActionPreference = 'Stop'; \
         $text = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes('{safe_temp}')); \
         [IO.File]::WriteAllText('{safe_staged}', $text, {dotnet}); \
         {replace}; \
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
/// An error text when the content exceeds `max_bytes`, the encoding is unknown,
/// or the target path is too long for one WinRS command line.
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
    // Every command of the write rides one WinRS command line: the host scan, the
    // chunks, the final replacement and the cleanup (TR-FS-05). The chunk is
    // derived from the escaped temporary path, which is fixed for this call.
    let chunk = max_chunk_bytes(temp_path);
    let fits = chunk >= MIN_WRITE_CHUNK_BYTES
        && fits_command_line(&write_scan(path))
        && fits_command_line(&commit)
        && fits_command_line(&write_abort(temp_path));
    if !fits {
        return Err(path_too_long(path));
    }
    let mut plan: Vec<String> = bytes
        .chunks(chunk)
        .enumerate()
        .map(|(index, part)| write_chunk(temp_path, &encode_base64(part), index == 0))
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

/// The refusal for a path whose commands cannot fit one WinRS command line.
fn path_too_long(path: &str) -> String {
    format!(
        "path is {} characters; the write must fit one WinRS command line of \
         {WINRS_COMMAND_LINE_LIMIT} characters; shorten the path",
        path.chars().count()
    )
}

/// The base64 strings that a generated write command carries in
/// `FromBase64String('...')`, so exactly what the command holds is redacted from
/// the audit and the reply (DR-4).
#[must_use]
pub fn base64_payloads(command: &str) -> Vec<String> {
    const OPEN: &str = "FromBase64String('";
    let mut out = Vec::new();
    let mut rest = command;
    while let Some(start) = rest.find(OPEN) {
        rest = &rest[start + OPEN.len()..];
        let Some(end) = rest.find('\'') else { break };
        let payload = &rest[..end];
        if !payload.is_empty() {
            out.push(payload.to_owned());
        }
        rest = &rest[end..];
    }
    out
}

/// A host command that returns the full path of a staging `.ps1` in the session
/// temp directory (ADR-0017 §31). `$env:TEMP` comes from the environment, so the
/// path agrees with the host locale.
#[must_use]
pub fn script_temp_path(suffix: &str) -> String {
    let safe = escape(suffix);
    format!(
        "$d = $env:TEMP; if ([string]::IsNullOrEmpty($d)) {{ $d = [IO.Path]::GetTempPath() }}; \
         [IO.Path]::Combine($d, 'winrig-{safe}.ps1')"
    )
}

/// The lowercase hex SHA-256 of the script bytes, exactly the content that reaches
/// the staging file (TR-EXE-06). The run step compares it against the hash of the
/// bytes it reads, so a change between the confirmation and the run stops the
/// script.
#[must_use]
pub fn script_sha256(script: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(script.as_bytes())
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use std::fmt::Write;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// The first staging chunk. `CreateNew` refuses an existing file, so a stale or
/// racing temporary file is not overwritten (TR-EXE-06). The later chunks append.
#[must_use]
pub fn script_chunk_create(path: &str, chunk_base64: &str) -> String {
    let safe = escape(path);
    let safe_chunk = escape(chunk_base64);
    format!(
        "$ErrorActionPreference = 'Stop'; \
         $bytes=[Convert]::FromBase64String('{safe_chunk}'); \
         $f=[IO.File]::Open('{safe}','CreateNew'); \
         try {{ $f.Write($bytes,0,$bytes.Length) }} finally {{ $f.Close() }}"
    )
}

/// The exit code of the run step when the staging file does not match the
/// confirmed SHA-256 (TR-EXE-06).
pub const SCRIPT_HASH_MISMATCH_EXIT: i32 = 97;

/// The marker in the run stderr that names a SHA-256 mismatch (TR-EXE-06). The
/// caller looks for it to add a plain error to the reply.
pub const SCRIPT_HASH_MISMATCH_MARKER: &str = "does not match the confirmed SHA-256";

/// The wrapper that verifies and runs the staging script (ADR-0017 §31,
/// TR-EXE-06).
///
/// The bytes are read once into `$b`, so the check and the run use the same
/// content and no gap stands between them. The SHA-256 is computed inside
/// `try`/`catch`, so an exception (for example under a strict FIPS policy) leaves
/// `$h` empty and the guard refuses; a bare computation inside the `if` would end
/// only that statement and the script would still run. The guard exits with
/// [`SCRIPT_HASH_MISMATCH_EXIT`] when `$h` differs from the confirmed value. The
/// text is decoded from the same `$b` and its leading U+FEFF is dropped.
///
/// The text becomes a script block instead of being started by path: a host with
/// the `Restricted` execution policy still runs a script block built from text.
/// The block runs from the expression, so no variable holds the text or the
/// block. The consequence is that `$PSScriptRoot` and `$PSCommandPath` are empty
/// inside the script and `param()` receives no arguments. A native command sets
/// `$LASTEXITCODE`; the wrapper exits with it, so `status_code` agrees with
/// `run_command`.
///
/// # Errors
///
/// An error text when the run command does not fit one WinRS command line.
pub fn run_script_file(path: &str, expected_sha256: &str) -> Result<String, String> {
    let safe = escape(path);
    let safe_hash = escape(expected_sha256);
    let script = format!(
        "$global:LASTEXITCODE=$null; \
         $b=[IO.File]::ReadAllBytes('{safe}'); \
         try {{ $h=[BitConverter]::ToString([Security.Cryptography.SHA256CryptoServiceProvider]::new()\
         .ComputeHash($b)).Replace('-','').ToLowerInvariant() }} catch {{ $h='' }}; \
         if ($h -ne '{safe_hash}') {{ Write-Error 'The uploaded script {SCRIPT_HASH_MISMATCH_MARKER}. \
         The tool did not run it.'; exit {SCRIPT_HASH_MISMATCH_EXIT} }}; \
         &([ScriptBlock]::Create(([Text.Encoding]::UTF8.GetString($b)).TrimStart([char]0xFEFF))); \
         $ok=$?; if ($LASTEXITCODE) {{ exit $LASTEXITCODE }}; if (-not $ok) {{ exit 1 }}"
    );
    if !fits_command_line(&script) {
        return Err(path_too_long(path));
    }
    Ok(script)
}

/// The command that removes the staging file and reports the outcome (TR-EXE-06).
///
/// `-ErrorAction Stop` makes a failed removal a nonzero exit, so the caller can
/// report it instead of losing it in silence.
#[must_use]
pub fn script_cleanup(path: &str) -> String {
    let safe = escape(path);
    format!(
        "if (Test-Path -LiteralPath '{safe}') {{ Remove-Item -LiteralPath '{safe}' -Force \
         -ErrorAction Stop; Write-Output 'removed' }} else {{ Write-Output 'absent' }}"
    )
}

/// The full plan of a `run_script` staging write: the content chunks that create
/// and append the `.ps1` file (TR-EXE-06, ADR-0017 §31).
///
/// The plan is built entirely before the confirmation, so the size limit and a
/// path too long are refused without a call to the host (AC-EXE-07). The first
/// chunk creates the file with `CreateNew` and the rest append. Unlike
/// `write_plan` there is no rename, because the staging file is written in place
/// and thrown away.
///
/// # Errors
///
/// An error text when the script exceeds `max_bytes`, when a chunk would fall
/// below the minimum, or when the run or the cleanup command does not fit one
/// WinRS command line.
pub fn script_plan(path: &str, script: &str, max_bytes: usize) -> Result<Vec<String>, String> {
    let bytes = script.as_bytes();
    if bytes.len() > max_bytes {
        return Err(format!(
            "script is {} bytes, above the limit of {max_bytes}; \
             raise WINRIG_MAX_WRITE_BYTES or shorten the script",
            bytes.len()
        ));
    }
    run_script_file(path, &script_sha256(script))?;
    if !fits_command_line(&script_cleanup(path)) {
        return Err(path_too_long(path));
    }
    // The first chunk uses the longer `CreateNew` command, so the chunk is sized
    // by the smaller of the create and the append budget.
    let chunk = max_chunk_bytes_with(path, script_chunk_create).min(max_chunk_bytes(path));
    if chunk < MIN_WRITE_CHUNK_BYTES {
        return Err(path_too_long(path));
    }
    let mut plan: Vec<String> = bytes
        .chunks(chunk)
        .enumerate()
        .map(|(index, part)| {
            if index == 0 {
                script_chunk_create(path, &encode_base64(part))
            } else {
                write_chunk(path, &encode_base64(part), false)
            }
        })
        .collect();
    if plan.is_empty() {
        plan.push(script_chunk_create(path, ""));
    }
    Ok(plan)
}

/// The generated wrapper that decodes the base64 command text, runs it as a script
/// block and returns its exit code (TR-EXE-04).
///
/// A native command sets `$LASTEXITCODE`; the wrapper exits with it. Otherwise a
/// failed command (`$?` false) exits with 1, so `status_code` shows the failure.
/// `$global:LASTEXITCODE` is cleared first, so a value from the preamble cannot leak.
/// The block runs from the expression, so no variable holds the command text.
fn run_command_wrapper(encoded: &str) -> String {
    format!(
        "$global:LASTEXITCODE=$null; \
         &([ScriptBlock]::Create([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))); \
         $ok=$?; if ($LASTEXITCODE) {{ exit $LASTEXITCODE }}; if (-not $ok) {{ exit 1 }}"
    )
}

/// Base64 length of `units` UTF-16 code units: four characters for each three
/// bytes, rounded up.
fn encoded_len_for_units(units: usize) -> usize {
    4 * (units * 2).div_ceil(3)
}

/// The largest command text, in UTF-16 units, whose encoded wrapper still fits
/// one WinRS command line. The search uses the real wrapper, so a change of the
/// wrapper moves the limit with it.
fn max_command_units() -> usize {
    let mut lo = 0usize;
    let mut hi = WINRS_COMMAND_LINE_LIMIT;
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        let probe = run_command_wrapper(&"A".repeat(encoded_len_for_units(mid)));
        if fits_command_line(&probe) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

/// The largest command text that [`run_command`] accepts, in UTF-16 units. The
/// tool description states it, so the agent does not build a command that cannot
/// run.
#[must_use]
pub fn max_command_chars() -> usize {
    max_command_units()
}

/// Runs arbitrary PowerShell that the operator confirmed (ADR-0013 §12–15).
///
/// The command text is base64-encoded and decoded into a script block, so the
/// text never touches the generated wrapper: a quote, a `;` or a `}` in the
/// command cannot break out of it. The wrapper rides one WinRS command line, and a
/// command that does not fit is refused before the transport (TR-REL-10).
///
/// # Errors
///
/// An empty command, or a command whose encoded wrapper is above the WinRS
/// command line.
pub fn run_command(command: &str) -> Result<String, String> {
    if command.trim().is_empty() {
        return Err("the command is empty".to_owned());
    }
    let encoded = encode_utf16_base64(command);
    let script = run_command_wrapper(&encoded);
    if !fits_command_line(&script) {
        return Err(format!(
            "the command is {} UTF-16 units; the encoded wrapper must fit one WinRS command line \
             of {WINRS_COMMAND_LINE_LIMIT} characters, which holds at most {} units of command \
             text; shorten the command, or write it with write_file and run it by path",
            command.encode_utf16().count(),
            max_command_units()
        ));
    }
    Ok(script)
}

/// UTF-16LE bytes of the text as base64, the form `-EncodedCommand` and the
/// script block both take.
fn encode_utf16_base64(text: &str) -> String {
    let mut bytes = Vec::with_capacity(text.len() * 2);
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    encode_base64(&bytes)
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

/// Both path resolutions, existence, the directory flag, the link type and the host
/// roots (TR-FS-03, TR-FS-06).
///
/// .NET writes the chunks and `Move-Item` replaces the target, and they resolve a
/// relative path from different directories, so the host returns both resolutions.
/// When the target exists, `Get-Item` reads it with `-ErrorAction Stop`: a failed read
/// refuses, it does not read as "no link". `LinkType` is `SymbolicLink` or `Junction`
/// for a name surrogate and `null` for any other reparse point. Any error stops the
/// script and the tool refuses (fail-closed).
#[must_use]
pub fn write_scan(path: &str) -> String {
    let safe = escape(path);
    format!(
        "$ErrorActionPreference = 'Stop'; \
         $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath('{safe}'); \
         $net = [IO.Path]::GetFullPath('{safe}'); \
         $exists = [bool](Test-Path -LiteralPath '{safe}'); \
         $it = if ($exists) {{ Get-Item -LiteralPath '{safe}' -Force -ErrorAction Stop }} else {{ $null }}; \
         [PSCustomObject]@{{ FullName=$full; DotNetFullName=$net; Exists=$exists; \
         IsDirectory=[bool]($it -and $it.PSIsContainer); \
         LinkType=if ($it) {{ $it.LinkType }} else {{ $null }}; {HOST_ROOTS} }} \
         | ConvertTo-Json -Compress"
    )
}

/// The scan of a file to delete: the host-resolved path, the directory flag, the link
/// type and the host roots (DR-6, TR-SEC-04, ADR-0017 §10).
#[must_use]
pub fn delete_file_scan(path: &str) -> String {
    let safe = escape(path);
    format!(
        "$item = Get-Item -LiteralPath '{safe}' -Force -ErrorAction Stop; \
         [PSCustomObject]@{{ FullName=$item.FullName; IsDirectory=[bool]$item.PSIsContainer; \
         LinkType=$item.LinkType; \
         SizeBytes=if($item.PSIsContainer){{$null}}else{{$item.Length}}; \
         Modified=$item.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss',[Globalization.CultureInfo]::InvariantCulture); {HOST_ROOTS} }} \
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

/// The item cap of the pre-scan of a directory source (ADR-0017 §17).
///
/// A larger tree reports lower-bound counts with `Truncated`, so the prompt stays
/// bounded. The copy command re-checks the tree, its link content and the copied
/// count, so a truncated pre-scan cannot hide an incomplete copy.
pub const COPY_SCAN_ITEM_CAP: usize = 20_000;

/// The refusal for a file-operation command that cannot fit one WinRS command line.
fn fit_or_error(command: String) -> Result<String, String> {
    if fits_command_line(&command) {
        Ok(command)
    } else {
        Err(format!(
            "the path is too long; a file-operation command must fit one WinRS command line of \
             {WINRS_COMMAND_LINE_LIMIT} characters; shorten the source or the target"
        ))
    }
}

/// The pre-scan of a file-operation source: the link type, the counts of a directory
/// tree, the presence of a nested link and the host roots (ADR-0017 §16–17).
///
/// `Get-Item -ErrorAction Stop` refuses a missing source. A directory source is
/// walked to the item cap; a larger tree reports `Truncated` true and the counts as
/// lower bounds. `LinkType` is the final component and `NestedLink` marks a link
/// anywhere in the tree, which a recursive copy would follow.
#[must_use]
pub fn copy_source_scan(path: &str) -> String {
    let safe = escape(path);
    let cap = COPY_SCAN_ITEM_CAP;
    let over = cap + 1;
    format!(
        "$ErrorActionPreference = 'Stop'; \
         $item = Get-Item -LiteralPath '{safe}' -Force -ErrorAction Stop; \
         $isDir = [bool]$item.PSIsContainer; \
         $files = 0; $dirs = 0; $bytes = 0; $nested = $false; $trunc = $false; $unread = $false; \
         if ($isDir) {{ \
         $all = @(Get-ChildItem -LiteralPath '{safe}' -Recurse -Force -ErrorAction SilentlyContinue -ErrorVariable walkErr | Select-Object -First {over}); \
         $unread = [bool]($walkErr.Count); \
         $trunc = [bool]($all.Count -gt {cap}); \
         if ($trunc) {{ $all = @($all | Select-Object -First {cap}) }}; \
         $fileItems = @($all | Where-Object {{ -not $_.PSIsContainer }}); \
         $files = $fileItems.Count; \
         $dirs = @($all | Where-Object {{ $_.PSIsContainer }}).Count; \
         $bytes = [long](($fileItems | Measure-Object -Property Length -Sum).Sum); \
         $nested = [bool](@($all | Where-Object {{ $_.LinkType }}).Count -gt 0) \
         }} else {{ \
         $files = 1; $bytes = [long]$item.Length \
         }}; \
         [PSCustomObject]@{{ FullName=$item.FullName; IsDirectory=$isDir; LinkType=$item.LinkType; \
         FileCount=$files; DirCount=$dirs; ByteCount=$bytes; NestedLink=$nested; Truncated=$trunc; Unreadable=$unread; {HOST_ROOTS} }} \
         | ConvertTo-Json -Compress"
    )
}

/// The pre-scan of a download source: the host path, the kind, the link type, the
/// length of the opened stream and the modification time (TR-XFER-02, ADR-0017 §24).
///
/// The path must resolve on the file system provider. The host opens the file with
/// `FileShare.ReadWrite` and `FileShare.Delete`, so a file that another process
/// holds open (a live log) still reads, and it reports `$fs.Length` without reading
/// the content. The tool hashes the bytes while it reads them, and it confirms the
/// whole length with one `SHA-256` pass after the read.
#[must_use]
pub fn download_scan(path: &str) -> String {
    let safe = escape(path);
    format!(
        "$ErrorActionPreference = 'Stop'; \
         $item = Get-Item -LiteralPath '{safe}' -Force -ErrorAction Stop; \
         if ($item.PSProvider.Name -ne 'FileSystem') {{ throw 'The path is not a file system path' }}; \
         $isDir = [bool]$item.PSIsContainer; \
         $size = 0; $modified = $null; \
         if (-not $isDir) {{ \
         $fs = [IO.File]::Open($item.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)); \
         try {{ $size = [long]$fs.Length }} finally {{ $fs.Close() }}; \
         $modified = $item.LastWriteTimeUtc.ToString('o', [Globalization.CultureInfo]::InvariantCulture) \
         }}; \
         [PSCustomObject]@{{ FullName=$item.FullName; IsDirectory=$isDir; LinkType=$item.LinkType; SizeBytes=$size; LastWriteTimeUtc=$modified; {HOST_ROOTS} }} \
         | ConvertTo-Json -Compress"
    )
}

/// One window of the host file as base64 lines (TR-XFER-02, ADR-0017 §24).
///
/// The file is opened with `FileShare.ReadWrite` and `FileShare.Delete`. The stream
/// seeks to `offset` and reads at most `length` bytes, one line of
/// [`TRANSFER_LINE_BYTES`] at a time, so the tool never loads the whole file into
/// the host memory and the call keeps producing output. The caller bounds the
/// window by the length the scan reported, so an append-only log still yields a
/// stable prefix.
#[must_use]
pub fn download_chunk(path: &str, offset: i64, length: i64) -> String {
    let safe = escape(path);
    format!(
        "$ErrorActionPreference = 'Stop'; \
         $fs = [IO.File]::Open('{safe}', [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)); \
         try {{ \
         $null = $fs.Seek({offset}, [IO.SeekOrigin]::Begin); \
         $remaining = {length}; \
         $buf = [byte[]]::new({line}); \
         while ($remaining -gt 0) {{ \
         $take = [int][Math]::Min([long]$buf.Length, [long]$remaining); \
         $n = $fs.Read($buf, 0, $take); \
         if ($n -le 0) {{ break }}; \
         Write-Output ([Convert]::ToBase64String($buf, 0, $n)); \
         $remaining -= $n \
         }} \
         }} finally {{ $fs.Close() }}",
        line = TRANSFER_LINE_BYTES
    )
}

/// The exit code of the host hash pass when the file is shorter than the size the
/// scan reported (TR-XFER-02).
pub const HASH_SHORT_EXIT: i32 = 3;

/// The host SHA-256 of exactly the first `size` bytes (TR-XFER-02, ADR-0017 §24).
///
/// The pass streams the bytes through `TransformBlock` in [`TRANSFER_HASH_READ_BYTES`]
/// pieces, so the host memory stays small, and it prints a progress line every
/// [`TRANSFER_HASH_PROGRESS_BYTES`] so a slow disk never makes the call sit without
/// output. A shorter file prints `short` and exits with code 3; a longer file is
/// hashed only up to `size`, so an append-only log still matches the read window.
/// The final output line carries the digest in lowercase hex.
#[must_use]
pub fn download_hash(path: &str, size: i64) -> String {
    let safe = escape(path);
    format!(
        "$ErrorActionPreference = 'Stop'; \
         $fs = [IO.File]::Open('{safe}', [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)); \
         try {{ \
         $h = [Security.Cryptography.SHA256]::Create(); \
         try {{ \
         $remaining = {size}; \
         $buf = [byte[]]::new({read}); \
         $done = 0; $mark = 0; \
         while ($remaining -gt 0) {{ \
         $take = [int][Math]::Min([long]$buf.Length, [long]$remaining); \
         $n = $fs.Read($buf, 0, $take); \
         if ($n -le 0) {{ break }}; \
         $null = $h.TransformBlock($buf, 0, $n, $null, 0); \
         $remaining -= $n; $done += $n; \
         if (($done - $mark) -ge {progress}) {{ $mark = $done; Write-Output ('progress ' + $done) }} \
         }}; \
         if ($remaining -ne 0) {{ Write-Output 'short'; exit 3 }}; \
         $null = $h.TransformFinalBlock([byte[]]::new(0), 0, 0); \
         Write-Output ([BitConverter]::ToString($h.Hash).Replace('-','').ToLowerInvariant()) \
         }} finally {{ $h.Dispose() }} \
         }} finally {{ $fs.Close() }}",
        read = TRANSFER_HASH_READ_BYTES,
        progress = TRANSFER_HASH_PROGRESS_BYTES
    )
}

/// The raw bytes read by one download read call (TR-XFER-02, ADR-0017 §24).
///
/// One window is emitted as base64 lines inside the text reply. winrm-rs caps one
/// command's output at `max_output_bytes` (64 MiB by default), so the window is
/// sized to stay well below it; see [`transfer_window_fits`].
pub const TRANSFER_WINDOW_BYTES: i64 = 16 * 1024 * 1024;

/// The raw bytes of one base64 output line of a download read call (TR-XFER-02).
///
/// A line of 1 MiB grows to about 1.4 MiB of base64. The host writes line by line,
/// so the call keeps producing output and never sits idle long enough to time out.
pub const TRANSFER_LINE_BYTES: i64 = 1024 * 1024;

/// The read buffer of the host SHA-256 pass (TR-XFER-02).
pub const TRANSFER_HASH_READ_BYTES: i64 = 1024 * 1024;

/// The bytes between two progress lines of the host SHA-256 pass (TR-XFER-02).
///
/// The pass prints a progress line often enough that the call does not sit without
/// output long enough for the transport to time out.
pub const TRANSFER_HASH_PROGRESS_BYTES: i64 = 8 * 1024 * 1024;

/// The output cap of one command on the winrm-rs side, in bytes (ADR-0017 §24).
///
/// winrm-rs fails a command whose output exceeds this value. It mirrors
/// `WinrmConfig::default().max_output_bytes`.
pub const WINRM_MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

/// True when one full read window, as base64 lines and with the line and envelope
/// overhead, stays under the winrm-rs output cap (TR-XFER-02).
#[must_use]
pub fn transfer_window_fits() -> bool {
    let window = TRANSFER_WINDOW_BYTES as usize;
    let base64 = 4 * window.div_ceil(3);
    let line_overhead = window / (TRANSFER_LINE_BYTES as usize) * 2;
    base64 + line_overhead + 4096 <= WINRM_MAX_OUTPUT_BYTES
}

/// Size of the chunk that one host command receives on its standard input
/// (TR-XFER-04, ADR-0017 §26).
///
/// One window is one host command whose standard input carries the bytes, so the
/// WinRS command line does not bound it. The call overhead (one NTLM handshake, one
/// shell) is paid once per window, which is why the window is large.
pub const UPLOAD_WINDOW_BYTES: i64 = 4 * 1024 * 1024;

/// The most parent directories the upload commit inspects for a link (TR-XFER-04).
///
/// A deeper path is refused, so the loop is bounded and fails closed.
pub const UPLOAD_PARENT_DEPTH: i32 = 128;

/// The exit code of the upload commit when the host SHA-256 differs from the
/// confirmed one (TR-XFER-04).
pub const UPLOAD_MISMATCH_EXIT: i32 = 4;

/// One upload window from the standard input into the host temp file (TR-XFER-04,
/// ADR-0017 §26).
///
/// The first window (`offset` 0) creates the temp file with `CreateNew`, so an
/// existing file or a link at the temp path refuses. Every later window opens the
/// file and requires its length to equal `offset`, so a repeated or a lost window
/// fails instead of corrupting the content. The file is opened with `FileShare.Delete`,
/// so the cleanup delete can succeed while a stalled window still holds the handle.
/// The script prints the new length of the file; the caller compares it with
/// `offset + length`. The bytes arrive on the standard input and never enter the
/// command text.
///
/// # Errors
///
/// An error text when the command cannot fit one WinRS command line.
pub fn upload_chunk(temp_path: &str, offset: i64, length: i64) -> Result<String, String> {
    let safe = escape(temp_path);
    fit_or_error(format!(
        "$ErrorActionPreference = 'Stop'; \
         $mode = if ({offset} -eq 0) {{ [IO.FileMode]::CreateNew }} else {{ [IO.FileMode]::Open }}; \
         $fs = [IO.File]::Open('{safe}', $mode, [IO.FileAccess]::Write, [IO.FileShare]::Delete); \
         try {{ \
         if ($fs.Length -ne {offset}) {{ throw 'the host temp file is not the length the tool expects' }}; \
         $null = $fs.Seek(0, [IO.SeekOrigin]::End); \
         $stdin = [Console]::OpenStandardInput(); \
         $buf = [byte[]]::new({read}); \
         $got = 0; \
         while ($true) {{ \
         $n = $stdin.Read($buf, 0, $buf.Length); \
         if ($n -le 0) {{ break }}; \
         $fs.Write($buf, 0, $n); \
         $got += $n \
         }}; \
         $fs.Flush(); \
         if ($got -ne {length}) {{ throw 'the host received a different number of bytes than the tool sent' }}; \
         Write-Output ([string]$fs.Length) \
         }} finally {{ $fs.Close() }}",
        read = TRANSFER_HASH_READ_BYTES
    ))
}

/// The final step of an upload: the host hash of the temp file, the target re-check
/// and the placement (TR-XFER-04, ADR-0017 §26).
///
/// The temp file opens with `FileShare.Read`, so nothing writes to it while it is
/// hashed. A length other than `size` prints `short` and exits with
/// [`HASH_SHORT_EXIT`]; a digest other than `sha256` prints the digest and exits with
/// [`UPLOAD_MISMATCH_EXIT`], and in both cases the target stays untouched. The
/// command repeats the target checks of the scan: an existing directory or a name
/// surrogate refuses, and an existing file needs `overwrite`. Without `overwrite` the
/// placement is `[IO.File]::Move`, which refuses a target that appeared after the
/// check. Before it places anything, the command requires the target to be its own full
/// path and every parent directory up to the root to be free of a symbolic link or a
/// junction. With `overwrite` it is the atomic `[IO.File]::Replace`. Each path enters the
/// command once, so a long path still fits the command line. The output is the digest
/// line, then `placed`.
///
/// # Errors
///
/// An error text when `sha256` is not 64 hexadecimal characters, or when the command
/// cannot fit one WinRS command line.
pub fn upload_commit(
    temp_path: &str,
    target_path: &str,
    size: i64,
    sha256: &str,
    overwrite: bool,
) -> Result<String, String> {
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("the SHA-256 is not 64 hexadecimal characters".to_owned());
    }
    let safe_temp = escape(temp_path);
    let safe_target = escape(target_path);
    let safe_hash = escape(sha256);
    let ow = ps_bool(overwrite);
    // `[NullString]::Value` keeps the backup name a typed null (see
    // `replace_target_command`).
    let place = if overwrite {
        "if ([IO.File]::Exists($dst)) { [IO.File]::Replace($src, $dst, [NullString]::Value) } \
         else { [IO.File]::Move($src, $dst) }"
    } else {
        "[IO.File]::Move($src, $dst)"
    };
    fit_or_error(format!(
        "$ErrorActionPreference = 'Stop'; \
         $src = '{safe_temp}'; $dst = '{safe_target}'; \
         $fs = [IO.File]::Open($src, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read); \
         try {{ \
         $h = [Security.Cryptography.SHA256]::Create(); \
         try {{ \
         if ($fs.Length -ne {size}) {{ Write-Output 'short'; exit {short} }}; \
         $buf = [byte[]]::new({read}); \
         $done = 0; $mark = 0; \
         while ($true) {{ \
         $n = $fs.Read($buf, 0, $buf.Length); \
         if ($n -le 0) {{ break }}; \
         $null = $h.TransformBlock($buf, 0, $n, $null, 0); \
         $done += $n; \
         if (($done - $mark) -ge {progress}) {{ $mark = $done; Write-Output ('progress ' + $done) }} \
         }}; \
         $null = $h.TransformFinalBlock([byte[]]::new(0), 0, 0); \
         $actual = [BitConverter]::ToString($h.Hash).Replace('-','').ToLowerInvariant() \
         }} finally {{ $h.Dispose() }} \
         }} finally {{ $fs.Close() }}; \
         Write-Output $actual; \
         if ($actual -ne '{safe_hash}') {{ exit {mismatch} }}; \
         if ([IO.Path]::GetFullPath($dst) -ne $dst) {{ throw 'the target path is not the path the scan resolved' }}; \
         $d = [IO.Path]::GetDirectoryName($dst); $n = 0; \
         while ($d -and [IO.Path]::GetDirectoryName($d) -and ($n -lt {depth})) {{ \
         $di = Get-Item -LiteralPath $d -Force -ErrorAction Stop; \
         if (($di.Attributes -band [IO.FileAttributes]::ReparsePoint) -and ($di.LinkType -in 'SymbolicLink','Junction')) {{ throw 'a parent directory of the target is a symbolic link or a junction; the tool refuses' }}; \
         $d = [IO.Path]::GetDirectoryName($d); $n++ \
         }}; \
         if ($n -ge {depth}) {{ throw 'the target path is too deep to check' }}; \
         $t = $null; if (Test-Path -LiteralPath $dst) {{ $t = Get-Item -LiteralPath $dst -Force -ErrorAction Stop }}; \
         if ($t) {{ \
         if ($t.PSIsContainer) {{ throw 'the target is an existing directory; delete it first with delete_directory' }}; \
         if ($t.LinkType -in 'SymbolicLink','Junction') {{ throw 'the target is a symbolic link or a junction; the tool refuses' }}; \
         if (-not {ow}) {{ throw 'the target already exists; pass overwrite=true to replace it' }} \
         }}; \
         {place}; \
         Write-Output 'placed'",
        read = TRANSFER_HASH_READ_BYTES,
        progress = TRANSFER_HASH_PROGRESS_BYTES,
        depth = UPLOAD_PARENT_DEPTH,
        short = HASH_SHORT_EXIT,
        mismatch = UPLOAD_MISMATCH_EXIT
    ))
}

/// Removes the host temp file of an upload and proves it (TR-XFER-04).
///
/// The exit code is 0 only when the file is gone afterwards, so the caller trusts the
/// code and not the absence of an error text.
///
/// # Errors
///
/// An error text when the command cannot fit one WinRS command line.
pub fn upload_remove_temp(temp_path: &str) -> Result<String, String> {
    let safe = escape(temp_path);
    fit_or_error(format!(
        "$p = '{safe}'; \
         Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue; \
         if (Test-Path -LiteralPath $p) {{ exit 1 }}; \
         exit 0"
    ))
}

/// The PowerShell boolean literal for a confirmation flag.
fn ps_bool(value: bool) -> &'static str {
    if value { "$true" } else { "$false" }
}

/// Replaces a target file with a source file without a wildcard-aware parameter
/// (ADR-0017 §18).
///
/// The `-Destination` parameter of `Move-Item` and `Copy-Item` expands a wildcard,
/// so `C:\[W]indows\x` would reach `System32`. `[IO.File]::Replace` and
/// `[IO.File]::Move` act on the literal path. `Replace` needs an existing target,
/// so a missing target uses `Move`.
fn replace_target_command(from: &str, to: &str) -> String {
    let safe_from = escape(from);
    let safe_to = escape(to);
    // `[NullString]::Value` passes a typed null to the `string` backup parameter;
    // a bare `$null` becomes `""`, which `File.Replace` rejects.
    format!(
        "if ([IO.File]::Exists('{safe_to}')) {{ [IO.File]::Replace('{safe_from}', '{safe_to}', [NullString]::Value) }} \
         else {{ [IO.File]::Move('{safe_from}', '{safe_to}') }}"
    )
}

/// The copy of a file or a directory (TR-FS-09, ADR-0017 §17).
///
/// The command repeats the safety checks before it writes: the source must not be a
/// name surrogate, its kind must match the confirmation, the target must not be an
/// existing directory or a name surrogate, and without `overwrite` the target must not
/// exist. A directory tree is walked once; a name surrogate anywhere in it is refused,
/// because a recursive walk would follow it. The copy uses the `[IO.File]` and
/// `[IO.Directory]` classes, whose parameters do not expand a wildcard. On a partial
/// failure the command returns `copied`, `total` and a plain `error`, and it exits
/// non-zero, so a partial copy is never reported as success.
///
/// # Errors
///
/// An error text when the command cannot fit one WinRS command line.
pub fn copy_command(
    source: &str,
    target: &str,
    overwrite: bool,
    is_directory: bool,
) -> Result<String, String> {
    let safe_src = escape(source);
    let safe_tgt = escape(target);
    let expect = ps_bool(is_directory);
    let ow = ps_bool(overwrite);
    let mode = if is_directory { "directory" } else { "file" };
    let body = if is_directory {
        format!(
            "$items = @(Get-ChildItem -LiteralPath '{safe_src}' -Recurse -Force -ErrorAction SilentlyContinue -ErrorVariable walkErr); \
             if ($walkErr.Count) {{ throw 'Refusing to copy: the source tree is not fully readable; a copy would be partial' }}; \
             if (@($items | Where-Object {{ $_.LinkType }}).Count -gt 0) {{ throw 'Refusing to copy: the source tree contains a symbolic link or a junction' }}; \
             $total = @($items | Where-Object {{ -not $_.PSIsContainer }}).Count; \
             $writing = $true; \
             [IO.Directory]::CreateDirectory('{safe_tgt}') | Out-Null; \
             foreach ($it in $items) {{ \
             $rel = $it.FullName.Substring($s.FullName.Length).TrimStart('\\'); \
             $dst = [IO.Path]::Combine('{safe_tgt}', $rel); \
             if ($it.PSIsContainer) {{ [IO.Directory]::CreateDirectory($dst) | Out-Null }} \
             else {{ [IO.File]::Copy($it.FullName, $dst, {ow}) | Out-Null; $copied++ }} \
             }}; \
             if ($copied -ne $total) {{ throw \"the copy is incomplete: $copied of $total files\" }}"
        )
    } else {
        format!(
            "$writing = $true; \
             $total = 1; \
             [IO.File]::Copy($s.FullName, '{safe_tgt}', {ow}) | Out-Null; \
             $copied = 1; \
             if ((Get-Item -LiteralPath '{safe_tgt}' -Force).Length -ne $s.Length) {{ throw 'the copied file is not the same size as the source' }}"
        )
    };
    fit_or_error(format!(
        "$ErrorActionPreference = 'Stop'; \
         $err = ''; $copied = 0; $total = 0; $writing = $false; \
         try {{ \
         $s = Get-Item -LiteralPath '{safe_src}' -Force -ErrorAction Stop; \
         if ($s.LinkType) {{ throw 'Refusing to copy: the source is a symbolic link or a junction' }}; \
         if ([bool]$s.PSIsContainer -ne {expect}) {{ throw 'the source is not the kind the confirmation showed; the tool refuses' }}; \
         $t = $null; if (Test-Path -LiteralPath '{safe_tgt}') {{ $t = Get-Item -LiteralPath '{safe_tgt}' -Force -ErrorAction Stop }}; \
         if ($t) {{ \
         if ($t.PSIsContainer) {{ throw 'the target is an existing directory; delete it first with delete_directory' }}; \
         if ($t.LinkType) {{ throw 'the target is a symbolic link or a junction; the tool refuses' }}; \
         if (-not {ow}) {{ throw 'the target already exists; pass overwrite=true to replace it' }} \
         }}; \
         {body} \
         }} catch {{ if ($writing) {{ $err = 'the target may be partial: ' + $_.Exception.Message }} else {{ $err = $_.Exception.Message }} }}; \
         [PSCustomObject]@{{ Mode='{mode}'; Total=$total; Copied=$copied; Error=$err }} | ConvertTo-Json -Compress; \
         if ($err) {{ exit 1 }}"
    ))
}

/// The same-volume move of a file or a directory (ADR-0017 §18).
///
/// `[IO.File]::Move` and `[IO.Directory]::Move` act on the literal path and stay on
/// one volume. An existing file target needs `overwrite`, and the replacement uses
/// the atomic `[IO.File]::Replace`; an existing directory target is refused in all
/// cases. The command refuses a name surrogate and a source whose kind changed.
///
/// # Errors
///
/// An error text when the command cannot fit one WinRS command line.
pub fn move_rename_command(
    source: &str,
    target: &str,
    is_directory: bool,
    overwrite: bool,
) -> Result<String, String> {
    move_item_command(source, target, is_directory, overwrite)
}

/// The rename of the last path component inside its own directory (TR-FS-10,
/// ADR-0017 §19). The operation is the same same-volume move, so the command is
/// shared with [`move_rename_command`].
///
/// # Errors
///
/// An error text when the command cannot fit one WinRS command line.
pub fn rename_command(
    source: &str,
    target: &str,
    is_directory: bool,
    overwrite: bool,
) -> Result<String, String> {
    move_item_command(source, target, is_directory, overwrite)
}

/// The shared same-volume move command for `move_file` and `rename_file`.
fn move_item_command(
    source: &str,
    target: &str,
    is_directory: bool,
    overwrite: bool,
) -> Result<String, String> {
    let safe_src = escape(source);
    let safe_tgt = escape(target);
    let expect = ps_bool(is_directory);
    let ow = ps_bool(overwrite);
    let action = if is_directory {
        format!("[IO.Directory]::Move($s.FullName, '{safe_tgt}')")
    } else {
        // `[NullString]::Value` keeps the `string` backup parameter typed; a bare
        // `$null` becomes `""` and `File.Replace` rejects it.
        format!(
            "if ($t) {{ if (-not {ow}) {{ throw 'the target already exists; pass overwrite=true to replace it' }}; \
             [IO.File]::Replace($s.FullName, '{safe_tgt}', [NullString]::Value) }} \
             else {{ [IO.File]::Move($s.FullName, '{safe_tgt}') }}"
        )
    };
    fit_or_error(format!(
        "$ErrorActionPreference = 'Stop'; \
         $s = Get-Item -LiteralPath '{safe_src}' -Force -ErrorAction Stop; \
         if ($s.LinkType) {{ throw 'Refusing to move: the source is a symbolic link or a junction' }}; \
         if ([bool]$s.PSIsContainer -ne {expect}) {{ throw 'the source is not the kind the confirmation showed; the tool refuses' }}; \
         $t = $null; if (Test-Path -LiteralPath '{safe_tgt}') {{ $t = Get-Item -LiteralPath '{safe_tgt}' -Force -ErrorAction Stop }}; \
         if ($t) {{ \
         if ($t.PSIsContainer) {{ throw 'the target is an existing directory; the tool does not replace a directory' }}; \
         if ($t.LinkType) {{ throw 'the target is a symbolic link or a junction; the tool refuses' }} \
         }}; \
         {action}; \
         if (Test-Path -LiteralPath '{safe_src}') {{ throw 'the source still exists after the move' }}; \
         Write-Output 'Moved'"
    ))
}

/// The same-volume move for a change of case only (`a.txt` → `A.txt`), TR-FS-10.
///
/// `[IO.File]::Move` and `[IO.Directory]::Move` treat a case-only target as the same
/// object and refuse, so the move goes through a unique temporary name in the same
/// directory. The command does not re-read the source path afterwards: `Test-Path` is
/// case-insensitive and would report the renamed object as still present. The
/// overwrite flag does not apply, because the target is the same object.
///
/// # Errors
///
/// An error text when the command cannot fit one WinRS command line.
pub fn move_case_command(
    source: &str,
    target: &str,
    is_directory: bool,
    overwrite: bool,
) -> Result<String, String> {
    let safe_src = escape(source);
    let safe_tgt = escape(target);
    let expect = ps_bool(is_directory);
    let ow = ps_bool(overwrite);
    let move_class = if is_directory {
        "[IO.Directory]::Move"
    } else {
        "[IO.File]::Move"
    };
    fit_or_error(format!(
        "$ErrorActionPreference = 'Stop'; \
         $s = Get-Item -LiteralPath '{safe_src}' -Force -ErrorAction Stop; \
         if ($s.LinkType) {{ throw 'Refusing to move: the source is a symbolic link or a junction' }}; \
         if ([bool]$s.PSIsContainer -ne {expect}) {{ throw 'the source is not the kind the confirmation showed; the tool refuses' }}; \
         $t = $null; if (Test-Path -LiteralPath '{safe_tgt}') {{ $t = Get-Item -LiteralPath '{safe_tgt}' -Force -ErrorAction Stop }}; \
         if ($t -and -not $s.FullName.Equals($t.FullName, [StringComparison]::Ordinal)) {{ \
         if ($t.PSIsContainer) {{ throw 'the target is an existing directory; the tool does not replace a directory' }}; \
         if ($t.LinkType) {{ throw 'the target is a symbolic link or a junction; the tool refuses' }}; \
         if (-not {ow}) {{ throw 'the target already exists; pass overwrite=true to replace it' }} \
         }}; \
         $tmp = [IO.Path]::Combine([IO.Path]::GetDirectoryName($s.FullName), '.winrig-' + [Guid]::NewGuid().ToString('N') + '.tmp'); \
         {move_class}($s.FullName, $tmp); {move_class}($tmp, '{safe_tgt}'); \
         Write-Output 'Moved'"
    ))
}

/// The cross-volume move of a file: copy, verify the size, then delete (TR-FS-10).
///
/// The delete falls under DR-6, so the command refuses a directory at run time (a
/// change between the confirmation and the call cannot turn a file move into a
/// recursive delete), and it deletes the source only when the copied length matches.
/// The copy uses `[IO.File]::Copy`, whose path does not expand a wildcard. The result
/// carries `copied`, `total` and a plain `error`: a failed copy names a partial
/// target, a failed delete names two remaining copies, and the exit code is non-zero.
///
/// # Errors
///
/// An error text when the command cannot fit one WinRS command line.
pub fn move_copy_delete_command(
    source: &str,
    target: &str,
    overwrite: bool,
) -> Result<String, String> {
    let safe_src = escape(source);
    let safe_tgt = escape(target);
    let ow = ps_bool(overwrite);
    fit_or_error(format!(
        "$ErrorActionPreference = 'Stop'; \
         $err = ''; $copied = 0; $total = 1; $phase = 'copy'; \
         try {{ \
         $s = Get-Item -LiteralPath '{safe_src}' -Force -ErrorAction Stop; \
         if ($s.LinkType) {{ throw 'Refusing to move: the source is a symbolic link or a junction' }}; \
         if ($s.PSIsContainer) {{ throw 'Refusing a cross-volume move of a directory; copy it and delete the source in two calls' }}; \
         $t = $null; if (Test-Path -LiteralPath '{safe_tgt}') {{ $t = Get-Item -LiteralPath '{safe_tgt}' -Force -ErrorAction Stop }}; \
         if ($t) {{ \
         if ($t.PSIsContainer) {{ throw 'the target is an existing directory; delete it first with delete_directory' }}; \
         if ($t.LinkType) {{ throw 'the target is a symbolic link or a junction; the tool refuses' }}; \
         if (-not {ow}) {{ throw 'the target already exists; pass overwrite=true to replace it' }} \
         }}; \
         $before = [long]$s.Length; \
         [IO.File]::Copy($s.FullName, '{safe_tgt}', {ow}) | Out-Null; \
         $after = [long](Get-Item -LiteralPath '{safe_tgt}' -Force).Length; \
         if ($after -ne $before) {{ throw 'Refusing to delete the source: the copy is not complete' }}; \
         $phase = 'delete'; \
         [IO.File]::Delete($s.FullName); \
         if (Test-Path -LiteralPath '{safe_src}') {{ throw 'the source still exists after the move' }}; \
         $copied = 1 \
         }} catch {{ if ($phase -eq 'delete') {{ $err = 'the copy is complete but the source was not deleted; both copies remain: ' + $_.Exception.Message }} else {{ $err = 'the target may be partial: ' + $_.Exception.Message }} }}; \
         [PSCustomObject]@{{ Mode='file'; Total=$total; Copied=$copied; Error=$err }} | ConvertTo-Json -Compress; \
         if ($err) {{ exit 1 }}"
    ))
}

/// The pre-scan of a `create_directory` target: the path, the directory flag, the
/// link type, the count and the top of the created levels and the host roots
/// (TR-FS-11).
///
/// The count walks up from the resolved path while a level is absent, so the prompt
/// names the number of directories the tool will add. `TopMissing` is the shallowest
/// absent level: it is the highest directory the call would create, and the caller
/// checks it against the strict-descendant rule of the write boundary.
#[must_use]
pub fn create_directory_scan(path: &str) -> String {
    let safe = escape(path);
    format!(
        "$ErrorActionPreference = 'Stop'; \
         $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath('{safe}'); \
         $net = [IO.Path]::GetFullPath('{safe}'); \
         $exists = [bool](Test-Path -LiteralPath '{safe}'); \
         $it = if ($exists) {{ Get-Item -LiteralPath '{safe}' -Force -ErrorAction Stop }} else {{ $null }}; \
         $levels = 0; $top = ''; $cur = $full; \
         while ($cur -and -not (Test-Path -LiteralPath $cur)) {{ $levels++; $top = $cur; $cur = Split-Path -Parent $cur }}; \
         [PSCustomObject]@{{ FullName=$full; DotNetFullName=$net; Exists=$exists; \
         IsDirectory=[bool]($it -and $it.PSIsContainer); LinkType=if ($it) {{ $it.LinkType }} else {{ $null }}; \
         MissingLevels=$levels; TopMissing=$top; {HOST_ROOTS} }} | ConvertTo-Json -Compress"
    )
}

/// The creation of a directory and its missing parents (TR-FS-11, ADR-0017 §20).
///
/// `[IO.Directory]::CreateDirectory` creates the parents and acts on the literal
/// path, so a wildcard in the path cannot expand. An existing file or directory is a
/// refusal: the tool creates only a missing directory.
///
/// # Errors
///
/// An error text when the command cannot fit one WinRS command line.
pub fn create_directory_command(path: &str) -> Result<String, String> {
    let safe = escape(path);
    fit_or_error(format!(
        "$ErrorActionPreference = 'Stop'; \
         if ([IO.File]::Exists('{safe}')) {{ throw 'the path is an existing file; the tool creates only a missing directory' }}; \
         if ([IO.Directory]::Exists('{safe}')) {{ throw 'the directory already exists; the tool creates only a missing directory' }}; \
         [IO.Directory]::CreateDirectory('{safe}') | Out-Null; \
         if (-not [IO.Directory]::Exists('{safe}')) {{ throw 'the directory was not created' }}; \
         Write-Output 'Created'"
    ))
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

/// The largest tail window the `exclude` filter grows to, in lines (TR-REL-16).
///
/// The window starts at ten times the requested count and grows tenfold until it
/// holds the count of lines without the literal, the file ends, or the window
/// reaches this bound. The lines stream through `Get-Content -ReadCount`, so the
/// host holds one batch and the queue of the requested count, not the window.
const TAIL_EXCLUDE_MAX_WINDOW: usize = 200_000;

/// The lines in one streamed batch of the `exclude` window.
const TAIL_EXCLUDE_READ_COUNT: usize = 1000;

/// # Errors
///
/// Returns an error text for an unknown encoding, an invalid range, an `exclude`
/// without the tail mode, or a command that does not fit one WinRS command line.
pub fn read_file(
    path: &str,
    start_line: i64,
    end_line: i64,
    tail: bool,
    encoding: &str,
    exclude: &str,
) -> Result<String, String> {
    let enc_key = encoding.trim().to_lowercase();
    if !VALID_ENCODINGS.contains(&enc_key.as_str()) {
        return Err(format!(
            "Invalid encoding '{encoding}'. Valid values: {}",
            VALID_ENCODINGS.join(", ")
        ));
    }
    if !tail && !exclude.trim().is_empty() {
        return Err("exclude works only with tail=true".to_owned());
    }
    let safe = escape(path);
    let command = if tail {
        let count = cap(end_line, 1, 500);
        if exclude.trim().is_empty() {
            format!(
                "$lines = @(Get-Content -LiteralPath '{safe}' -Tail {count} -Encoding {enc_key} -ErrorAction Stop); \
                 $n = 1; $lines | ForEach-Object {{ '{{0,6}}|{{1}}' -f ($n++), $_ }}; \
                 Write-Output (\"--- tail: last $($lines.Count) lines ---\")"
            )
        } else {
            // The window grows from the end of the file until it holds `count`
            // lines without the literal, so the host reads only as much as it
            // needs and never the whole file. The lines stream in batches, and the
            // queue keeps only the requested count. `IndexOf` is a literal
            // substring test, not a wildcard pattern (TR-REL-16, Q-22).
            let safe_exclude = escape(exclude);
            format!(
                "$want = {count}; $W = $want * 10; $max = {TAIL_EXCLUDE_MAX_WINDOW}; $lines = @(); $covered = $false; \
                 while (-not $covered) {{ \
                 $q = [System.Collections.Generic.Queue[string]]::new(); $read = 0; \
                 Get-Content -LiteralPath '{safe}' -Tail $W -ReadCount {TAIL_EXCLUDE_READ_COUNT} -Encoding {enc_key} -ErrorAction Stop | ForEach-Object {{ \
                 foreach ($line in $_) {{ $read++; if ($line.IndexOf('{safe_exclude}', [StringComparison]::OrdinalIgnoreCase) -lt 0) {{ $q.Enqueue($line); if ($q.Count -gt $want) {{ [void]$q.Dequeue() }} }} }} }}; \
                 $lines = @($q.ToArray()); \
                 if ($lines.Count -ge $want -or $read -lt $W -or $W -ge $max) {{ $covered = $true }} else {{ $W = $W * 10; if ($W -gt $max) {{ $W = $max }} }} \
                 }}; \
                 $n = 1; $lines | ForEach-Object {{ '{{0,6}}|{{1}}' -f ($n++), $_ }}; \
                 Write-Output (\"--- tail: last $($lines.Count) lines (excluded lines are dropped) ---\")"
            )
        }
    } else {
        let start = start_line.max(1);
        if end_line < start {
            return Err("end_line must be >= start_line".to_owned());
        }
        let end = if end_line - start + 1 > 500 {
            start + 499
        } else {
            end_line
        };
        read_file_range(&safe, start, end, &enc_key)
    };
    if !fits_command_line(&command) {
        return Err(format!(
            "the read command does not fit the WinRS command line of \
             {WINRS_COMMAND_LINE_LIMIT} characters; shorten the path or the exclude pattern"
        ));
    }
    Ok(command)
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

/// When the caller gives no format, the search uses this one (TR-REL-16).
pub const DEFAULT_TIMESTAMP_FORMAT: &str = "yyyy-MM-dd HH:mm:ss";

// Fixed-width .NET custom date and time specifiers. A variable-width specifier
// (`M`, `d`, `H`, `h`, `m`, `s`, `t` alone, `F`, `g`, `K`, `z`) is refused,
// because the host takes a timestamp prefix of a fixed length (TR-REL-16).
const TIMESTAMP_SPECIFIER_LETTERS: [char; 13] = [
    'd', 'f', 'F', 'g', 'h', 'H', 'K', 'm', 'M', 's', 't', 'y', 'z',
];

// Time filter block of the search (TR-REL-16). The timestamp prefix is parsed
// with the invariant culture, so the comparison does not depend on the host
// locale. A line without a timestamp is outside the range and does not match.
const TIMESTAMP_WHERE: &str = "| Where-Object { $ln=$_.Line; \
    if($ln.Length -lt $len){ $false } else { $ts=[DateTime]::MinValue; \
    [DateTime]::TryParseExact($ln.Substring(0,$len),$fmt,$inv,[Globalization.DateTimeStyles]::None,[ref]$ts) \
    -and $ts -ge $since -and $ts -le $until } } ";

// The line format of one match in a file, in a directory and with context lines.
const SEARCH_LINE_FILE: &str = "| ForEach-Object { \"$($_.LineNumber)|$($_.Line)\" }";
const SEARCH_LINE_DIR: &str = "| ForEach-Object { \"$($_.Path):$($_.LineNumber)|$($_.Line)\" }";
const SEARCH_LINE_CTX: &str = "| Out-String -Width 300";

/// Extra filters of the log search (TR-REL-16, Q-22).
pub struct SearchOptions<'a> {
    /// Return the last matches instead of the first. AC-REL16-1.
    pub from_end: bool,
    /// Return only the number of matches for each file. AC-REL16-1.
    pub count_only: bool,
    /// Lower time bound of the line timestamp, or empty for no lower bound.
    pub since: &'a str,
    /// Upper time bound of the line timestamp, or empty for no upper bound.
    pub until: &'a str,
    /// The .NET custom format of the timestamp at the start of a line (Q-22).
    pub timestamp_format: &'a str,
}

/// True when a run of one specifier letter renders at a fixed width.
fn timestamp_spec_is_fixed(letter: char, run: usize) -> bool {
    match letter {
        'y' => matches!(run, 2 | 4),
        'M' | 'd' => matches!(run, 2 | 3),
        'H' | 'h' | 'm' | 's' => run == 2,
        'f' => (1..=7).contains(&run),
        't' => run == 2,
        _ => false,
    }
}

/// # Errors
///
/// Refuses an empty format, a single-character standard format, a quoted or
/// escaped literal, a non-ASCII character, and a specifier that is not a fixed
/// width (TR-REL-16).
fn validate_timestamp_format(format: &str) -> Result<(), String> {
    if format.is_empty() {
        return Err("timestamp_format is empty".to_owned());
    }
    if format.chars().count() == 1 {
        return Err(format!(
            "timestamp_format '{format}' is a .NET standard format; use a custom format such as yyyy-MM-dd HH:mm:ss"
        ));
    }
    let chars: Vec<char> = format.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if ['\'', '"', '\\', '%'].contains(&c) {
            return Err(format!(
                "timestamp_format holds '{c}'; quoted, escaped and single-specifier forms are not allowed"
            ));
        }
        if !c.is_ascii() {
            return Err(format!(
                "timestamp_format holds the non-ASCII character '{c}'; use ASCII digits and separators"
            ));
        }
        if c.is_ascii_alphabetic() {
            let mut j = i;
            while j < chars.len() && chars[j] == c {
                j += 1;
            }
            let run = j - i;
            if TIMESTAMP_SPECIFIER_LETTERS.contains(&c) && !timestamp_spec_is_fixed(c, run) {
                return Err(format!(
                    "timestamp_format specifier '{c}' repeated {run} time(s) is not a fixed-width date field; \
                     use yyyy, yy, MM, MMM, dd, ddd, HH, hh, mm, ss, f..fffffff or tt"
                ));
            }
            i = j;
        } else {
            i += 1;
        }
    }
    Ok(())
}

/// A Gregorian calendar adds a day to February when the divisibility rule holds.
///
/// The rule is a multiple of 4, but not of 100 unless it is also a multiple of 400.
fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// The length of a calendar period, or 0 when the value is outside 1 to 12.
fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// A bound as `YYYY-MM-DDTHH:MM:SS.fffffff` in the host local time (TR-REL-16).
///
/// The fractional part is kept at full .NET precision (seven digits) and the
/// comparison on the host runs at that precision. A date without a time is the
/// start of the day for `since` and the end of the day for `until`.
///
/// # Errors
///
/// Refuses a value that is not a real `YYYY-MM-DD [HH:MM[:SS[.fffffff]]]` date in
/// the host local time.
fn parse_time_bound(value: &str, is_until: bool) -> Result<String, String> {
    let text = value.trim();
    let (date, time) = match text.split_once(['T', ' ']) {
        Some((date, time)) => (date, time.trim()),
        None => (text, ""),
    };
    let invalid = || {
        format!(
            "Invalid timestamp '{value}'. Use YYYY-MM-DD [HH:MM[:SS[.fffffff]]] in the host local time, without a zone"
        )
    };
    let date_parts: Vec<&str> = date.split('-').collect();
    if date_parts.len() != 3 {
        return Err(invalid());
    }
    let year = fixed_digits(date_parts[0], 4).ok_or_else(&invalid)?;
    let month = fixed_digits(date_parts[1], 2).ok_or_else(&invalid)?;
    let day = fixed_digits(date_parts[2], 2).ok_or_else(&invalid)?;
    if !(1..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
    {
        return Err(invalid());
    }
    if time.is_empty() {
        return Ok(if is_until {
            format!("{year:04}-{month:02}-{day:02}T23:59:59.9999999")
        } else {
            format!("{year:04}-{month:02}-{day:02}T00:00:00.0000000")
        });
    }
    let (clock, fraction) = match time.split_once('.') {
        Some((clock, fraction)) => (clock, Some(fraction)),
        None => (time, None),
    };
    let time_parts: Vec<&str> = clock.split(':').collect();
    if time_parts.len() < 2 || time_parts.len() > 3 {
        return Err(invalid());
    }
    let hour = fixed_digits(time_parts[0], 2).ok_or_else(&invalid)?;
    let minute = fixed_digits(time_parts[1], 2).ok_or_else(&invalid)?;
    let second = if time_parts.len() == 3 {
        fixed_digits(time_parts[2], 2).ok_or_else(&invalid)?
    } else {
        0
    };
    if !(0..=23).contains(&hour) || !(0..=59).contains(&minute) || !(0..=59).contains(&second) {
        return Err(invalid());
    }
    let fraction = match fraction {
        None => "0000000".to_owned(),
        Some(digits) => {
            if digits.is_empty() || digits.len() > 7 || !digits.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(invalid());
            }
            format!("{digits:0<7}")
        }
    };
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{fraction}"
    ))
}

/// The numeric value of `text` when it is exactly `len` ASCII digits.
fn fixed_digits(text: &str, len: usize) -> Option<i64> {
    if text.len() == len && text.bytes().all(|b| b.is_ascii_digit()) {
        text.parse().ok()
    } else {
        None
    }
}

/// The prelude and the `Where-Object` block of the line time filter (TR-REL-16).
fn build_time_filter(
    since: &str,
    until: &str,
    format: &str,
) -> Result<(String, &'static str), String> {
    let format = if format.trim().is_empty() {
        DEFAULT_TIMESTAMP_FORMAT
    } else {
        format
    };
    validate_timestamp_format(format)?;
    let since_iso = if since.trim().is_empty() {
        None
    } else {
        Some(parse_time_bound(since, false)?)
    };
    let until_iso = if until.trim().is_empty() {
        None
    } else {
        Some(parse_time_bound(until, true)?)
    };
    if let (Some(since_iso), Some(until_iso)) = (&since_iso, &until_iso) {
        // Both values are fixed-width ISO, so a string compare is a time compare.
        if since_iso > until_iso {
            return Err(format!("since '{since}' is after until '{until}'"));
        }
    }
    let bound = |iso: &Option<String>, empty: &str| match iso {
        Some(iso) => format!(
            "[DateTime]::ParseExact('{iso}','yyyy-MM-ddTHH:mm:ss.fffffff',$inv,[Globalization.DateTimeStyles]::None)"
        ),
        None => empty.to_owned(),
    };
    let since_expr = bound(&since_iso, "[DateTime]::MinValue");
    let until_expr = bound(&until_iso, "[DateTime]::MaxValue");
    let prelude = format!(
        "$inv=[Globalization.CultureInfo]::InvariantCulture; $fmt='{}'; \
         $len=(Get-Date).ToString($fmt,$inv).Length; $since={since_expr}; $until={until_expr}; ",
        escape(format)
    );
    Ok((prelude, TIMESTAMP_WHERE))
}

/// Searches the literal text in one file or in a directory (TR-REL-06, TR-REL-16).
///
/// The search streams the file: `Select-String` reads line by line and
/// `Select-Object -First` or `-Last` keeps a bounded number of matches, so the
/// host does not hold the whole file. The `from_end`, `count_only`, `since`,
/// `until` and `timestamp_format` options come from [`SearchOptions`]; a line
/// without a timestamp does not match an active time filter (AC-REL16-1,
/// AC-REL16-2, Q-22).
///
/// # Errors
///
/// Refuses an invalid timestamp, an invalid timestamp format, or a command that
/// does not fit one WinRS command line. Each refusal names the input.
pub fn search_file_content(
    path: &str,
    pattern: &str,
    file_filter: &str,
    max_results: i64,
    context_lines: i64,
    modified_after_hours: i64,
    options: &SearchOptions<'_>,
) -> Result<String, String> {
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
    let mtime_filter = if modified_after_hours > 0 {
        format!(
            "| Where-Object {{ $_.LastWriteTime -gt (Get-Date).AddHours(-{modified_after_hours}) }} "
        )
    } else {
        String::new()
    };
    let time_active = !options.since.trim().is_empty() || !options.until.trim().is_empty();
    let (prelude, ts_where) = if time_active {
        build_time_filter(options.since, options.until, options.timestamp_format)?
    } else {
        (String::new(), "")
    };
    // A time-only filter needs a pattern that matches every line; the time filter
    // then drops the lines without a timestamp. Without a time filter an empty
    // pattern cannot work: `Select-String -Pattern ''` rejects an empty string
    // (TR-REL-16).
    let empty_pattern = pattern.is_empty();
    if empty_pattern && !time_active {
        return Err(
            "pattern is empty; give a literal text to find, or set since or until for a \
             time-only search"
                .to_owned(),
        );
    }
    let pattern_clause = if empty_pattern {
        "-Pattern '.'".to_owned()
    } else {
        format!("-Pattern '{safe_pattern}' -SimpleMatch")
    };
    // The file order matters for `from_end` and for the time filter: the matches
    // must run oldest first, so `app.log.2` (the oldest) is not the last file.
    let sort_files = if options.from_end || time_active {
        "| Sort-Object LastWriteTime "
    } else {
        ""
    };
    let command = if options.count_only {
        format!(
            "{prelude}\
             $t = Get-Item -LiteralPath '{safe_path}' -ErrorAction Stop; \
             if ($t.PSIsContainer) {{ \
             $scanned = 0; $matched = 0; \
             foreach ($file in @(Get-ChildItem -LiteralPath '{safe_path}' -Recurse -File -Filter '{safe_filter}' \
             -ErrorAction SilentlyContinue {mtime_filter})) {{ $scanned++; \
             $c = (Select-String -LiteralPath $file.FullName {pattern_clause} \
             -ErrorAction SilentlyContinue {ts_where}| Measure-Object).Count; \
             if ($c -gt 0) {{ $matched++; Write-Output ($file.FullName + ': ' + $c + ' matches') }} }}; \
             Write-Output (\"$scanned files scanned, $matched with matches\") \
             }} else {{ \
             $c = (Select-String -LiteralPath '{safe_path}' {pattern_clause} \
             -ErrorAction Stop {ts_where}| Measure-Object).Count; \
             Write-Output ('{safe_path}' + ': ' + $c + ' matches') \
             }}"
        )
    } else {
        let selection = if options.from_end {
            format!("| Select-Object -Last {result_cap} ")
        } else {
            format!("| Select-Object -First {result_cap} ")
        };
        let (dir_format, file_format) = if ctx > 0 {
            (SEARCH_LINE_CTX, SEARCH_LINE_CTX)
        } else {
            (SEARCH_LINE_DIR, SEARCH_LINE_FILE)
        };
        format!(
            "{prelude}\
             $t = Get-Item -LiteralPath '{safe_path}' -ErrorAction Stop; \
             if ($t.PSIsContainer) {{ \
             Get-ChildItem -LiteralPath '{safe_path}' -Recurse -File -Filter '{safe_filter}' \
             -ErrorAction SilentlyContinue {mtime_filter}{sort_files}\
             | Select-String {pattern_clause}{ctx_arg} -ErrorAction SilentlyContinue {ts_where}\
             {selection}{dir_format} \
             }} else {{ \
             Select-String -LiteralPath '{safe_path}' {pattern_clause}{ctx_arg} -ErrorAction Stop {ts_where}\
             {selection}{file_format} \
             }}"
        )
    };
    if !fits_command_line(&command) {
        return Err(format!(
            "the search inputs are too long; the command does not fit the WinRS command line of \
             {WINRS_COMMAND_LINE_LIMIT} characters; shorten the path, the pattern or the directory filter"
        ));
    }
    Ok(command)
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
/// Returns an error text for an unknown level (TR-REL-03) or for a channel name
/// with a wildcard character.
///
/// The channel name is any name that `Get-WinEvent -ListLog` returns (TR-REL-12).
/// The name is escaped before it enters the single-quoted string, so it cannot
/// inject. A wildcard is refused, because the validation below must check one
/// exact channel.
pub fn get_event_log(
    log_name: &str,
    level: &str,
    hours_back: i64,
    source: &str,
    count: i64,
) -> Result<String, String> {
    if log_name.contains(['*', '?', '[']) {
        return Err(format!(
            "Invalid log_name '{log_name}': the wildcard characters '*', '?' and '[' are not \
             allowed. Use the exact channel name from list_event_logs."
        ));
    }
    let safe_log = escape(log_name);
    let result_cap = cap(count, 1, 100);
    let hours = cap(hours_back, 1, 720);
    let level_key = level.trim().to_lowercase();
    let Some(position) = EVENT_LEVELS.iter().position(|(name, _)| *name == level_key) else {
        return Err(format!(
            "Invalid level '{level}'. Valid values: Critical, Error, Warning, Info"
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
        format!("Get-WinEvent -FilterHashtable {filter} -MaxEvents {result_cap} -ErrorAction Stop")
    } else {
        let safe_source = escape(source.trim());
        format!(
            "Get-WinEvent -FilterHashtable {filter} -ErrorAction Stop \
             | Where-Object {{ $_.ProviderName -like '{safe_source}' }} \
             | Select-Object -First {result_cap}"
        )
    };
    // The channel is checked first with `-ListLog`, so a missing or mistyped
    // channel fails the call before the event query. Only a missing channel
    // (`*NoMatchingLogs*`) is fatal; another pre-check error, for example a
    // reader who may read Security events but not its configuration, is ignored
    // and the query runs. In the query only `NoMatchingEventsFound` means an
    // empty result; the message text is localized, so both branches are taken on
    // the error id, and any other error is rethrown.
    Ok(format!(
        "try {{ Get-WinEvent -ListLog '{safe_log}' -ErrorAction Stop | Out-Null }} \
         catch {{ if ($_.FullyQualifiedErrorId -like '*NoMatchingLogs*') {{ throw }} }}; \
         $ev = @(); \
         try {{ $ev = @({get_events}) }} \
         catch {{ if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {{ $ev = @() }} else {{ throw }} }}; \
         if ($ev.Count -eq 0) {{ Write-Output 'No events matched: log={safe_log}, level={level_key} and higher, last {hours}h'; exit 0 }}; \
         $ev | ForEach-Object {{ \
         \"$($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) [$($_.LevelDisplayName)] ($($_.ProviderName)) ID:$($_.Id)\"; \
         \"  $(if ($_.Message) {{ $_.Message.Substring(0,[Math]::Min($_.Message.Length,400)) }} else {{ '' }})\"; \
         \"---\" }}"
    ))
}

/// The cap on the channel list. A host exposes more than a thousand channels once
/// the Analytic and Debug logs are included, so a query without a filter is
/// normally truncated; the full count sets the `truncated` flag.
const EVENT_LOG_LIMIT: usize = 300;

/// Returns every accessible channel that `Get-WinEvent -ListLog` reports, with
/// the record count and the enabled state (TR-REL-12, AC-REL12-2).
///
/// The filter is a wildcard on the channel name; an empty filter lists every
/// channel. The name is escaped before it enters the single-quoted string. A
/// channel that denies access is skipped and counted, and a filter with no match
/// gives an empty list (the `NoMatchingLogs` error is not a skip).
#[must_use]
pub fn list_event_logs(filter: &str) -> String {
    let trimmed = filter.trim();
    let pattern = if trimmed.is_empty() { "*" } else { trimmed };
    let safe_filter = escape(pattern);
    let limit = EVENT_LOG_LIMIT;
    format!(
        "$err = @(); \
         $logs = @(Get-WinEvent -ListLog '{safe_filter}' -ErrorAction SilentlyContinue -ErrorVariable err); \
         $skipped = @($err | Where-Object {{ $_.FullyQualifiedErrorId -notlike '*NoMatchingLogs*' }}).Count; \
         $truncated = $logs.Count -gt {limit}; \
         $rows = @($logs | Select-Object -First {limit} | ForEach-Object {{ \
         [PSCustomObject]@{{ name=$_.LogName; record_count=$_.RecordCount; enabled=[bool]$_.IsEnabled }} }}); \
         [PSCustomObject]@{{ logs=$rows; count=$rows.Count; truncated=$truncated; skipped=$skipped }} \
         | ConvertTo-Json -Compress -Depth 3",
        limit = limit,
    )
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

/// Upper bound in characters for a service name (TR-REL-17, TR-REL-18).
///
/// The Service Control Manager caps a service name at 256 characters; the bound
/// stops an absurd input before the command is built. Even a worst-case name of this
/// length fits one WinRS command line.
pub const SERVICE_NAME_MAX_CHARS: usize = 256;

/// The start types of `set_service_start_type`, as (label, `sc.exe` value) (TR-REL-18).
pub const SERVICE_START_TYPES: [(&str, &str); 4] = [
    ("Automatic", "auto"),
    ("AutomaticDelayed", "delayed-auto"),
    ("Manual", "demand"),
    ("Disabled", "disabled"),
];

/// The `(label, sc.exe value)` of a start type, case-insensitive, or `None`.
#[must_use]
pub fn start_type(input: &str) -> Option<(&'static str, &'static str)> {
    let candidate = input.trim();
    SERVICE_START_TYPES
        .iter()
        .copied()
        .find(|(label, _)| label.eq_ignore_ascii_case(candidate))
}

/// Refusal reason if the service name is empty, outside the allowed charset, or above
/// [`SERVICE_NAME_MAX_CHARS`] (finding 3).
fn service_name_guard(name: &str) -> Result<(), String> {
    let chars = name.chars().count();
    if chars == 0 {
        return Err("the service name is empty".to_owned());
    }
    if !crate::policy::is_valid_service_name(name) {
        return Err(
            "the service name holds a character outside letters, digits, '_', '-', '.' and space"
                .to_owned(),
        );
    }
    if chars > SERVICE_NAME_MAX_CHARS {
        return Err(format!(
            "service name is {chars} characters; the limit is {SERVICE_NAME_MAX_CHARS}"
        ));
    }
    Ok(())
}

/// The refusal for a service command that does not fit one WinRS command line.
fn service_command_too_long(name: &str) -> String {
    format!(
        "service name is {} characters; the command does not fit the WinRS command line of \
         {WINRS_COMMAND_LINE_LIMIT} characters; shorten the service name",
        name.chars().count()
    )
}

/// The protected service names as a PowerShell array literal (TR-SEC-15, finding 2).
fn protected_list_literal() -> String {
    let quoted: Vec<String> = crate::policy::PROTECTED_SERVICES
        .iter()
        .map(|name| format!("'{name}'"))
        .collect();
    format!("@({})", quoted.join(","))
}

/// PowerShell helper: map an input to the canonical service `Name` (finding 2).
///
/// An exact WQL match on `Win32_Service.Name`; an unknown name is refused, so a
/// display name never reaches a service. The protected check runs again on the
/// canonical name on the host, because `ServiceController` also accepts a display
/// name. The WQL literal is escaped (`\`→`\\`, `'`→`\'`).
const HELPER_RESOLVE: &str = r#"function Resolve-WinrigService($raw,$protected){$w=$raw.Replace('\','\\').Replace("'","\'");$f=@(Get-CimInstance Win32_Service -Filter "Name='$w'" -ErrorAction Stop);if($f.Count -eq 0){throw "No service with the name '$raw'; the tool does not fall back to a display name"};$c=[string]$f[0].Name;if($protected -contains $c){throw "Refusing to change '$c': it is critical for the remote session"};$c};"#;

/// PowerShell helper that maps the registry `Start` value to a label (TR-REL-18).
///
/// `Start` is `2` automatic, `3` manual, `4` disabled, `0` boot, `1` system;
/// `DelayedAutostart` marks `AutomaticDelayed`. `Boot` and `System` are returned
/// as-is.
const HELPER_START_TYPE: &str = r#"function Get-WinrigStartType($s){$p="HKLM:\SYSTEM\CurrentControlSet\Services\$s";$o=Get-ItemProperty -LiteralPath $p -ErrorAction SilentlyContinue;if(-not $o){return 'Unknown'};$n=@($o.PSObject.Properties.Name);if($n -notcontains 'Start'){return 'Unknown'};$d=$false;if($n -contains 'DelayedAutostart'){$d=([int]$o.DelayedAutostart -eq 1)};switch([int]$o.Start){2{if($d){return 'AutomaticDelayed'}else{return 'Automatic'}}3{return 'Manual'}4{return 'Disabled'}0{return 'Boot'}1{return 'System'}default{return 'Unknown'}}};"#;

/// PowerShell helper that decodes a service from an event `Binary` field (TR-REL-18,
/// finding 4).
///
/// `param1` holds the localized display name, so the name is decoded from the event
/// `Binary` field: hex → bytes → UTF-16LE text, before the `/`.
const HELPER_EVENT_NAME: &str = r#"function Get-WinrigEventName($e){$h=[string]([xml]$e.ToXml()).Event.EventData.Binary;if(-not $h){return $null};$c=[int][math]::Floor($h.Length/2);$b=[byte[]]::new($c);for($j=0;$j -lt $c;$j++){$b[$j]=[Convert]::ToByte($h.Substring($j*2,2),16)};[string](([Text.Encoding]::Unicode.GetString($b)).TrimEnd([char]0).Split('/')[0])};"#;

/// PowerShell helper that walks the tree below a service (TR-REL-18, finding 1).
const HELPER_DEPENDENTS: &str = r#"function Get-WinrigDependents($s){$d=@();$q=@($s);while($q.Count -gt 0){$c=$q[0];$q=@($q|Select-Object -Skip 1);$v=Get-Service -Name $c -ErrorAction SilentlyContinue;if($v){foreach($x in @($v.DependentServices)){if($d -notcontains $x.Name){$d+=$x.Name;$q+=$x.Name}}}};@($d)};"#;

/// The configuration of one service: the start type, the account, the binary path and
/// the recovery actions (TR-REL-17, AC-REL17-1).
///
/// The parse does not depend on the host locale. The status comes from CIM
/// (`Win32_Service`: `StartMode`, `StartName`, `PathName`); the delayed marker and
/// the recovery actions come from the service registry key — `DelayedAutostart`, and
/// `FailureActions`, a `REG_BINARY`: `dwResetPeriod` at 0, the reboot-message offset
/// at 4, the command offset at 8, `cActions` at 12, the action-array offset at 16 and
/// the array of `{type, delay_ms}` pairs at that offset (normally 20). The localized
/// text of `sc.exe` is never read. The start type is normalized to `Automatic`,
/// `AutomaticDelayed`, `Manual` or `Disabled`; `Boot` and `System` are returned from
/// CIM as they are.
///
/// # Errors
///
/// A name above [`SERVICE_NAME_MAX_CHARS`], or a command that does not fit one WinRS
/// command line. Both refusals name the length and the limit.
pub fn get_service_config(name: &str) -> Result<String, String> {
    service_name_guard(name)?;
    let safe = escape(name);
    let command = format!(
        "$n = '{safe}'; \
         $svc = Get-CimInstance Win32_Service -Filter \"Name='$n'\" -ErrorAction Stop; \
         if ($null -eq $svc) {{ throw \"Service not found: $n\" }}; \
         $props = Get-ItemProperty -LiteralPath (\"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$n\") -ErrorAction SilentlyContinue; \
         $names = @(); if ($props) {{ $names = @($props.PSObject.Properties.Name) }}; \
         $delayed = $false; \
         if ($names -contains 'DelayedAutostart') {{ $delayed = ([int]$props.DelayedAutostart -eq 1) }}; \
         $start = [string]$svc.StartMode; \
         if ($start -eq 'Auto') {{ $start = if ($delayed) {{ 'AutomaticDelayed' }} else {{ 'Automatic' }} }}; \
         $reset = 0; $actions = @(); $has_failure = $false; $on_non_crash = $false; \
         if ($names -contains 'FailureActions') {{ \
           $fa = [byte[]]$props.FailureActions; \
           if ($fa.Length -ge 20) {{ \
             $has_failure = $true; \
             $reset = [BitConverter]::ToUInt32($fa, 0); \
             $count = [BitConverter]::ToUInt32($fa, 12); \
             $start_at = [BitConverter]::ToUInt32($fa, 16); \
             if ($start_at -lt 20) {{ $start_at = 20 }}; \
             $max = [int](($fa.Length - $start_at) / 8); \
             if ($max -lt 0) {{ $max = 0 }}; \
             if ($count -gt $max) {{ $count = $max }}; \
             for ($i = 0; $i -lt $count; $i++) {{ \
               $off = $start_at + ($i * 8); \
               $type = [BitConverter]::ToUInt32($fa, $off); \
               $delay = [BitConverter]::ToUInt32($fa, $off + 4); \
               $label = switch ($type) {{ 0 {{ 'None' }} 1 {{ 'Restart' }} 2 {{ 'Reboot' }} 3 {{ 'RunCommand' }} default {{ \"Unknown($type)\" }} }}; \
               $actions += [PSCustomObject]@{{ action = $label; delay_ms = $delay }}; \
             }} \
           }} \
         }}; \
         if ($names -contains 'FailureActionsOnNonCrashFailures') {{ $on_non_crash = ([int]$props.FailureActionsOnNonCrashFailures -eq 1) }}; \
         [PSCustomObject]@{{ name = $n; display_name = $svc.DisplayName; status = [string]$svc.State; \
           start_type = $start; delayed_auto_start = $delayed; service_account = $svc.StartName; \
           binary_path = $svc.PathName; recovery_present = $has_failure; reset_period_seconds = $reset; \
           failure_actions_on_non_crash_failures = $on_non_crash; failure_actions = @($actions); \
           failure_action_count = @($actions).Count }} | ConvertTo-Json -Compress -Depth 4"
    );
    if !fits_command_line(&command) {
        return Err(service_command_too_long(name));
    }
    Ok(command)
}

/// Change the Service Control Manager start type of one service (TR-REL-18,
/// AC-REL15-2).
///
/// The write uses `sc.exe config … start= <value>` and checks only its exit code,
/// because the output of `sc.exe` is localized. `sc.exe config start= auto` does not
/// guarantee that a previously set delayed flag is cleared, so the script sets the
/// registry value `DelayedAutostart` explicitly: 1 for `AutomaticDelayed`, 0
/// otherwise. It re-reads the start type and returns the normalized label, not the
/// `sc.exe` value.
///
/// # Errors
///
/// A name above [`SERVICE_NAME_MAX_CHARS`], or a command that does not fit one WinRS
/// command line.
pub fn set_service_start_type(name: &str, label: &str, sc_value: &str) -> Result<String, String> {
    service_name_guard(name)?;
    let safe = escape(name);
    let protected = protected_list_literal();
    // Disabling a service whose dependents run can strand them; the same protected
    // dependent guard as `stop_service` runs before the write (finding 2).
    let (helpers, dependents_check) = if label == "Disabled" {
        (
            format!("{HELPER_RESOLVE}{HELPER_START_TYPE}{HELPER_DEPENDENTS}"),
            "$dep=@(Get-WinrigDependents $n);\
             $bad=@($dep|Where-Object{$protected -contains $_});\
             if($bad.Count -gt 0){throw \"Refusing to disable ${n}: dependent $($bad -join ', ') is critical for the remote session\"};"
                .to_owned(),
        )
    } else {
        (
            format!("{HELPER_RESOLVE}{HELPER_START_TYPE}"),
            String::new(),
        )
    };
    let command = format!(
        "{helpers}\
         $protected={protected};$n=Resolve-WinrigService '{safe}' $protected;\
         {dependents_check}\
         $null=& sc.exe config $n start= {sc_value};\
         if($LASTEXITCODE -ne 0){{throw \"sc.exe config failed with exit code $LASTEXITCODE for $n\"}};\
         $delayed=if('{label}' -eq 'AutomaticDelayed'){{1}}else{{0}};\
         New-ItemProperty -LiteralPath (\"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$n\") -Name DelayedAutostart -Value $delayed -PropertyType DWord -Force -ErrorAction Stop|Out-Null;\
         $after=Get-WinrigStartType $n;\
         if($after -ne '{label}'){{throw \"the start type is $after, but the tool requested '{label}'\"}};\
         [PSCustomObject]@{{name=$n;start_type=$after;requested='{label}'}}|ConvertTo-Json -Compress"
    );
    if !fits_command_line(&command) {
        return Err(service_command_too_long(name));
    }
    Ok(command)
}

/// Restart through the canonical name (TR-SEC-15, finding 7).
///
/// `Restart-Service` accepts a display name and `-Force` stops the dependent
/// services, so the script resolves the canonical name, re-checks the protected list
/// on the host, and runs without `-Force`: a running dependent makes the restart fail
/// with a clear host error instead of stopping the dependent.
///
/// # Errors
///
/// A name above [`SERVICE_NAME_MAX_CHARS`], or a command that does not fit one WinRS
/// command line.
pub fn restart_service(name: &str) -> Result<String, String> {
    service_name_guard(name)?;
    let safe = escape(name);
    let protected = protected_list_literal();
    let command = format!(
        "{HELPER_RESOLVE}\
         $protected={protected};$n=Resolve-WinrigService '{safe}' $protected;\
         Restart-Service -Name $n -ErrorAction Stop;\
         Start-Sleep -Seconds 2;\
         Get-Service -Name $n -ErrorAction Stop|Select-Object Name,Status,StartType|ConvertTo-Json -Compress"
    );
    if !fits_command_line(&command) {
        return Err(service_command_too_long(name));
    }
    Ok(command)
}

/// Stop a service and verify that it stays stopped (TR-REL-18, AC-REL18-1/2).
///
/// The script resolves the canonical name and re-checks the protected list on the
/// host. It refuses a service whose transitive dependent services include a protected
/// one, before any write. With `disable` it sets the start type `Disabled` before the
/// stop, so a recovery action cannot start the service again. It stops without
/// `-Force`, so a running dependent makes the stop fail; the failure is caught and
/// returned as `stop_error` with the previous start type, so the operator sees the
/// half-done state. After the stop it waits `wait_seconds`, reads the state, and reads
/// the events 7031, 7034 and 7036 of the `System` log since the stop; the service is
/// matched by the name decoded from the event `Binary` field, not by the localized
/// display name. The answer holds `running_again`, so the caller can refuse when the
/// service returned.
///
/// # Errors
///
/// A name above [`SERVICE_NAME_MAX_CHARS`], or a command that does not fit one WinRS
/// command line.
pub fn stop_service_verified(
    name: &str,
    disable: bool,
    wait_seconds: i64,
    previous: &str,
) -> Result<String, String> {
    service_name_guard(name)?;
    let safe = escape(name);
    let protected = protected_list_literal();
    let previous = escape(previous);
    let disable_step = if disable {
        "$null=& sc.exe config $n start= disabled;\
         if($LASTEXITCODE -ne 0){throw \"sc.exe config failed with exit code $LASTEXITCODE for $n\"};$ch=$true;"
            .to_owned()
    } else {
        String::new()
    };
    let disabled_literal = if disable { "$true" } else { "$false" };
    let command = format!(
        "{HELPER_RESOLVE}{HELPER_EVENT_NAME}{HELPER_DEPENDENTS}\
         $protected={protected};$n=Resolve-WinrigService '{safe}' $protected;\
         $t0=(Get-Date).AddSeconds(-2);\
         $prev='{previous}';$ch=$false;$err=$null;\
         $dep=@(Get-WinrigDependents $n);$bad=@($dep|Where-Object{{$protected -contains $_}});\
         if($bad.Count -gt 0){{throw \"Refusing to stop ${{n}}: dependent $($bad -join ', ') is critical for the remote session\"}};\
         {disable_step}\
         try{{Stop-Service -Name $n -ErrorAction Stop}}catch{{$err=[string]$_.Exception.Message}};\
         Start-Sleep -Seconds {wait_seconds};\
         $svc=Get-Service -Name $n -ErrorAction SilentlyContinue;\
         $st=if($svc){{[string]$svc.Status}}else{{'Unknown'}};\
         $ev=@();$everr=$null;\
         try{{$ev=@(Get-WinEvent -FilterHashtable @{{LogName='System';Id=@(7031,7034,7036);StartTime=$t0}} -ErrorAction Stop)}}catch{{if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){{$everr=[string]$_.Exception.Message}}}};\
         $ev=@($ev|Where-Object{{(Get-WinrigEventName $_) -eq $n}});\
         $rows=@($ev|ForEach-Object{{[PSCustomObject]@{{id=$_.Id;time=if($_.TimeCreated){{$_.TimeCreated.ToString('o',[Globalization.CultureInfo]::InvariantCulture)}}else{{$null}}}}}});\
         $run=($null -eq $err)-and($st -eq 'Running');\
         [PSCustomObject]@{{name=$n;state=$st;previous_start_type=$prev;start_type_changed=$ch;stop_error=$err;events_error=$everr;running_again=[bool]$run;wait_seconds={wait_seconds};disabled={disabled_literal};dependents=@($dep);events=@($rows);event_count=@($rows).Count}}|ConvertTo-Json -Compress -Depth 4"
    );
    if !fits_command_line(&command) {
        return Err(service_command_too_long(name));
    }
    Ok(command)
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

/// The name, the executable path and the start time of one process (TR-SEC-17).
///
/// The command line is never fetched, so it can carry no secret to the prompt or
/// the audit (DR-4). A missing process gives an honest object, not an empty one.
#[must_use]
pub fn process_details(pid: i64) -> String {
    format!(
        "$c = Get-CimInstance Win32_Process -Property Name,ExecutablePath,CreationDate \
         -Filter \"ProcessId={pid}\" -ErrorAction SilentlyContinue; \
         if ($c) {{ [PSCustomObject]@{{ Name=$c.Name; \
         ExecutablePath=if($c.ExecutablePath){{$c.ExecutablePath}}else{{'N/A'}}; \
         Started=if($c.CreationDate){{$c.CreationDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ',[Globalization.CultureInfo]::InvariantCulture)}}else{{'N/A'}} }} \
         | ConvertTo-Json -Compress }} else {{ 'process not found' }}"
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
pub fn get_registry(key: &str, value_name: &str, subkeys: bool, depth: i64) -> String {
    let mut k = key.trim().to_owned();
    if k.to_uppercase().starts_with("HKEY_") {
        k = format!("Registry::{k}");
    }
    let safe_key = escape(&k);
    let named_value = !value_name.trim().is_empty();
    let safe_val = escape(value_name.trim());
    let values = if named_value {
        format!(
            "Get-ItemProperty -LiteralPath '{safe_key}' -Name '{safe_val}' -ErrorAction Stop \
             | Select-Object -Property '{safe_val}'"
        )
    } else {
        format!(
            "Get-ItemProperty -LiteralPath '{safe_key}' -ErrorAction Stop \
             | Select-Object * -ExcludeProperty PS*"
        )
    };
    if !subkeys {
        return format!("{values} | ConvertTo-Json -Compress");
    }
    // TR-REL-11: depth counts child levels, so level 1 is `-Depth 0` (a plain
    // child listing); a value outside 1..=5 is clamped. The walk skips a child that
    // denies access and reports the count. Each child is a path relative to the
    // key: the registry item `Name` is the hive path, so the root prefix is cut.
    let walk = cap(depth, 1, 5) - 1;
    let limit = REGISTRY_SUBKEY_LIMIT;
    // The value and the subkeys are read separately: a value that is absent must
    // not hide the subkeys, so its read does not stop on error and reports an
    // `error` field instead.
    let values_read = if named_value {
        format!(
            "$v=Get-ItemProperty -LiteralPath '{safe_key}' -Name '{safe_val}' \
             -ErrorAction SilentlyContinue | Select-Object -Property '{safe_val}'; \
             $e=if($null -eq $v){{'value not read'}}else{{$null}}"
        )
    } else {
        format!(
            "$v=Get-ItemProperty -LiteralPath '{safe_key}' -ErrorAction Stop \
             | Select-Object * -ExcludeProperty PS*; $e=$null"
        )
    };
    format!(
        "$root=Get-Item -LiteralPath '{safe_key}' -ErrorAction Stop; {values_read}; \
         $items=@(Get-ChildItem -LiteralPath '{safe_key}' -Recurse -Depth {walk} \
         -ErrorVariable subErr -ErrorAction SilentlyContinue | Select-Object -First {over}); \
         $truncated=$items.Count -gt {limit}; \
         $keys=@($items | Select-Object -First {limit} \
         | ForEach-Object {{ $_.Name.Substring($root.Name.Length+1) }}); \
         $skipped=@($subErr).Count; \
         [PSCustomObject]@{{ values=$v; error=$e; subkeys=$keys; \
         truncated=$truncated; skipped=$skipped }} | ConvertTo-Json -Compress -Depth 3",
        over = limit + 1,
    )
}

/// Whether a registry value exists, and its type, without reading the data
/// (DR-4, TR-SEC-18).
///
/// The old value can be a secret, so the pre-confirmation read never returns it:
/// the command reports only the state (`present`, `absent`, `unknown`) and the
/// `RegistryValueKind` name. An access-denied or unreadable key gives `unknown`,
/// not `absent`; the branch is on the .NET exception type, so it does not depend on
/// the host locale.
#[must_use]
pub fn registry_value_presence(key: &str, value_name: &str) -> String {
    let mut k = key.trim().to_owned();
    if k.to_uppercase().starts_with("HKEY_") {
        k = format!("Registry::{k}");
    }
    let safe_key = escape(&k);
    let safe_val = escape(value_name.trim());
    format!(
        "$state='unknown';$type=$null;$k=$null; \
         try {{ $k=Get-Item -LiteralPath '{safe_key}' -ErrorAction Stop }} \
         catch {{ if ($_.Exception -is [System.Management.Automation.ItemNotFoundException]) {{ $state='absent' }} }}; \
         if ($k) {{ try {{ if (@($k.GetValueNames()) -contains '{safe_val}') {{ $state='present'; $type=[string]$k.GetValueKind('{safe_val}') }} else {{ $state='absent' }} }} catch {{ $state='unknown' }} }}; \
         [PSCustomObject]@{{ state=$state; type=$type }} | ConvertTo-Json -Compress"
    )
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
        "Get-ChildItem -LiteralPath 'Cert:\\{st}\\My' -ErrorAction Stop {expiry_filter}\
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

/// The cap on the summary groups, so a single answer stays inside the executor
/// output limit (TR-REL-13).
const TCP_SUMMARY_LIMIT: usize = 100;

/// The longest accepted process-name wildcard. The server refuses a longer value
/// before any host call (TR-REL-13).
pub const TCP_PROCESS_FILTER_MAX_CHARS: usize = 256;

/// The accepted `state_filter` values and their `Get-NetTCPConnection` state.
/// `All` is not in the table: it means "no state filter".
const TCP_STATES: [(&str, &str); 8] = [
    ("bound", "Bound"),
    ("closewait", "CloseWait"),
    ("established", "Established"),
    ("finwait1", "FinWait1"),
    ("finwait2", "FinWait2"),
    ("listen", "Listen"),
    ("synreceived", "SynReceived"),
    ("timewait", "TimeWait"),
];

/// Escapes the wildcard characters `` ` ``, `[` and `]` with a backtick so the
/// `-like` operator matches them literally. An unbalanced `[` throws on every
/// row otherwise; the backtick stays literal inside the single-quoted pattern and
/// reaches the wildcard engine.
fn escape_like(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if matches!(c, '`' | '[' | ']') {
            out.push('`');
        }
        out.push(c);
    }
    out
}

/// # Errors
///
/// Returns an error text for a `state_filter` outside the accepted values.
pub fn get_tcp_connections(
    state_filter: &str,
    port_filter: i64,
    pid: i64,
    process: &str,
    summary: bool,
) -> Result<String, String> {
    let mut where_parts: Vec<String> = Vec::new();
    let sf = state_filter.trim().to_lowercase();
    if sf != "all" {
        let Some((_, ps_state)) = TCP_STATES.iter().find(|(name, _)| *name == sf.as_str()) else {
            let allowed = std::iter::once(String::from("All"))
                .chain(TCP_STATES.iter().map(|(_, state)| (*state).to_owned()))
                .collect::<Vec<String>>()
                .join(", ");
            return Err(format!(
                "Invalid state_filter '{state_filter}'. Valid values: {allowed}"
            ));
        };
        where_parts.push(format!("$_.State -eq '{ps_state}'"));
    }
    if port_filter > 0 {
        where_parts.push(format!(
            "($_.LocalPort -eq {port_filter} -or $_.RemotePort -eq {port_filter})"
        ));
    }
    if pid > 0 {
        where_parts.push(format!("$_.OwningProcess -eq {pid}"));
    }
    let trimmed_process = process.trim();
    if !trimmed_process.is_empty() {
        where_parts.push(format!(
            "$names[[int]$_.OwningProcess] -like '{}'",
            escape(&escape_like(trimmed_process))
        ));
    }
    // The filter is a client-side `Where-Object` on purpose: the `-State`,
    // `-LocalPort` and `-OwningProcess` parameters of `Get-NetTCPConnection`
    // throw a localized non-terminating error when nothing matches, while an
    // empty pipeline is already an empty result (TR-REL-13).
    let where_clause = if where_parts.is_empty() {
        String::new()
    } else {
        format!("| Where-Object {{ {} }} ", where_parts.join(" -and "))
    };
    // The owning process name is resolved once into a hashtable. A `Get-Process`
    // call per row would issue one call for each connection, and a PID that
    // vanished between the two commands reads a null name, not an error.
    let name_table = "$names=@{}; Get-Process -ErrorAction SilentlyContinue \
         | ForEach-Object { $names[[int]$_.Id]=$_.ProcessName }; ";
    if summary {
        let limit = TCP_SUMMARY_LIMIT;
        // A `Listen` row holds the bound address. The local address stays in the
        // group key: without it a listener on `127.0.0.1` and one on `::1` would
        // merge into one group. The largest groups survive the cap.
        return Ok(format!(
            "{name_table}\
             $groups=@(Get-NetTCPConnection -ErrorAction SilentlyContinue {where_clause}\
             | Group-Object -Property {{ $names[[int]$_.OwningProcess] }}, {{ $_.LocalPort }}, \
             {{ $_.LocalAddress }}, {{ $_.RemoteAddress }} \
             | Sort-Object Count -Descending | Select-Object -First {over}); \
             $truncated=$groups.Count -gt {limit}; \
             $rows=@($groups | Select-Object -First {limit} | ForEach-Object {{ \
             $first=$_.Group[0]; [PSCustomObject]@{{ \
             process=$names[[int]$first.OwningProcess]; local_port=[int]$first.LocalPort; \
             local_address=[string]$first.LocalAddress; remote_address=[string]$first.RemoteAddress; \
             count=$_.Count }} }}); \
             [PSCustomObject]@{{ groups=$rows; count=$rows.Count; truncated=$truncated }} \
             | ConvertTo-Json -Compress -Depth 3",
            over = limit + 1,
        ));
    }
    Ok(format!(
        "{name_table}\
         Get-NetTCPConnection -ErrorAction SilentlyContinue {where_clause}\
         | Select-Object @{{N='Local';E={{\"$($_.LocalAddress):$($_.LocalPort)\"}}}}, \
         @{{N='Remote';E={{\"$($_.RemoteAddress):$($_.RemotePort)\"}}}}, \
         @{{N='State';E={{[string]$_.State}}}}, \
         @{{N='PID';E={{$_.OwningProcess}}}}, \
         @{{N='Process';E={{$names[[int]$_.OwningProcess]}}}} \
         | Sort-Object Remote | Format-Table -AutoSize | Out-String -Width 300"
    ))
}

/// # Errors
///
/// Returns an error text for an unknown record type.
pub fn resolve_dns_name(name: &str, record_type: &str, dns_server: &str) -> Result<String, String> {
    const VALID: [&str; 9] = ["A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT"];
    let rt = record_type.trim().to_uppercase();
    if !VALID.contains(&rt.as_str()) {
        return Err(format!(
            "Invalid record_type '{record_type}'. Valid values: {}",
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

/// The read-only script that reaches the Restart Manager for the holder list (TR-REL-14).
///
/// A dynamic type carries the P/Invoke methods, built by `Reflection.Emit` inside the
/// PowerShell process: no compiler runs and no file goes to the host disk (unlike
/// `Add-Type`). Type attributes `'Public,Class'` are explicit, because the
/// one-argument `DefineType` overload makes the type not public. Method attributes `22` are `Public|Static`; `DefinePInvokeMethod` adds
/// `PinvokeImpl` itself, and the value `86` would wrongly add `Virtual`. The trailing
/// `1,3` pair is `CallingConvention.Winapi` and `CharSet.Unicode`, so `string[]` goes
/// as `LPWSTR[]` and the 33-`char` session key stays wide. `SetImplementationFlags(128)`
/// is `PreserveSig`, so a non-zero return is the Restart Manager error code, not a
/// translated HRESULT. The `RM_PROCESS_INFO` array is one raw byte buffer of 668 bytes
/// for each holder; the offsets come from the Restart Manager header, and `strAppName`
/// and `strServiceShortName` are NUL-terminated inside their fields, so the first NUL
/// ends the name; the script still guards the no-NUL case. The path enters a
/// single-quoted string ([`escape`]) at `@PATH@`.
const OPEN_HANDLES_SCRIPT: &str = r#"$ErrorActionPreference='Stop';$p='@PATH@';try{$i=Get-Item -LiteralPath $p -Force -ea Stop}catch[Management.Automation.ItemNotFoundException]{throw "Path not found: $p"}catch[UnauthorizedAccessException]{throw "Access denied: $p"};if($i.PSProvider.Name -ne 'FileSystem'){throw "NotFile: $p"};$p=$i.FullName;$a=[AppDomain]::CurrentDomain.DefineDynamicAssembly([Reflection.AssemblyName]::new('Winrig'),1).DefineDynamicModule('Winrig').DefineType('Winrig','Public,Class');$w={$m=$a.DefinePInvokeMethod($args[0],'rstrtmgr.dll',22,1,[int],$args[1],1,3);$null=$m.SetImplementationFlags(128)};$q=[int].MakeByRefType();&$w RmStartSession @($q,[int],[char[]]);&$w RmRegisterResources @([int],[int],[string[]],[int],[IntPtr],[int],[IntPtr]);&$w RmGetList @([int],$q,$q,[byte[]],$q);&$w RmEndSession @([int]);$t=$a.CreateType();$e=@{5='Deny';87='Bad';121='Timeout';234='More';353='Max'};function RmFail($m,$r){throw "$m ${r}: $($e[$r])"};function RmStr($b,$o,$n){$s=[Text.Encoding]::Unicode.GetString($b,$o,$n);$k=$s.IndexOf([char]0);if($k -ge 0){$s.Substring(0,$k)}else{$s}};$s=0;if($i.PSIsContainer){$x=@();$f=@(Get-ChildItem -LiteralPath $p -Recurse -File -Force -ea 0 -ev +x|Select -First @FO@ -Expand FullName);$ft=$f.Count -gt @FL@;$f=@($f|Select -First @FL@);$s=@($x).Count}else{$f=@($p);$ft=$false};$h=0;$r=$t::RmStartSession([ref]$h,0,[char[]]::new(33));if($r){RmFail RmStartSession $r};$o=@();try{if($f.Count){$r=$t::RmRegisterResources($h,$f.Count,[string[]]$f,0,[IntPtr]::Zero,0,[IntPtr]::Zero);if($r){RmFail RmRegisterResources $r};$n=$c=$b=0;$d=$null;$r=234;for($j=0;$j++ -lt 5 -and $r -eq 234;){$r=$t::RmGetList($h,[ref]$n,[ref]$c,$d,[ref]$b);if($r -eq 234){$c=$n;$d=[byte[]]::new($c*668)}};if($r){RmFail RmGetList $r};for($j=0;$j -lt $c;$j++){$y=$j*668;$z=[BitConverter]::ToInt64($d,$y+4);$o+=[PSCustomObject]@{pid=[BitConverter]::ToUInt32($d,$y);name=(RmStr $d ($y+12) 512);service=(RmStr $d ($y+524) 128);started=if($z -gt 0){[DateTime]::FromFileTimeUtc($z).ToString('yyyy-MM-ddTHH:mm:ssZ',[Globalization.CultureInfo]::InvariantCulture)}else{$null}}}}}finally{$null=$t::RmEndSession($h)};$rt=$o.Count -gt @RL@;[PSCustomObject]@{path=$p;holders=@($o|Select -First @RL@);count=$o.Count;files_checked=$f.Count;skipped=$s;files_truncated=$ft;rows_truncated=$rt}|ConvertTo-Json -Compress -Depth 3"#;

/// Sanity upper bound in characters: the Windows long-path maximum, 32767 (TR-REL-14).
///
/// The real limit is the WinRS command line, which the Restart Manager script fills
/// much more than a plain script; this bound only stops an absurd input before the
/// command is built. A plain 260-character path and even a worst-case all-quote path
/// of 260 characters still fit.
pub const OPEN_HANDLES_PATH_MAX_CHARS: usize = 32_767;
/// The cap on the holders in one answer, like the other diagnostic tools.
const OPEN_HANDLES_ROW_LIMIT: usize = 100;
/// The cap on the files registered for a directory path. The Restart Manager
/// refuses a directory itself (`ERROR_ACCESS_DENIED`), so a directory is walked.
const OPEN_HANDLES_FILE_LIMIT: usize = 200;

/// The processes that hold a file open, with the PID, the name and the start time (TR-REL-14).
///
/// The Restart Manager refuses a directory path itself (`ERROR_ACCESS_DENIED`), so
/// a directory is enumerated file by file up to [`OPEN_HANDLES_FILE_LIMIT`], and
/// the answer carries `files_checked` and `skipped`. An empty holder set is an
/// empty array, not an error; a missing path throws.
///
/// # Errors
///
/// A path above [`OPEN_HANDLES_PATH_MAX_CHARS`], or a command that does not fit
/// one WinRS command line. Both refusals name the path length and the limit.
pub fn get_open_handles(path: &str) -> Result<String, String> {
    let chars = path.chars().count();
    if chars > OPEN_HANDLES_PATH_MAX_CHARS {
        return Err(format!(
            "path is {chars} characters; the limit is {OPEN_HANDLES_PATH_MAX_CHARS}"
        ));
    }
    let safe = escape(path);
    // The path is substituted last, so a `@…@` sequence inside it cannot match a
    // later placeholder.
    let command = OPEN_HANDLES_SCRIPT
        .replace("@FO@", &(OPEN_HANDLES_FILE_LIMIT + 1).to_string())
        .replace("@FL@", &OPEN_HANDLES_FILE_LIMIT.to_string())
        .replace("@RL@", &OPEN_HANDLES_ROW_LIMIT.to_string())
        .replace("@PATH@", &safe);
    if !fits_command_line(&command) {
        return Err(format!(
            "path is {chars} characters; the command does not fit the WinRS command line of \
             {WINRS_COMMAND_LINE_LIMIT} characters; shorten the path"
        ));
    }
    Ok(command)
}

/// The command that lists every printer with the state name and the job count (TR-REL-15).
///
/// The state is the `Get-Printer` `PrinterStatus` enum name, for example
/// `Normal` or `Offline`. On some hosts the value is an ordinal enum, so the name
/// is read as a string and never decoded as the `PRINTER_STATUS_*` bit mask. The
/// registry `Status` value under `…\Control\Print\Printers` is read next: it is
/// reported as `state_flags` when it is readable, and when the name is absent it
/// is decoded with a fixed English bit table into the state. If neither can be
/// read the state stays `Unknown` with `state_flags` null, so an unread state
/// never looks healthy. Both forms are independent of the host locale. The job
/// count comes from `Get-Printer`; a missing value is null, not zero. Rows are
/// kept while their compressed JSON stays under `@BUD@` characters, so the answer
/// fits the executor output limit however many printers the host has. A stopped
/// Print Spooler or a missing PrintManagement module gives a clear error, not an
/// empty list.
const PRINTERS_SCRIPT: &str = r#"$ErrorActionPreference='Stop';if($null -eq (Get-Command Get-Printer -ErrorAction SilentlyContinue)){throw "PrintManagement module is not available"};$svc=Get-Service -Name Spooler -ErrorAction Stop;if($svc.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running){throw "The Print Spooler service is not running: $($svc.Status)"};function Cap($s,$n){$s=[string]$s;if($s.Length -gt $n){$s.Substring(0,$n)}else{$s}};$flags=@{1='Paused';2='Error';4='PendingDeletion';8='PaperJam';16='PaperOut';32='ManualFeed';64='PaperProblem';128='Offline';256='IOActive';512='Busy';1024='Printing';2048='OutputBinFull';4096='NotAvailable';8192='Waiting';16384='Processing';32768='Initializing';65536='WarmingUp';131072='TonerLow';262144='NoToner';524288='PagePunt';1048576='UserInterventionRequired';2097152='OutOfMemory';4194304='DoorOpen';8388608='ServerUnknown';16777216='PowerSave';33554432='ServerOffline';67108864='DriverUpdateNeeded'};$perr=@();$printers=@(Get-Printer -ErrorAction SilentlyContinue -ErrorVariable +perr|Sort-Object Name);if(-not $printers.Count -and $perr.Count){throw "Get-Printer failed: $([string]$perr[0])"};$total=$printers.Count;$rows=@();$len=0;$truncated=$false;foreach($printer in $printers){if($rows.Count -ge @LIM@){$truncated=$true;break};$name=Cap $printer.Name @NF@;$share=Cap $printer.ShareName @SF@;$driver=Cap $printer.DriverName @DF@;$portname=Cap $printer.PortName @PF@;$state=[string]$printer.PrinterStatus;$state_flags=$null;$mask=$null;try{$mask=[int](Get-ItemProperty -LiteralPath ("HKLM:\SYSTEM\CurrentControlSet\Control\Print\Printers\"+([string]$printer.Name)) -Name Status -ErrorAction Stop).Status;$state_flags=$mask}catch{$mask=$null};if([string]::IsNullOrEmpty($state)){if($null -ne $mask){$states=@($flags.Keys|Sort-Object|Where-Object{$mask -band $_}|ForEach-Object{$flags[$_]});if($states.Count){$state=($states -join ', ')}else{$state='Normal'}}else{$state='Unknown'}};$ph=$null;$pnum=$null;try{$po=Get-PrinterPort -Name $printer.PortName -ErrorAction Stop;if($po){$ph=Cap $po.PrinterHostAddress @HF@;$pnum=[int]$po.PortNumber}}catch{};$row=[PSCustomObject]@{name=$name;share_name=$share;driver=$driver;port=$portname;port_host=$ph;port_number=$pnum;state=$state;state_flags=$state_flags;job_count=if($null -ne $printer.JobCount){[int]$printer.JobCount}else{$null}};$j=$row|ConvertTo-Json -Compress;if(($len+$j.Length+1+@ENV@) -gt @BUD@){$truncated=$true;break};$len=$len+$j.Length+1;$rows+=$row};[PSCustomObject]@{printers=$rows;count=$total;returned=$rows.Count;truncated=$truncated}|ConvertTo-Json -Compress -Depth 4"#;

/// The command that lists the jobs of one printer (TR-REL-15).
///
/// The personal-data fields (`document_name`, `user`) are substituted as the
/// placeholder `@PERSONAL@` only when the caller asks for them (Q-21): without
/// the flag the script does not read `DocumentName` and `UserName` on the host,
/// so the values never leave it. The submit time is an invariant ISO string, and
/// the job state is the enum name as a string, so neither depends on the host
/// locale. Rows are kept while their compressed JSON stays under `@BUD@`
/// characters. A stopped Print Spooler, a missing PrintManagement module or an
/// unknown printer gives a clear error. The name enters a single-quoted string
/// ([`escape`]) at `@PRINTER@`.
const PRINT_JOBS_SCRIPT: &str = r#"$ErrorActionPreference='Stop';if($null -eq (Get-Command Get-Printer -ErrorAction SilentlyContinue)){throw "PrintManagement module is not available"};$svc=Get-Service -Name Spooler -ErrorAction Stop;if($svc.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running){throw "The Print Spooler service is not running: $($svc.Status)"};function Cap($s,$n){$s=[string]$s;if($s.Length -gt $n){$s.Substring(0,$n)}else{$s}};$printer='@PRINTER@';$perr=@();$names=@(Get-Printer -ErrorAction SilentlyContinue -ErrorVariable +perr|ForEach-Object{[string]$_.Name});if(-not $names.Count -and $perr.Count){throw "Get-Printer failed: $([string]$perr[0])"};if($names -notcontains $printer){throw "Printer not found: $printer"};$jerr=@();$jobs=@(Get-PrintJob -PrinterName $printer -ErrorAction SilentlyContinue -ErrorVariable +jerr|Sort-Object Id);if(-not $jobs.Count -and $jerr.Count){throw "Get-PrintJob failed: $([string]$jerr[0])"};$total=$jobs.Count;$rows=@();$len=0;$truncated=$false;foreach($job in $jobs){if($rows.Count -ge @LIM@){$truncated=$true;break};$row=[PSCustomObject]@{
job_id=[int]$job.Id;
@PERSONAL@
state=[string]$job.JobStatus;size=[long]$job.Size;submitted=if($job.SubmittedTime -is [datetime]){$job.SubmittedTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ',[Globalization.CultureInfo]::InvariantCulture)}elseif($job.SubmittedTime){[string]$job.SubmittedTime}else{$null}};$j=$row|ConvertTo-Json -Compress;if(($len+$j.Length+1+@ENV@) -gt @BUD@){$truncated=$true;break};$len=$len+$j.Length+1;$rows+=$row};[PSCustomObject]@{printer=$printer;jobs=$rows;count=$total;returned=$rows.Count;truncated=$truncated}|ConvertTo-Json -Compress -Depth 4"#;

/// The row cap on the printers in one answer (TR-REL-15).
const PRINTER_LIMIT: usize = 200;
/// The cap on the print jobs of one printer in one answer.
const PRINT_JOB_LIMIT: usize = 200;
/// The most characters of the JSON rows in one answer (TR-REL-15).
///
/// The script keeps rows while the running total of their compressed JSON,
/// the separators and the envelope stays under this budget, so the answer fits
/// `executor::MAX_OUTPUT_CHARS` however many rows the host has. PowerShell 5.1
/// `ConvertTo-Json` escapes `'`, `<`, `>` and `&` as six characters, so the
/// budget covers that worst case.
const PRINT_OUTPUT_BUDGET_CHARS: usize = 50_000;
/// Allowance in characters for the JSON envelope around the rows.
const PRINT_ENVELOPE_CHARS: usize = 256;
/// The most characters of a printer name in the answer. The host caps the value,
/// so a long name cannot push the JSON over the executor output limit.
const PRINTER_NAME_CAP: usize = 128;
/// The most characters of the share name, the driver and the port in the answer.
const PRINTER_FIELD_CAP: usize = 64;
/// The most characters of a port host address in the answer.
const PORT_HOST_CAP: usize = 45;
/// The most characters of a job document name in the answer.
const DOCUMENT_NAME_CAP: usize = 128;
/// The most characters of a job owner in the answer.
const JOB_USER_CAP: usize = 64;
/// Sanity upper bound in characters for a printer name (TR-REL-15).
///
/// A Windows printer name is at most about 220 characters; the bound only stops
/// an absurd input before the command is built. Even a worst-case all-quote name
/// of this length fits one WinRS command line.
pub const PRINT_JOB_PRINTER_MAX_CHARS: usize = 512;

/// The printers on the host, with the state as the printer-status name and the job count (TR-REL-15).
///
/// The state is the `PrinterStatus` enum name, for example `Normal` or `Offline`,
/// the decoded registry `Status` mask when the name is absent, or `Unknown` when
/// neither is readable. The share
/// name, the driver, the port, the port host and number come from `Get-Printer`
/// and `Get-PrinterPort`; the job count comes from `Get-Printer`. The answer is
/// cut to the row cap or the size budget, and `truncated` shows the cut. A stopped
/// Print Spooler or a missing PrintManagement module gives a clear error, not an
/// empty list.
#[must_use]
pub fn get_printers() -> String {
    PRINTERS_SCRIPT
        .replace("@NF@", &PRINTER_NAME_CAP.to_string())
        .replace("@SF@", &PRINTER_FIELD_CAP.to_string())
        .replace("@DF@", &PRINTER_FIELD_CAP.to_string())
        .replace("@PF@", &PRINTER_FIELD_CAP.to_string())
        .replace("@HF@", &PORT_HOST_CAP.to_string())
        .replace("@ENV@", &PRINT_ENVELOPE_CHARS.to_string())
        .replace("@BUD@", &PRINT_OUTPUT_BUDGET_CHARS.to_string())
        .replace("@LIM@", &PRINTER_LIMIT.to_string())
}

/// The print jobs of one printer, with the personal data hidden by default (TR-REL-15, Q-21).
///
/// The document name and the owner are personal data. The script selects them on
/// the host only with `include_personal_data`; without the flag it does not read
/// the fields at all, so they never leave the host. The answer is cut to the row
/// cap or the size budget, and `truncated` shows the cut. A stopped Print Spooler,
/// a missing PrintManagement module or an unknown printer gives a clear error.
///
/// # Errors
///
/// A printer name above [`PRINT_JOB_PRINTER_MAX_CHARS`], or a command that does
/// not fit one WinRS command line. Both refusals name the length and the limit.
pub fn get_print_jobs(printer: &str, include_personal_data: bool) -> Result<String, String> {
    let chars = printer.chars().count();
    if chars > PRINT_JOB_PRINTER_MAX_CHARS {
        return Err(format!(
            "printer is {chars} characters; the limit is {PRINT_JOB_PRINTER_MAX_CHARS}"
        ));
    }
    let personal = if include_personal_data {
        format!(
            "document_name=Cap $job.DocumentName {};user=Cap $job.UserName {}",
            DOCUMENT_NAME_CAP, JOB_USER_CAP
        )
    } else {
        String::new()
    };
    // The name is substituted last, so a `@…@` sequence inside it cannot match a
    // later placeholder.
    let command = PRINT_JOBS_SCRIPT
        .replace("@ENV@", &PRINT_ENVELOPE_CHARS.to_string())
        .replace("@BUD@", &PRINT_OUTPUT_BUDGET_CHARS.to_string())
        .replace("@LIM@", &PRINT_JOB_LIMIT.to_string())
        .replace("@PERSONAL@", &personal)
        .replace("@PRINTER@", &escape(printer));
    if !fits_command_line(&command) {
        return Err(format!(
            "printer is {chars} characters; the command does not fit the WinRS command line of \
             {WINRS_COMMAND_LINE_LIMIT} characters; shorten the printer name"
        ));
    }
    Ok(command)
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
        let error = read_file("C:\\a.txt", 1, 10, false, "koi8", "").expect_err("bad encoding");
        assert!(error.contains("utf8"));
    }

    #[test]
    fn read_file_rejects_reversed_range() {
        let error = read_file("C:\\a.txt", 10, 5, false, "UTF8", "").expect_err("reversed");
        assert!(error.contains("end_line"));
    }

    #[test]
    fn read_file_tail_uses_tail_switch() {
        let cmd = read_file("C:\\a.log", 1, 50, true, "UTF8", "").expect("valid");
        assert!(cmd.contains("-Tail 50"));
    }

    /// TR-REL-16 backward compatibility: an empty `exclude` keeps the plain tail,
    /// and only a non-empty `exclude` adds the literal filter (Q-22).
    #[test]
    fn read_file_tail_without_exclude_keeps_the_plain_tail() {
        let cmd = read_file("C:\\a.log", 1, 50, true, "UTF8", "").expect("valid");
        assert!(cmd.contains("-Tail 50"), "{cmd}");
        assert!(!cmd.contains("IndexOf"), "{cmd}");
        assert!(!cmd.contains("Select-Object -Last"), "{cmd}");
    }

    /// TR-REL-16, Q-22: `exclude` is a literal substring (case-insensitive, no
    /// wildcards), escaped for a single-quoted string. The window grows from the
    /// end of the file, streams in batches and keeps only the requested count.
    #[test]
    fn read_file_tail_exclude_grows_a_window_from_the_end() {
        let cmd = read_file("C:\\a.log", 1, 50, true, "UTF8", "'quiet'").expect("valid");
        assert!(
            cmd.contains("IndexOf('''quiet''', [StringComparison]::OrdinalIgnoreCase) -lt 0"),
            "{cmd}"
        );
        assert!(cmd.contains("-Tail $W"), "the window must use -Tail: {cmd}");
        assert!(
            cmd.contains("-ReadCount"),
            "the window must stream in batches: {cmd}"
        );
        assert!(
            cmd.contains("[System.Collections.Generic.Queue[string]]"),
            "the window must keep a bounded queue: {cmd}"
        );
        assert!(
            !cmd.contains("@(Get-Content -Tail"),
            "the window must not materialize the whole window: {cmd}"
        );
        assert!(
            cmd.contains("while (-not $covered)"),
            "the window must grow in a loop: {cmd}"
        );
        assert!(cmd.contains("* 10"), "the window must grow tenfold: {cmd}");
        assert!(
            cmd.contains(&TAIL_EXCLUDE_MAX_WINDOW.to_string()),
            "the window must stop at the bound: {cmd}"
        );
        assert!(
            !cmd.contains("Where-Object"),
            "the literal filter must not use Where-Object: {cmd}"
        );
        assert!(
            cmd.contains("$want") && !cmd.contains("$N"),
            "the count variable must not collide with the line counter: {cmd}"
        );
    }

    /// TR-REL-16: `exclude` without the tail mode is refused before any host call.
    #[test]
    fn read_file_refuses_exclude_without_tail() {
        let error = read_file("C:\\a.log", 1, 50, false, "UTF8", "quiet").expect_err("no tail");
        assert!(
            error.contains("exclude works only with tail=true"),
            "{error}"
        );
    }

    fn default_options() -> SearchOptions<'static> {
        SearchOptions {
            from_end: false,
            count_only: false,
            since: "",
            until: "",
            timestamp_format: "",
        }
    }

    /// TR-REL-16 backward compatibility: the default search keeps the first
    /// matches and adds no time filter.
    #[test]
    fn search_file_content_default_uses_first_and_no_time_filter() {
        let cmd = search_file_content(
            "C:\\app.log",
            "ERROR",
            "*.log",
            50,
            0,
            0,
            &default_options(),
        )
        .expect("valid");
        assert!(cmd.contains("Select-Object -First 50"), "{cmd}");
        assert!(!cmd.contains("Select-Object -Last"), "{cmd}");
        assert!(!cmd.contains("TryParseExact"), "{cmd}");
        assert!(!cmd.contains("Measure-Object"), "{cmd}");
    }

    /// AC-REL16-1: `from_end` takes the last matches. The file streams through
    /// `Select-String` and `Select-Object -Last`, so the host keeps a bounded set.
    #[test]
    fn search_file_content_from_end_takes_the_last_matches() {
        let options = SearchOptions {
            from_end: true,
            ..default_options()
        };
        let cmd = search_file_content("C:\\app.log", "ERROR", "*.log", 50, 0, 0, &options)
            .expect("valid");
        assert!(
            cmd.contains("Select-String -Pattern 'ERROR' -SimpleMatch"),
            "{cmd}"
        );
        assert!(cmd.contains("Select-Object -Last 50"), "{cmd}");
        assert!(!cmd.contains("Select-Object -First"), "{cmd}");
        assert!(!cmd.contains("-Raw"), "{cmd}");
    }

    /// AC-REL16-1: `count_only` returns the number of matches for each file. It
    /// counts through `Measure-Object`, which streams and does not build an array.
    #[test]
    fn search_file_content_count_only_counts_each_file() {
        let options = SearchOptions {
            count_only: true,
            ..default_options()
        };
        let cmd = search_file_content("C:\\app.log", "ERROR", "*.log", 50, 0, 0, &options)
            .expect("valid");
        assert!(cmd.contains("Measure-Object).Count"), "{cmd}");
        assert!(cmd.contains("matches"), "{cmd}");
        assert!(!cmd.contains("Select-Object -First"), "{cmd}");
        assert!(!cmd.contains("Select-Object -Last"), "{cmd}");
    }

    /// AC-REL16-2: `since`, `until` and `timestamp_format` filter the lines by the
    /// timestamp at the start of the line, with the invariant culture (Q-22). A
    /// line without a timestamp is outside the range.
    #[test]
    fn search_file_content_time_filter_parses_the_line_prefix() {
        let options = SearchOptions {
            from_end: false,
            count_only: false,
            since: "2026-01-01 09:30:00",
            until: "2026-01-01 11:00:00",
            timestamp_format: "yyyy-MM-dd HH:mm:ss",
        };
        let cmd = search_file_content("C:\\app.log", "ERROR", "*.log", 50, 0, 0, &options)
            .expect("valid");
        assert!(cmd.contains("$fmt='yyyy-MM-dd HH:mm:ss'"), "{cmd}");
        assert!(
            cmd.contains("$len=(Get-Date).ToString($fmt,$inv).Length"),
            "{cmd}"
        );
        assert!(
            cmd.contains("[Globalization.CultureInfo]::InvariantCulture"),
            "{cmd}"
        );
        assert!(
            cmd.contains("ParseExact('2026-01-01T09:30:00.0000000','yyyy-MM-ddTHH:mm:ss.fffffff'"),
            "{cmd}"
        );
        assert!(
            cmd.contains("ParseExact('2026-01-01T11:00:00.0000000','yyyy-MM-ddTHH:mm:ss.fffffff'"),
            "{cmd}"
        );
        assert!(
            cmd.contains("TryParseExact($ln.Substring(0,$len),$fmt,$inv"),
            "{cmd}"
        );
        assert!(cmd.contains("if($ln.Length -lt $len){ $false }"), "{cmd}");
        assert!(
            cmd.contains("-and $ts -ge $since -and $ts -le $until"),
            "{cmd}"
        );
    }

    /// Q-22: a bound without a format uses the default line format, and a missing
    /// bound becomes the smallest or the largest date.
    #[test]
    fn search_file_content_time_filter_defaults_the_format_and_the_missing_bound() {
        let options = SearchOptions {
            since: "2026-01-01 09:30:00",
            ..default_options()
        };
        let cmd = search_file_content("C:\\app.log", "ERROR", "*.log", 50, 0, 0, &options)
            .expect("valid");
        assert!(cmd.contains("$fmt='yyyy-MM-dd HH:mm:ss'"), "{cmd}");
        assert!(cmd.contains("$since=[DateTime]::ParseExact"), "{cmd}");
        assert!(cmd.contains("$until=[DateTime]::MaxValue"), "{cmd}");
    }

    /// TR-REL-16 backward compatibility: without a bound the format is not used
    /// and not validated, so the default call is unchanged.
    #[test]
    fn search_file_content_ignores_the_format_without_a_bound() {
        let options = SearchOptions {
            timestamp_format: "not a format",
            ..default_options()
        };
        assert!(
            search_file_content("C:\\app.log", "ERROR", "*.log", 50, 0, 0, &options).is_ok(),
            "the format must be ignored without a bound"
        );
    }

    /// TR-REL-16: an invalid bound is refused before any host call, with the
    /// accepted shape in the message.
    #[test]
    fn search_file_content_rejects_an_invalid_time_bound() {
        let options = SearchOptions {
            since: "yesterday",
            ..default_options()
        };
        let error = search_file_content("C:\\app.log", "ERROR", "*.log", 50, 0, 0, &options)
            .expect_err("bad timestamp");
        assert!(error.contains("Invalid timestamp"), "{error}");
        assert!(error.contains("YYYY-MM-DD"), "{error}");
    }

    /// TR-REL-16: a bound outside the calendar is refused, not left to the host.
    #[test]
    fn search_file_content_rejects_an_out_of_range_bound() {
        let options = SearchOptions {
            since: "2026-13-01 00:00:00",
            ..default_options()
        };
        let error = search_file_content("C:\\app.log", "ERROR", "*.log", 50, 0, 0, &options)
            .expect_err("bad month");
        assert!(error.contains("Invalid timestamp"), "{error}");
    }

    /// TR-REL-16: a variable-width specifier is refused, because the host takes a
    /// timestamp prefix of a fixed length.
    #[test]
    fn search_file_content_rejects_a_variable_width_format() {
        let options = SearchOptions {
            since: "2026-01-01 00:00:00",
            timestamp_format: "M/d/yyyy H:mm:ss",
            ..default_options()
        };
        let error = search_file_content("C:\\app.log", "ERROR", "*.log", 50, 0, 0, &options)
            .expect_err("variable width");
        assert!(error.contains("not a fixed-width date field"), "{error}");
    }

    /// TR-REL-16: with `from_end` or a time filter the directory search orders the
    /// files by their last write time, so `app.log.2` (the oldest) is not last.
    #[test]
    fn search_file_content_sorts_the_directory_files_for_from_end() {
        let options = SearchOptions {
            from_end: true,
            ..default_options()
        };
        let cmd =
            search_file_content("C:\\logs", "ERROR", "*.log", 50, 0, 0, &options).expect("valid");
        let sort_at = cmd.find("Sort-Object LastWriteTime").expect("sort");
        let search_at = cmd.find("Select-String").expect("search");
        assert!(
            sort_at < search_at,
            "the sort must run before Select-String: {cmd}"
        );
    }

    /// TR-REL-16 backward compatibility: the default search keeps the directory
    /// enumeration order.
    #[test]
    fn search_file_content_default_keeps_the_file_order() {
        let cmd = search_file_content("C:\\logs", "ERROR", "*.log", 50, 0, 0, &default_options())
            .expect("valid");
        assert!(!cmd.contains("Sort-Object"), "{cmd}");
    }

    /// TR-REL-16: a time bound with an empty pattern matches every line. Without a
    /// time bound an empty pattern is refused, because `Select-String -Pattern ''`
    /// rejects an empty string on the host.
    #[test]
    fn search_file_content_time_only_matches_every_line() {
        let options = SearchOptions {
            since: "2026-01-01 00:00:00",
            ..default_options()
        };
        let cmd =
            search_file_content("C:\\app.log", "", "*.log", 50, 0, 0, &options).expect("valid");
        assert!(cmd.contains("Select-String -Pattern '.'"), "{cmd}");
        assert!(
            !cmd.contains("-SimpleMatch"),
            "the time-only filter must not use SimpleMatch: {cmd}"
        );

        let error = search_file_content("C:\\app.log", "", "*.log", 50, 0, 0, &default_options())
            .expect_err("an empty pattern without a time bound");
        assert!(error.contains("pattern is empty"), "{error}");
    }

    /// TR-REL-16: a date that does not exist is refused, not left to the host.
    #[test]
    fn search_file_content_rejects_an_impossible_date() {
        let options = SearchOptions {
            since: "2026-02-31",
            ..default_options()
        };
        let error = search_file_content("C:\\app.log", "ERROR", "*.log", 50, 0, 0, &options)
            .expect_err("31 February");
        assert!(error.contains("Invalid timestamp"), "{error}");
    }

    /// TR-REL-16: `since` after `until` is refused before any host call.
    #[test]
    fn search_file_content_rejects_since_after_until() {
        let options = SearchOptions {
            since: "2026-01-02 00:00:00",
            until: "2026-01-01 00:00:00",
            ..default_options()
        };
        let error = search_file_content("C:\\app.log", "ERROR", "*.log", 50, 0, 0, &options)
            .expect_err("reversed range");
        assert!(error.contains("is after until"), "{error}");
    }

    /// TR-REL-16: a date-only `until` is the end of that day; a date-only `since`
    /// is the start of the day. Fractional seconds are kept at full precision.
    #[test]
    fn search_file_content_normalizes_date_only_and_fraction_bounds() {
        let options = SearchOptions {
            since: "2026-01-01",
            until: "2026-01-01",
            ..default_options()
        };
        let cmd = search_file_content("C:\\app.log", "ERROR", "*.log", 50, 0, 0, &options)
            .expect("valid");
        assert!(
            cmd.contains("ParseExact('2026-01-01T00:00:00.0000000'"),
            "{cmd}"
        );
        assert!(
            cmd.contains("ParseExact('2026-01-01T23:59:59.9999999'"),
            "{cmd}"
        );

        let fraction = SearchOptions {
            since: "2026-01-01 09:30:00.5",
            ..default_options()
        };
        let cmd = search_file_content("C:\\app.log", "ERROR", "*.log", 50, 0, 0, &fraction)
            .expect("valid");
        assert!(
            cmd.contains("ParseExact('2026-01-01T09:30:00.5000000'"),
            "{cmd}"
        );
    }

    /// TR-REL-16: `MMM` and `ddd` are fixed three-character fields in the
    /// invariant culture; `MMMM` and `dddd` are variable and refused.
    #[test]
    fn search_file_content_accepts_month_and_day_names() {
        for format in ["dd MMM yyyy HH:mm:ss", "ddd yyyy-MM-dd HH:mm:ss"] {
            let options = SearchOptions {
                since: "2026-01-01 00:00:00",
                timestamp_format: format,
                ..default_options()
            };
            assert!(
                search_file_content("C:\\app.log", "ERROR", "*.log", 50, 0, 0, &options).is_ok(),
                "{format} must be accepted"
            );
        }
        for format in ["MMMM yyyy", "dddd yyyy"] {
            let options = SearchOptions {
                since: "2026-01-01 00:00:00",
                timestamp_format: format,
                ..default_options()
            };
            let error = search_file_content("C:\\app.log", "ERROR", "*.log", 50, 0, 0, &options)
                .expect_err("variable width");
            assert!(
                error.contains("not a fixed-width date field"),
                "{format}: {error}"
            );
        }
    }

    /// TR-REL-16: a one-character format is a .NET standard format, not a custom
    /// one, and is refused.
    #[test]
    fn search_file_content_rejects_a_standard_format() {
        for format in ["f", "D"] {
            let options = SearchOptions {
                since: "2026-01-01 00:00:00",
                timestamp_format: format,
                ..default_options()
            };
            let error = search_file_content("C:\\app.log", "ERROR", "*.log", 50, 0, 0, &options)
                .expect_err("standard format");
            assert!(error.contains("standard format"), "{format}: {error}");
        }
    }

    /// TR-REL-16: `count_only` over a directory prints a summary line after the
    /// per-file counts.
    #[test]
    fn search_file_content_count_only_prints_a_directory_summary() {
        let options = SearchOptions {
            count_only: true,
            ..default_options()
        };
        let cmd =
            search_file_content("C:\\logs", "ERROR", "*.log", 50, 0, 0, &options).expect("valid");
        assert!(
            cmd.contains("\"$scanned files scanned, $matched with matches\""),
            "{cmd}"
        );
        assert!(
            !cmd.contains("($scanned + "),
            "the summary must not add an integer and a string: {cmd}"
        );
    }

    /// A PowerShell command fails when a number sits on the left of a string
    /// addition: the right operand converts to `Int32` (TR-REL-16).
    #[test]
    fn no_generator_adds_a_number_to_a_string() {
        for command in every_generator_command("x") {
            for left in [
                "$scanned + ",
                "$matched + ",
                "$read + ",
                "$kept + ",
                "$diff + ",
            ] {
                assert!(
                    !command.contains(left),
                    "an integer sits on the left of a string addition: {command}"
                );
            }
        }
    }

    /// Worst case for the WinRS command line: a pattern whose every character is a
    /// single quote, so the escape doubles it and the pattern appears in both
    /// branches. A large pattern still fits one command line (TR-REL-16).
    #[test]
    fn search_file_content_fits_the_winrs_line_for_the_worst_case() {
        let pattern = "'".repeat(300);
        let cmd = search_file_content(
            "C:\\app.log",
            &pattern,
            "*.log",
            100,
            0,
            0,
            &default_options(),
        )
        .expect("the worst case must fit one command line");
        assert!(
            fits_command_line(&cmd),
            "chars: {}",
            command_line_chars(&cmd)
        );
        assert!(command_line_chars(&cmd) < WINRS_COMMAND_LINE_LIMIT);
    }

    /// TR-REL-16: an input too long for one command line is refused before any
    /// host call, and the refusal names the limit.
    #[test]
    fn search_file_content_refuses_inputs_above_the_command_line() {
        let pattern = "'".repeat(5000);
        let error = search_file_content(
            "C:\\app.log",
            &pattern,
            "*.log",
            100,
            0,
            0,
            &default_options(),
        )
        .expect_err("too long");
        assert!(
            error.contains(&WINRS_COMMAND_LINE_LIMIT.to_string()),
            "{error}"
        );
    }

    /// TR-REL-06: the row cap keeps one answer readable even for a large request.
    #[test]
    fn search_and_read_cap_the_rows() {
        let cmd = search_file_content(
            "C:\\app.log",
            "ERROR",
            "*.log",
            9999,
            0,
            0,
            &default_options(),
        )
        .expect("valid");
        assert!(cmd.contains("Select-Object -First 100"), "{cmd}");
        let tail = read_file("C:\\a.log", 1, 9999, true, "UTF8", "").expect("valid");
        assert!(tail.contains("-Tail 500"), "{tail}");
    }

    /// TR-REL-16: a path too long for one command line is refused before any host
    /// call, and the refusal names the limit.
    #[test]
    fn read_file_refuses_a_path_above_the_command_line() {
        let path = format!("C:\\{}", "'".repeat(6000));
        let error = read_file(&path, 1, 10, false, "UTF8", "").expect_err("too long");
        assert!(
            error.contains(&WINRS_COMMAND_LINE_LIMIT.to_string()),
            "{error}"
        );
    }

    /// Worst case for the WinRS command line: an `exclude` whose every character
    /// is a single quote, so the escape doubles it. A large exclude still fits one
    /// command line (TR-REL-16).
    #[test]
    fn read_file_tail_exclude_fits_the_winrs_line_for_the_worst_case() {
        let exclude = "'".repeat(300);
        let cmd = read_file("C:\\a.log", 1, 100, true, "UTF8", &exclude).expect("fits");
        assert!(
            fits_command_line(&cmd),
            "chars: {}",
            command_line_chars(&cmd)
        );
    }

    /// TR-REL-16: an `exclude` too long for one command line is refused before any
    /// host call, and the refusal names the limit.
    #[test]
    fn read_file_tail_exclude_refuses_an_input_above_the_command_line() {
        let exclude = "'".repeat(5000);
        let error = read_file("C:\\a.log", 1, 100, true, "UTF8", &exclude).expect_err("too long");
        assert!(
            error.contains(&WINRS_COMMAND_LINE_LIMIT.to_string()),
            "{error}"
        );
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

    /// AC-REL12-1: a channel name with any single quote doubles every form of the
    /// quote in the recorded command (TR-SEC-12).
    #[test]
    fn get_event_log_escapes_the_channel_name_quote() {
        for quote in SINGLE_QUOTES {
            let channel = format!("Microsoft-Windows-X{quote}Operational");
            let cmd = get_event_log(&channel, "error", 24, "", 10).expect("valid");
            let doubled = format!("Microsoft-Windows-X{quote}{quote}Operational");
            assert!(
                cmd.contains(&format!("LogName='{doubled}'")),
                "the channel quote must be doubled: {cmd}"
            );
        }
    }

    /// TR-REL-12: the query selects the channel by name, so any operational
    /// channel passes. The channel is validated with `-ListLog` before the event
    /// query, so a mistyped channel fails before the query runs.
    #[test]
    fn get_event_log_accepts_an_operational_channel() {
        let cmd = get_event_log(
            "Microsoft-Windows-PrintService/Operational",
            "info",
            24,
            "",
            25,
        )
        .expect("valid");
        assert!(
            cmd.contains("LogName='Microsoft-Windows-PrintService/Operational'"),
            "{cmd}"
        );
        let list_log = cmd.find("-ListLog").expect("the channel check");
        let filter = cmd.find("-FilterHashtable").expect("the event query");
        assert!(
            list_log < filter,
            "the channel check must precede the event query: {cmd}"
        );
    }

    /// A channel name with a wildcard is refused before any host call, because
    /// the validation must check one exact channel.
    #[test]
    fn get_event_log_refuses_a_wildcard_channel() {
        for name in ["*", "Microsoft-Windows-*", "Print?Service", "[System]"] {
            let error = get_event_log(name, "error", 24, "", 10).expect_err("wildcard channel");
            assert!(error.contains("log_name"), "{error}");
            assert!(error.contains("'*'"), "{error}");
        }
    }

    /// The "no events" error is an empty result, not a failure. The branch is on
    /// the error id, because the message text is localized.
    #[test]
    fn get_event_log_treats_no_matching_events_as_empty() {
        let cmd = get_event_log("System", "error", 24, "", 10).expect("valid");
        assert!(
            cmd.contains("$_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'"),
            "{cmd}"
        );
        assert!(cmd.contains("$ev = @()"), "{cmd}");
    }

    /// A missing channel fails the call before the query; a pre-check error for
    /// another reason is ignored and the query runs. In the query only the "no
    /// matching events" error becomes an empty list; any other error is rethrown.
    #[test]
    fn get_event_log_rethrows_only_a_missing_channel_and_query_errors() {
        let cmd = get_event_log("Security", "error", 24, "", 10).expect("valid");
        assert!(
            cmd.contains(
                "catch { if ($_.FullyQualifiedErrorId -like '*NoMatchingLogs*') { throw } }"
            ),
            "the pre-check must rethrow only a missing channel: {cmd}"
        );
        assert!(
            cmd.contains(
                "catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $ev = @() } else { throw } }"
            ),
            "the query must rethrow everything but a no-match: {cmd}"
        );
    }

    /// Worst case for the WinRS command line: a long channel name and a long
    /// source wildcard. The command must still fit one line.
    #[test]
    fn get_event_log_command_fits_the_winrs_line_for_a_long_channel() {
        let channel = format!("Microsoft-Windows-{}/Operational", "A".repeat(200));
        let source = format!("Microsoft-Windows-{}-*", "B".repeat(200));
        let cmd = get_event_log(&channel, "info", 24, &source, 100).expect("valid");
        assert!(
            command_line_chars(&cmd) < WINRS_COMMAND_LINE_LIMIT,
            "chars: {}",
            command_line_chars(&cmd)
        );
    }

    /// AC-REL12-2: the command reads `Get-WinEvent -ListLog` and the result names
    /// each channel, the record count and the enabled state as a JSON array.
    #[test]
    fn list_event_logs_reads_the_channel_list() {
        let cmd = list_event_logs("Microsoft-Windows-*");
        assert!(
            cmd.contains("Get-WinEvent -ListLog 'Microsoft-Windows-*'"),
            "{cmd}"
        );
        assert!(cmd.contains("name=$_.LogName"), "{cmd}");
        assert!(cmd.contains("record_count=$_.RecordCount"), "{cmd}");
        assert!(cmd.contains("enabled=[bool]$_.IsEnabled"), "{cmd}");
        assert!(
            cmd.contains("$rows = @("),
            "the array form needs @(): {cmd}"
        );
        assert!(cmd.contains("ConvertTo-Json"), "{cmd}");
        assert!(cmd.contains("truncated=$truncated"), "{cmd}");
    }

    /// A channel that denies access is skipped, not fatal: the list continues and
    /// the count of skipped channels goes to the result.
    #[test]
    fn list_event_logs_skips_an_inaccessible_channel() {
        let cmd = list_event_logs("");
        assert!(
            cmd.contains("-ErrorAction SilentlyContinue -ErrorVariable err"),
            "{cmd}"
        );
        assert!(cmd.contains("$skipped = @($err"), "{cmd}");
        assert!(cmd.contains("skipped=$skipped"), "{cmd}");
        // The "no matching logs" error is an empty result, not a skip, so it is
        // excluded by the error id (the message text is localized).
        assert!(
            cmd.contains("$_.FullyQualifiedErrorId -notlike '*NoMatchingLogs*'"),
            "{cmd}"
        );
    }

    /// An empty filter lists every channel; the pattern is the wildcard.
    #[test]
    fn list_event_logs_empty_filter_lists_every_channel() {
        let cmd = list_event_logs("   ");
        assert!(cmd.contains("Get-WinEvent -ListLog '*'"), "{cmd}");
    }

    /// Worst case for the WinRS command line: a long channel wildcard.
    #[test]
    fn list_event_logs_command_fits_the_winrs_line_for_a_long_filter() {
        let filter = format!("{}-*", "A".repeat(300));
        let cmd = list_event_logs(&filter);
        assert!(
            command_line_chars(&cmd) < WINRS_COMMAND_LINE_LIMIT,
            "chars: {}",
            command_line_chars(&cmd)
        );
    }

    /// The cap keeps the JSON result inside the executor output limit even with
    /// the longest plausible channel names.
    #[test]
    fn list_event_logs_output_fits_the_executor_cap() {
        let rows: Vec<Value> = (0..EVENT_LOG_LIMIT)
            .map(|index| {
                serde_json::json!({
                    "name": "A".repeat(100),
                    "record_count": 9_999_999_i64,
                    "enabled": index % 2 == 0,
                })
            })
            .collect();
        let payload = serde_json::json!({
            "logs": rows,
            "count": EVENT_LOG_LIMIT,
            "truncated": false,
            "skipped": 0,
        });
        let text = serde_json::to_string(&payload).expect("serialize");
        assert!(
            text.len() <= crate::executor::MAX_OUTPUT_CHARS,
            "the capped result is {} characters, over the {} limit",
            text.len(),
            crate::executor::MAX_OUTPUT_CHARS
        );
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
            get_registry("HKEY_LOCAL_MACHINE\\SOFTWARE", "", false, 1)
                .contains("Registry::HKEY_LOCAL_MACHINE")
        );
        assert!(
            get_registry("HKLM:\\SOFTWARE", "", false, 1)
                .contains("-LiteralPath 'HKLM:\\SOFTWARE'")
        );
    }

    #[test]
    fn registry_generators_use_literal_path() {
        // AC-REL06-1: a literal path with wildcard characters is not treated as
        // a pattern, so `-Path` is not allowed here, only `-LiteralPath`.
        let read = get_registry("HKLM:\\SOFTWARE\\App[1]", "", false, 1);
        assert!(read.contains("-LiteralPath '"), "{read}");
        assert!(!read.contains("-Path '"), "{read}");
        // The subkey walk uses the same literal path, so a name with a wildcard
        // character cannot widen the query.
        let walk = get_registry("HKLM:\\SOFTWARE\\App[1]", "", true, 2);
        assert!(
            walk.contains("-LiteralPath 'HKLM:\\SOFTWARE\\App[1]'"),
            "{walk}"
        );
        assert!(!walk.contains("-Path '"), "{walk}");
    }

    /// AC-REL11-1: with `subkeys=true` the command lists the child key names down
    /// to `depth` next to the values. `depth` counts child levels, so level 1 is a
    /// plain child listing (`-Depth 0`) and level 2 is `-Depth 1`.
    #[test]
    fn get_registry_lists_subkeys_down_to_depth() {
        let one = get_registry("HKLM:\\SOFTWARE", "", true, 1);
        assert!(
            one.contains("Get-ChildItem -LiteralPath 'HKLM:\\SOFTWARE' -Recurse -Depth 0"),
            "{one}"
        );
        let two = get_registry("HKLM:\\SOFTWARE", "", true, 2);
        assert!(
            two.contains("Get-ChildItem -LiteralPath 'HKLM:\\SOFTWARE' -Recurse -Depth 1"),
            "{two}"
        );
        assert!(
            two.contains("Get-ItemProperty -LiteralPath 'HKLM:\\SOFTWARE'"),
            "{two}"
        );
        assert!(two.contains("ConvertTo-Json"), "{two}");
    }

    /// AC-REL11-1: each child is a path relative to the key, cut from the item
    /// `Name` (the hive path) by the length of the root `Name`.
    #[test]
    fn get_registry_returns_relative_child_paths() {
        let cmd = get_registry("HKLM:\\SOFTWARE", "", true, 2);
        assert!(
            cmd.contains("$_.Name.Substring($root.Name.Length+1)"),
            "{cmd}"
        );
        assert!(
            cmd.contains("$root=Get-Item -LiteralPath 'HKLM:\\SOFTWARE'"),
            "{cmd}"
        );
    }

    /// AC-REL11-1: the answer is capped and flags a truncation. The command fetches
    /// one key over the cap so a full result is not reported as truncated.
    #[test]
    fn get_registry_caps_subkeys_and_flags_truncation() {
        let cmd = get_registry("HKLM:\\SOFTWARE", "", true, 2);
        assert!(
            cmd.contains(&format!(
                "Select-Object -First {}",
                REGISTRY_SUBKEY_LIMIT + 1
            )),
            "{cmd}"
        );
        assert!(
            cmd.contains(&format!(
                "$truncated=$items.Count -gt {REGISTRY_SUBKEY_LIMIT}"
            )),
            "{cmd}"
        );
        assert!(cmd.contains("truncated=$truncated"), "{cmd}");
    }

    /// AC-REL11-1: a child that denies access is skipped and counted, not fatal.
    #[test]
    fn get_registry_reports_skipped_children() {
        let cmd = get_registry("HKLM:\\SOFTWARE", "", true, 2);
        assert!(cmd.contains("-ErrorVariable subErr"), "{cmd}");
        assert!(cmd.contains("$skipped=@($subErr).Count"), "{cmd}");
        assert!(cmd.contains("skipped=$skipped"), "{cmd}");
    }

    /// AC-REL11-1: the range 1 to 5 is a safety limit, so a value outside it is
    /// clamped rather than refused.
    #[test]
    fn get_registry_clamps_depth() {
        assert!(get_registry("HKLM:\\A", "", true, 0).contains("-Depth 0"));
        assert!(get_registry("HKLM:\\A", "", true, -4).contains("-Depth 0"));
        assert!(get_registry("HKLM:\\A", "", true, 99).contains("-Depth 4"));
        assert!(get_registry("HKLM:\\A", "", true, 5).contains("-Depth 4"));
    }

    /// AC-REL11-1: a named value and the subkeys come together. The value read does
    /// not stop on error, so an absent value gives `values=null` with an `error`
    /// field and the subkeys still arrive.
    #[test]
    fn get_registry_keeps_subkeys_when_a_named_value_is_absent() {
        let named = get_registry("HKLM:\\A", "Version", true, 3);
        assert!(
            named.contains("-Name 'Version' -ErrorAction SilentlyContinue"),
            "{named}"
        );
        assert!(named.contains("$e=if($null -eq $v)"), "{named}");
        // The same text covers an absent value and an access-denied read.
        assert!(named.contains("'value not read'"), "{named}");
        assert!(named.contains("subkeys=$keys"), "{named}");
        assert!(named.contains("-Depth 2"), "{named}");
    }

    /// AC-REL11-2: with the default `subkeys=false` the command stays the
    /// values-only form and does not walk the key.
    #[test]
    fn get_registry_without_subkeys_stays_values_only() {
        let cmd = get_registry("HKLM:\\SOFTWARE", "", false, 2);
        assert!(!cmd.contains("Get-ChildItem"), "{cmd}");
        assert!(
            cmd.contains(
                "Get-ItemProperty -LiteralPath 'HKLM:\\SOFTWARE' -ErrorAction Stop \
                 | Select-Object * -ExcludeProperty PS* | ConvertTo-Json -Compress"
            ),
            "{cmd}"
        );
    }

    /// DR-4, TR-SEC-18: the pre-confirmation read returns only the state and the
    /// type, so the old value never reaches the prompt or the audit. An access
    /// denied read is `unknown`, and the branch is on the .NET exception type, not
    /// on a localized message.
    #[test]
    fn registry_value_presence_reads_no_data() {
        let cmd = registry_value_presence("HKLM:\\SOFTWARE\\MyApp", "Password");
        assert!(cmd.contains("GetValueNames"), "{cmd}");
        assert!(cmd.contains("GetValueKind"), "{cmd}");
        assert!(cmd.contains("state='present'"), "{cmd}");
        assert!(cmd.contains("state='absent'"), "{cmd}");
        assert!(
            cmd.contains("System.Management.Automation.ItemNotFoundException"),
            "the absence branch is not on the exception type: {cmd}"
        );
        assert!(
            !cmd.contains("Get-ItemProperty"),
            "the presence read must not read the value data: {cmd}"
        );
    }

    /// Worst case for the WinRS command line: the deepest walk, the cap and a long
    /// key with a named value. The command must still fit one line.
    #[test]
    fn get_registry_subkey_command_fits_the_winrs_line_for_a_long_key() {
        let key = format!(
            "HKLM:\\{}",
            "Microsoft\\Windows\\CurrentVersion\\Uninstall\\".repeat(8)
        );
        let cmd = get_registry(&key, "DisplayName", true, 5);
        assert!(
            command_line_chars(&cmd) < WINRS_COMMAND_LINE_LIMIT,
            "chars: {}",
            command_line_chars(&cmd)
        );
    }

    #[test]
    fn test_network_switches_between_ping_and_tcp() {
        assert!(test_network("host", 0).contains("Test-Connection"));
        assert!(test_network("host", 443).contains("Test-NetConnection"));
    }

    #[test]
    fn tcp_connections_default_to_established() {
        let cmd = get_tcp_connections("Established", 0, 0, "", false).expect("valid");
        assert!(cmd.contains("$_.State -eq 'Established'"));
        // The default output shape stays the tabular one (backward compatible).
        assert!(cmd.contains("Format-Table"), "{cmd}");
        assert!(!cmd.contains("Group-Object"), "{cmd}");
    }

    /// TR-REL-13: a `state_filter` outside the accepted values is refused with
    /// the list, not silently mapped to `Established`.
    #[test]
    fn tcp_connections_reject_an_unknown_state() {
        let error = get_tcp_connections("galaxy", 0, 0, "", false).expect_err("unknown state");
        assert!(error.contains("Established"), "{error}");
        assert!(error.contains("Listen"), "{error}");
        assert!(error.contains("All"), "{error}");
        assert!(
            get_tcp_connections("all", 0, 0, "", false).is_ok(),
            "All must stay accepted"
        );
        // The comparison is case-insensitive, as the state names are.
        assert!(get_tcp_connections("lIsTeN", 0, 0, "", false).is_ok());
    }

    /// TR-REL-13: the `pid` and `process` filters narrow the rows, and the owning
    /// process name is resolved once, not once per row.
    #[test]
    fn tcp_connections_apply_pid_and_process_filters() {
        let cmd = get_tcp_connections("all", 0, 1234, "chrome*", false).expect("valid");
        assert!(cmd.contains("$_.OwningProcess -eq 1234"), "{cmd}");
        assert!(
            cmd.contains("$names[[int]$_.OwningProcess] -like 'chrome*'"),
            "{cmd}"
        );
        // One `Get-Process` call feeds the hashtable; a per-row call would be N.
        assert_eq!(cmd.matches("Get-Process").count(), 1, "{cmd}");
        // The value 0 means all the processes, so no filter is emitted.
        let none = get_tcp_connections("all", 0, 0, "   ", false).expect("valid");
        assert!(!none.contains("OwningProcess -eq"), "{none}");
        assert!(!none.contains("-like"), "{none}");
    }

    /// TR-REL-13: the `[` of the process wildcard is escaped with a backtick, so
    /// an unbalanced bracket reaches `-like` as a literal and does not throw on
    /// every row.
    #[test]
    fn tcp_connections_escape_the_process_wildcard_brackets() {
        let cmd = get_tcp_connections("all", 0, 0, "a[", false).expect("valid");
        assert!(
            cmd.contains("$names[[int]$_.OwningProcess] -like 'a`['"),
            "{cmd}"
        );
        let both = get_tcp_connections("all", 0, 0, "a]b[", false).expect("valid");
        assert!(both.contains("'a`]b`['"), "{both}");
    }

    /// AC-REL13-1: `state_filter='Listen'` with `summary=true` filters on the
    /// state, groups the rows with a count, and a `Listen` row holds the bound
    /// address (the local address).
    #[test]
    fn tcp_connections_summary_groups_listeners_with_the_bound_address() {
        let cmd = get_tcp_connections("Listen", 0, 0, "", true).expect("valid");
        assert!(cmd.contains("$_.State -eq 'Listen'"), "{cmd}");
        assert!(cmd.contains("Group-Object"), "{cmd}");
        assert!(cmd.contains("count=$_.Count"), "{cmd}");
        assert!(
            cmd.contains("local_address=[string]$first.LocalAddress"),
            "{cmd}"
        );
        assert!(cmd.contains("ConvertTo-Json"), "{cmd}");
    }

    /// TR-REL-13: the summary is capped and flags a truncation; it fetches one
    /// group over the cap so a full result is not reported as truncated. `@()`
    /// keeps a single group an array. The cap keeps the largest groups: the sort
    /// by count runs before the slice.
    #[test]
    fn tcp_connections_summary_caps_the_largest_groups_and_flags_truncation() {
        let cmd = get_tcp_connections("Established", 0, 0, "", true).expect("valid");
        let take = format!("Select-Object -First {}", TCP_SUMMARY_LIMIT + 1);
        assert!(cmd.contains(&take), "{cmd}");
        assert!(
            cmd.contains(&format!("$truncated=$groups.Count -gt {TCP_SUMMARY_LIMIT}")),
            "{cmd}"
        );
        assert!(cmd.contains("$rows=@("), "the array form needs @(): {cmd}");
        assert!(cmd.contains("truncated=$truncated"), "{cmd}");
        let sort = cmd.find("Sort-Object Count -Descending").expect("sort");
        let slice = cmd.find(&take).expect("slice");
        assert!(sort < slice, "the sort must run before the cap: {cmd}");
    }

    /// Worst case for the WinRS command line: the process wildcard at the
    /// 256-character limit in the summary form, with the most costly escaping —
    /// `'` doubles to `''` and `[` becomes `` `[ ``. The command must still fit
    /// one line.
    #[test]
    fn get_tcp_connections_command_fits_the_winrs_line_for_a_long_wildcard() {
        for process in [
            "[".repeat(TCP_PROCESS_FILTER_MAX_CHARS),
            "'".repeat(TCP_PROCESS_FILTER_MAX_CHARS),
        ] {
            let cmd = get_tcp_connections("all", 0, 0, &process, true).expect("valid");
            assert!(
                command_line_chars(&cmd) < WINRS_COMMAND_LINE_LIMIT,
                "chars: {}",
                command_line_chars(&cmd)
            );
        }
    }

    /// The cap keeps the summary JSON inside the executor output limit even with
    /// the longest plausible process names and addresses.
    #[test]
    fn tcp_connections_summary_fits_the_executor_cap() {
        let rows: Vec<Value> = (0..TCP_SUMMARY_LIMIT)
            .map(|_| {
                serde_json::json!({
                    "process": "A".repeat(255),
                    "local_port": 65535,
                    "local_address": "f".repeat(45),
                    "remote_address": "f".repeat(45),
                    "count": 9_999_999_i64,
                })
            })
            .collect();
        let payload = serde_json::json!({
            "groups": rows,
            "count": TCP_SUMMARY_LIMIT,
            "truncated": false,
        });
        let text = serde_json::to_string(&payload).expect("serialize");
        assert!(
            text.len() <= crate::executor::MAX_OUTPUT_CHARS,
            "the capped summary is {} characters, over the {} limit",
            text.len(),
            crate::executor::MAX_OUTPUT_CHARS
        );
    }

    /// AC-REL14-1: the command reaches the Restart Manager through a dynamic
    /// P/Invoke type, so the host needs no Sysinternals `handle.exe` and no
    /// compiler runs (unlike `Add-Type`).
    #[test]
    fn get_open_handles_uses_reflection_emit_without_add_type() {
        let cmd = get_open_handles("C:\\App\\data.mdb").expect("valid");
        for api in [
            "DefineDynamicAssembly",
            "DefineDynamicModule",
            "DefinePInvokeMethod",
            "rstrtmgr.dll",
            "RmStartSession",
            "RmRegisterResources",
            "RmGetList",
            "RmEndSession",
        ] {
            assert!(cmd.contains(api), "missing {api}: {cmd}");
        }
        assert!(
            !cmd.contains("Add-Type"),
            "Add-Type writes to the host disk: {cmd}"
        );
        // Reflection through `MethodInfo.Invoke` cannot bind `[ref]` and does not
        // coerce `object[]` to `string[]`; the PowerShell binder on `$t::…` is used.
        assert!(
            !cmd.contains(".Invoke($null,"),
            "the P/Invoke must be called through the PowerShell binder: {cmd}"
        );
    }

    /// `$name:` inside a double-quoted string is a scope qualifier and breaks the
    /// parse; the safe form is `${name}`. The error text must stay free of an
    /// unbraced variable followed by a colon (TR-REL-14).
    #[test]
    fn get_open_handles_has_no_scope_qualified_variable_in_a_string() {
        let cmd = get_open_handles("C:\\App\\data.mdb").expect("valid");
        assert_eq!(
            unbraced_variable_colon(&cmd),
            None,
            "an unbraced $name: lives in a double-quoted string"
        );
        assert!(!cmd.contains("$r:"), "{cmd}");
        assert!(cmd.contains("${r}: $($e[$r])"), "{cmd}");
    }

    /// The P/Invoke signatures, declared through one helper over a signature
    /// table: an out handle and a 33-character session key for `RmStartSession`;
    /// a 7-argument `RmRegisterResources`; a byte buffer of 668 bytes for each
    /// `RM_PROCESS_INFO` and three out/ref counts for `RmGetList` (TR-REL-14).
    #[test]
    fn get_open_handles_declares_the_pinvoke_signatures() {
        let cmd = get_open_handles("C:\\App\\data.mdb").expect("valid");
        assert!(
            cmd.contains("DefinePInvokeMethod($args[0],'rstrtmgr.dll',22,1,[int],$args[1],1,3)"),
            "{cmd}"
        );
        // 22 = Public|Static (DefinePInvokeMethod adds PinvokeImpl); the trailing
        // 1,3 is CallingConvention.Winapi and CharSet.Unicode; 128 is PreserveSig.
        assert!(cmd.contains("SetImplementationFlags(128)"), "{cmd}");
        assert!(cmd.contains("$q=[int].MakeByRefType()"), "{cmd}");
        for call in [
            "&$w RmStartSession @($q,[int],[char[]])",
            "&$w RmRegisterResources @([int],[int],[string[]],[int],[IntPtr],[int],[IntPtr])",
            "&$w RmGetList @([int],$q,$q,[byte[]],$q)",
            "&$w RmEndSession @([int])",
        ] {
            assert!(cmd.contains(call), "missing {call}: {cmd}");
        }
        assert!(
            cmd.contains("$r=$t::RmStartSession([ref]$h,0,[char[]]::new(33))"),
            "{cmd}"
        );
        assert!(
            cmd.contains("$t::RmRegisterResources($h,$f.Count,[string[]]$f,0,[IntPtr]::Zero,0,[IntPtr]::Zero)"),
            "{cmd}"
        );
        assert!(
            cmd.contains("$t::RmGetList($h,[ref]$n,[ref]$c,$d,[ref]$b)"),
            "{cmd}"
        );
        assert!(cmd.contains("$t::RmEndSession($h)"), "{cmd}");
        assert!(cmd.contains("$d=[byte[]]::new($c*668)"), "{cmd}");
    }

    /// TR-SEC-12: the path enters a single-quoted string, so every single-quote
    /// form is doubled (AC-OBS02-1).
    #[test]
    fn get_open_handles_escapes_the_path() {
        for quote in SINGLE_QUOTES {
            let path = format!("C:\\a{quote}b\\data.mdb");
            let cmd = get_open_handles(&path).expect("valid");
            let doubled = format!("C:\\a{quote}{quote}b\\data.mdb");
            assert!(cmd.contains(&doubled), "the quote must be doubled: {cmd}");
        }
    }

    /// A path above the Windows long-path maximum is refused before any host call,
    /// and the refusal names the length and the limit (TR-REL-14).
    #[test]
    fn get_open_handles_refuses_a_path_above_the_sanity_bound() {
        let path = "C:\\".to_owned() + &"a".repeat(OPEN_HANDLES_PATH_MAX_CHARS);
        let error = get_open_handles(&path).expect_err("above the sanity bound");
        assert!(error.contains(&path.chars().count().to_string()), "{error}");
        assert!(
            error.contains(&OPEN_HANDLES_PATH_MAX_CHARS.to_string()),
            "{error}"
        );
    }

    /// TR-REL-14: a plain path of 260 characters, the Windows `MAX_PATH`, fits one
    /// command line.
    #[test]
    fn get_open_handles_accepts_a_260_character_plain_path() {
        let path = "C:\\".to_owned() + &"a".repeat(257);
        assert_eq!(path.chars().count(), 260);
        let cmd = get_open_handles(&path).expect("260 plain characters must fit");
        assert!(
            fits_command_line(&cmd),
            "chars: {}",
            command_line_chars(&cmd)
        );
    }

    /// TR-REL-14: the command fits up to a computed path limit; the next character
    /// is refused before any host call, and the error names the path and the WinRS
    /// limit. The plain limit is far above 260 characters.
    #[test]
    fn get_open_handles_fits_up_to_the_computed_path_limit() {
        let path_of = |chars: usize| format!("C:\\{}", "a".repeat(chars.saturating_sub(3)));
        let mut limit = 0;
        while limit < 4000 && get_open_handles(&path_of(limit + 1)).is_ok() {
            limit += 1;
        }
        assert!(limit < 4000, "no path limit found");
        assert!(
            limit >= 260,
            "the budget must allow at least 260 characters: {limit}"
        );

        let boundary = path_of(limit);
        let cmd = get_open_handles(&boundary).expect("the boundary fits");
        assert!(
            fits_command_line(&cmd),
            "chars: {}",
            command_line_chars(&cmd)
        );

        let over = path_of(limit + 1);
        let error = get_open_handles(&over).expect_err("beyond the limit");
        assert!(error.contains(&over.chars().count().to_string()), "{error}");
        assert!(
            error.contains(&WINRS_COMMAND_LINE_LIMIT.to_string()),
            "{error}"
        );
    }

    /// TR-REL-14: a directory is walked file by file. The Restart Manager refuses
    /// a directory itself, so the enumeration is capped at the file limit and the
    /// errors of the walk are counted.
    #[test]
    fn get_open_handles_checks_a_directory_file_by_file() {
        let cmd = get_open_handles("C:\\App\\data").expect("valid");
        assert!(cmd.contains("$i.PSIsContainer"), "{cmd}");
        assert!(
            cmd.contains("Get-ChildItem -LiteralPath $p -Recurse -File"),
            "{cmd}"
        );
        assert!(cmd.contains("-ev +x"), "{cmd}");
        assert!(
            cmd.contains(&format!(
                "Select -First {} -Expand FullName",
                OPEN_HANDLES_FILE_LIMIT + 1
            )),
            "{cmd}"
        );
    }

    /// The answer reports how many files were checked and how many were skipped
    /// by the directory walk (TR-REL-14).
    #[test]
    fn get_open_handles_reports_files_checked_and_skipped() {
        let cmd = get_open_handles("C:\\App\\data").expect("valid");
        assert!(cmd.contains("files_checked=$f.Count"), "{cmd}");
        assert!(cmd.contains("skipped=$s"), "{cmd}");
        assert!(cmd.contains("$s=@($x).Count"), "{cmd}");
    }

    /// A missing path (or a parent directory that denies access) throws before the
    /// Restart Manager runs, so the agent sees a clear refusal, not an empty result.
    #[test]
    fn get_open_handles_reports_a_missing_path() {
        let cmd = get_open_handles("C:\\gone\\data.mdb").expect("valid");
        assert!(
            cmd.contains(
                "catch[Management.Automation.ItemNotFoundException]{throw \"Path not found: $p\"}"
            ),
            "{cmd}"
        );
    }

    /// An access-denied path says so, and the branch is on the exception type,
    /// not on localized text (AGENTS.md §6).
    #[test]
    fn get_open_handles_reports_access_denied() {
        let cmd = get_open_handles("C:\\App\\data.mdb").expect("valid");
        assert!(
            cmd.contains("catch[UnauthorizedAccessException]{throw \"Access denied: $p\"}"),
            "{cmd}"
        );
        assert!(
            cmd.contains("if($i.PSProvider.Name -ne 'FileSystem')"),
            "the item must be a filesystem item: {cmd}"
        );
    }

    /// The Restart Manager error codes map to fixed English names, not to a
    /// localized `Win32Exception.Message`.
    #[test]
    fn get_open_handles_maps_restart_manager_error_codes() {
        let cmd = get_open_handles("C:\\App\\data.mdb").expect("valid");
        for code in ["5", "87", "121", "234", "353"] {
            assert!(cmd.contains(&format!("{code}='")), "code {code}: {cmd}");
        }
        assert!(cmd.contains("$($e[$r])"), "{cmd}");
    }

    /// A `RmGetList` that reports `ERROR_MORE_DATA` (234) is retried with a
    /// larger buffer, up to five attempts (TR-REL-14).
    #[test]
    fn get_open_handles_retries_on_more_data() {
        let cmd = get_open_handles("C:\\App\\data.mdb").expect("valid");
        assert!(
            cmd.contains("for($j=0;$j++ -lt 5 -and $r -eq 234;)"),
            "{cmd}"
        );
        assert!(
            cmd.contains("$r=$t::RmGetList($h,[ref]$n,[ref]$c,$d,[ref]$b)"),
            "{cmd}"
        );
        assert!(cmd.contains("$d=[byte[]]::new($c*668)"), "{cmd}");
    }

    /// The holders are capped and flagged, and an empty holder set is an empty
    /// array, not an error: the Restart Manager returns zero entries.
    #[test]
    fn get_open_handles_caps_the_rows_and_returns_an_empty_array() {
        let cmd = get_open_handles("C:\\App\\data.mdb").expect("valid");
        assert!(cmd.contains("$o=@()"), "{cmd}");
        assert!(cmd.contains("if($f.Count){"), "{cmd}");
        assert!(
            cmd.contains(&format!("Select -First {}", OPEN_HANDLES_ROW_LIMIT)),
            "{cmd}"
        );
        assert!(
            cmd.contains(&format!("$rt=$o.Count -gt {OPEN_HANDLES_ROW_LIMIT}")),
            "{cmd}"
        );
        assert!(cmd.contains("holders=@($o|Select -First"), "{cmd}");
        assert!(cmd.contains("count=$o.Count"), "{cmd}");
        assert!(cmd.contains("rows_truncated=$rt"), "{cmd}");
        assert!(cmd.contains("files_truncated=$ft"), "{cmd}");
    }

    /// AC-REL14-1: the result names the PID, the app name, the service short name
    /// and the start time. All of them come from the `RM_PROCESS_INFO` buffer, so
    /// no `Get-Process` and no `.StartTime` (TR-REL-14).
    #[test]
    fn get_open_handles_returns_pid_name_and_start_time() {
        let cmd = get_open_handles("C:\\App\\data.mdb").expect("valid");
        assert!(cmd.contains("pid=[BitConverter]::ToUInt32($d,$y)"), "{cmd}");
        // strAppName is 256 WCHAR at offset 12; strServiceShortName is 64 WCHAR at
        // offset 524 (12 + 512). `RmStr` trims each at the first NUL.
        assert!(cmd.contains("name=(RmStr $d ($y+12) 512)"), "{cmd}");
        assert!(cmd.contains("service=(RmStr $d ($y+524) 128)"), "{cmd}");
        assert!(
            cmd.contains("$k=$s.IndexOf([char]0);if($k -ge 0){$s.Substring(0,$k)}else{$s}"),
            "RmStr must guard a missing NUL: {cmd}"
        );
        // ProcessStartTime is a FILETIME at offset 4, shown as invariant ISO UTC.
        assert!(cmd.contains("[DateTime]::FromFileTimeUtc($z)"), "{cmd}");
        assert!(
            cmd.contains("[Globalization.CultureInfo]::InvariantCulture"),
            "{cmd}"
        );
        assert!(
            cmd.contains(
                ".ToString('yyyy-MM-ddTHH:mm:ssZ',[Globalization.CultureInfo]::InvariantCulture)"
            ),
            "the start time must be ISO UTC: {cmd}"
        );
        assert!(!cmd.contains("Get-Process"), "{cmd}");
        assert!(!cmd.contains(".StartTime"), "{cmd}");
        assert!(cmd.contains("ConvertTo-Json -Compress"), "{cmd}");
    }

    /// In command/argument mode a comma builds one array argument, so `RmStr $d,$y+12,512`
    /// would pass a single array and `$y+12` would stay the string "0+12". The call
    /// uses parenthesised arguments with spaces (TR-REL-14).
    #[test]
    fn get_open_handles_calls_rmstr_with_separate_arguments() {
        let cmd = get_open_handles("C:\\App\\data.mdb").expect("valid");
        assert!(
            !cmd.contains("RmStr $d,"),
            "a comma would pass one array argument: {cmd}"
        );
        assert!(cmd.contains("(RmStr $d ($y+12) 512)"), "{cmd}");
        assert!(cmd.contains("(RmStr $d ($y+524) 128)"), "{cmd}");
    }

    /// TR-REL-14: a function the script declares must not collide with a Windows
    /// PowerShell 5.1 default alias. An alias wins over a function, and the names
    /// are case-insensitive, so an old `function R` would run the alias `r`
    /// (`Invoke-History`) instead of the helper.
    #[test]
    fn get_open_handles_function_names_avoid_default_aliases() {
        let cmd = get_open_handles("C:\\App\\data.mdb").expect("valid");
        assert!(
            !cmd.contains("function R("),
            "the one-letter helper collides with the alias r: {cmd}"
        );
        assert!(
            !cmd.contains("R Rm"),
            "the helper calls must use the renamed name: {cmd}"
        );
        const ALIASES: [&str; 40] = [
            "r", "h", "ls", "gc", "gi", "sl", "ft", "fl", "gl", "gm", "gp", "gu", "gv", "iex",
            "ii", "ni", "ri", "rm", "si", "sc", "sp", "cd", "cls", "dir", "echo", "kill", "man",
            "ps", "pwd", "sort", "type", "where", "foreach", "select", "measure", "group",
            "compare", "diff", "tee", "sleep",
        ];
        let names = function_names(&cmd);
        assert!(!names.is_empty(), "the script must declare helpers: {cmd}");
        for name in &names {
            assert!(
                !ALIASES.contains(&name.to_lowercase().as_str()),
                "the function {name} collides with a PowerShell 5.1 default alias"
            );
        }
    }

    /// Worst case for the WinRS command line: a path whose every character is a
    /// single quote, so the escape doubles it. 260 such characters, the Windows
    /// `MAX_PATH` length, still fit one command line (TR-REL-14).
    #[test]
    fn get_open_handles_command_fits_the_winrs_line_for_the_worst_case() {
        let path = "'".repeat(260);
        let cmd = get_open_handles(&path).expect("the worst case must fit one command line");
        assert!(
            fits_command_line(&cmd),
            "chars: {}",
            command_line_chars(&cmd)
        );
        assert!(
            command_line_chars(&cmd) < WINRS_COMMAND_LINE_LIMIT,
            "chars: {}",
            command_line_chars(&cmd)
        );
    }

    /// The cap keeps the JSON result inside the executor output limit even with
    /// the longest plausible process names and a long path.
    #[test]
    fn get_open_handles_output_fits_the_executor_cap() {
        let rows: Vec<Value> = (0..OPEN_HANDLES_ROW_LIMIT)
            .map(|_| {
                serde_json::json!({
                    "pid": 9_999_999_i64,
                    "name": "A".repeat(255),
                    "service": "B".repeat(63),
                    "started": "2099-12-31T23:59:59Z",
                })
            })
            .collect();
        let payload = serde_json::json!({
            "path": "C:\\".to_owned() + &"a".repeat(517),
            "holders": rows,
            "count": OPEN_HANDLES_ROW_LIMIT,
            "files_checked": OPEN_HANDLES_FILE_LIMIT,
            "skipped": 0,
            "files_truncated": true,
            "rows_truncated": false,
        });
        let text = serde_json::to_string(&payload).expect("serialize");
        assert!(
            text.len() <= crate::executor::MAX_OUTPUT_CHARS,
            "the capped result is {} characters, over the {} limit",
            text.len(),
            crate::executor::MAX_OUTPUT_CHARS
        );
    }

    /// AC-REL15-1: the state is the `Get-Printer` `PrinterStatus` enum name, and
    /// the registry mask decodes with a fixed English table when the name is
    /// absent, so the state does not depend on the host locale.
    #[test]
    fn get_printers_decodes_the_state_flags() {
        let cmd = get_printers();
        for (bit, name) in [
            (1, "Paused"),
            (128, "Offline"),
            (256, "IOActive"),
            (1024, "Printing"),
            (33554432, "ServerOffline"),
            (67108864, "DriverUpdateNeeded"),
        ] {
            assert!(
                cmd.contains(&format!("{bit}='{name}'")),
                "missing flag {name}: {cmd}"
            );
        }
        assert!(
            cmd.contains("$state=[string]$printer.PrinterStatus"),
            "the state must be the enum name, not a decoded mask: {cmd}"
        );
        assert!(
            cmd.contains("$states=@($flags.Keys|Sort-Object|Where-Object{$mask -band $_}|ForEach-Object{$flags[$_]})"),
            "the registry mask must decode by the bit table: {cmd}"
        );
        assert!(cmd.contains("$state=($states -join ', ')"), "{cmd}");
        assert!(
            cmd.contains("if([string]::IsNullOrEmpty($state)){if($null -ne $mask){"),
            "the mask is a fallback only when the name is absent: {cmd}"
        );
        assert!(
            cmd.contains("$state_flags=$mask"),
            "the flag mask must come from the registry value: {cmd}"
        );
        assert!(
            !cmd.contains("else{0}"),
            "a fallback must not make an unread value look healthy: {cmd}"
        );
    }

    /// The state must not look healthy when the host did not report it:
    /// `Get-Printer`'s `PrinterStatus` is the primary source, the registry
    /// `Status` value the fallback, and an unread state stays `Unknown` with a
    /// null flag mask (TR-REL-15).
    #[test]
    fn get_printers_treats_unread_state_as_unknown() {
        let cmd = get_printers();
        assert!(
            cmd.contains("$state=[string]$printer.PrinterStatus"),
            "PrinterStatus must be the primary source: {cmd}"
        );
        assert!(
            cmd.contains("-Name Status -ErrorAction Stop).Status"),
            "the registry Status value must stay the fallback: {cmd}"
        );
        assert!(cmd.contains("$state='Unknown'"), "{cmd}");
        assert!(
            cmd.contains("state=$state;state_flags=$state_flags"),
            "{cmd}"
        );
    }

    /// AC-REL15-1: the result holds the share name, the driver, the port, the port
    /// host and number and the job count (TR-REL-15).
    #[test]
    fn get_printers_returns_the_required_fields() {
        let cmd = get_printers();
        assert!(cmd.contains("share_name=$share"), "{cmd}");
        assert!(cmd.contains("driver=$driver"), "{cmd}");
        assert!(cmd.contains("port=$portname"), "{cmd}");
        assert!(cmd.contains("port_host=$ph"), "{cmd}");
        assert!(cmd.contains("port_number=$pnum"), "{cmd}");
        assert!(
            cmd.contains(
                "job_count=if($null -ne $printer.JobCount){[int]$printer.JobCount}else{$null}"
            ),
            "the job count must come from Get-Printer with no silent 0: {cmd}"
        );
        assert!(
            cmd.contains("Get-PrinterPort -Name $printer.PortName"),
            "{cmd}"
        );
        assert!(
            cmd.contains("Get-Printer -ErrorAction SilentlyContinue"),
            "{cmd}"
        );
        assert!(
            !cmd.contains("Get-PrintJob"),
            "the job count no longer needs a per-printer job query: {cmd}"
        );
    }

    /// A host without the PrintManagement module gives a clear error before any
    /// other host call (TR-REL-15).
    #[test]
    fn print_generators_report_a_missing_print_module() {
        for cmd in [
            get_printers(),
            get_print_jobs("HQ-Printer", false).expect("valid"),
        ] {
            assert!(
                cmd.contains("if($null -eq (Get-Command Get-Printer -ErrorAction SilentlyContinue)){throw \"PrintManagement module is not available\"}"),
                "{cmd}"
            );
        }
    }

    /// A stopped Print Spooler gives a clear error, not an empty list. The branch
    /// is on the service status enum, not on localized text (AGENTS.md §6).
    #[test]
    fn get_printers_gives_a_clear_error_when_the_spooler_is_stopped() {
        let cmd = get_printers();
        assert!(
            cmd.contains(
                "$svc.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running"
            ),
            "{cmd}"
        );
        assert!(
            cmd.contains("throw \"The Print Spooler service is not running: $($svc.Status)\""),
            "{cmd}"
        );
    }

    /// A `Get-Printer` that fails while the list is empty must abort with a clear
    /// error, not look like an empty list (TR-REL-15).
    #[test]
    fn get_printers_throws_when_get_printer_fails() {
        let cmd = get_printers();
        assert!(cmd.contains("-ErrorVariable +perr"), "{cmd}");
        assert!(
            cmd.contains(
                "if(-not $printers.Count -and $perr.Count){throw \"Get-Printer failed: $([string]$perr[0])\"}"
            ),
            "{cmd}"
        );
    }

    /// The fixed printer list script always fits one WinRS command line (TR-REL-15).
    #[test]
    fn get_printers_command_fits_the_winrs_line() {
        let cmd = get_printers();
        assert!(
            fits_command_line(&cmd),
            "chars: {}",
            command_line_chars(&cmd)
        );
    }

    /// An empty printer list is an empty array, not an error, and the row cap and
    /// the size budget both carry the `truncated` flag (TR-REL-15).
    #[test]
    fn get_printers_caps_the_rows_and_returns_an_empty_array() {
        let cmd = get_printers();
        assert!(cmd.contains("$rows=@()"), "{cmd}");
        assert!(
            cmd.contains(&format!(
                "if($rows.Count -ge {PRINTER_LIMIT}){{$truncated=$true;break}}"
            )),
            "{cmd}"
        );
        assert!(
            cmd.contains("count=$total;returned=$rows.Count;truncated=$truncated"),
            "{cmd}"
        );
        assert!(cmd.contains("printers=$rows"), "{cmd}");
        assert!(cmd.contains("$total=$printers.Count"), "{cmd}");
    }

    /// The answer is cut on the host by a size budget, independent of the row cap:
    /// each row is serialized with `ConvertTo-Json -Compress`, rows are kept while
    /// the running total, the separators and the envelope stay under the budget,
    /// and `count`/`returned`/`truncated` report the cut (TR-REL-15).
    #[test]
    fn print_generators_cut_by_the_size_budget() {
        for cmd in [
            get_printers(),
            get_print_jobs("HQ-Printer", true).expect("valid"),
        ] {
            assert!(
                cmd.contains("$j=$row|ConvertTo-Json -Compress"),
                "each row must be serialized to measure it: {cmd}"
            );
            assert!(
                cmd.contains(&format!(
                    "if(($len+$j.Length+1+{PRINT_ENVELOPE_CHARS}) -gt {PRINT_OUTPUT_BUDGET_CHARS}){{$truncated=$true;break}}"
                )),
                "the size budget must stop the rows: {cmd}"
            );
            assert!(cmd.contains("$len=$len+$j.Length+1"), "{cmd}");
            assert!(
                cmd.contains("returned=$rows.Count"),
                "the kept row count must be reported: {cmd}"
            );
        }
        let jobs = get_print_jobs("HQ-Printer", false).expect("valid");
        assert!(jobs.contains("$total=$jobs.Count"), "{jobs}");
    }

    /// AC-REL15-2, Q-21: without `include_personal_data` the script does not read
    /// the document name and the owner on the host at all, so the values never
    /// leave it. With the flag both fields appear.
    #[test]
    fn get_print_jobs_hides_personal_data_by_default() {
        let hidden = get_print_jobs("HQ-Printer", false).expect("valid");
        assert!(
            !hidden.contains("DocumentName"),
            "the document name must not be selected: {hidden}"
        );
        assert!(
            !hidden.contains("UserName"),
            "the owner must not be selected: {hidden}"
        );
        let shown = get_print_jobs("HQ-Printer", true).expect("valid");
        assert!(
            shown.contains(&format!(
                "document_name=Cap $job.DocumentName {DOCUMENT_NAME_CAP}"
            )),
            "{shown}"
        );
        assert!(
            shown.contains(&format!("user=Cap $job.UserName {JOB_USER_CAP}")),
            "{shown}"
        );
    }

    /// An unknown printer gives a clear error, not an empty job list (TR-REL-15).
    #[test]
    fn get_print_jobs_reports_an_unknown_printer() {
        let cmd = get_print_jobs("HQ-Printer", false).expect("valid");
        assert!(cmd.contains("$names -notcontains $printer"), "{cmd}");
        assert!(
            cmd.contains("throw \"Printer not found: $printer\""),
            "{cmd}"
        );
    }

    /// A `Get-Printer` that fails while the name list is empty must abort with
    /// `Get-Printer failed`, not with `Printer not found` (TR-REL-15).
    #[test]
    fn get_print_jobs_throws_when_get_printer_fails() {
        let cmd = get_print_jobs("HQ-Printer", false).expect("valid");
        assert!(
            cmd.contains("-ErrorVariable +perr|ForEach-Object{[string]$_.Name}"),
            "{cmd}"
        );
        assert!(
            cmd.contains(
                "if(-not $names.Count -and $perr.Count){throw \"Get-Printer failed: $([string]$perr[0])\"}"
            ),
            "{cmd}"
        );
    }

    /// A stopped Print Spooler gives a clear error, not an empty job list
    /// (TR-REL-15).
    #[test]
    fn get_print_jobs_gives_a_clear_error_when_the_spooler_is_stopped() {
        let cmd = get_print_jobs("HQ-Printer", false).expect("valid");
        assert!(
            cmd.contains("throw \"The Print Spooler service is not running: $($svc.Status)\""),
            "{cmd}"
        );
    }

    /// No print job is an empty array, not an error, and the cap is carried by
    /// the `truncated` flag (TR-REL-15).
    #[test]
    fn get_print_jobs_caps_the_rows_and_returns_an_empty_array() {
        let cmd = get_print_jobs("HQ-Printer", false).expect("valid");
        assert!(cmd.contains("$rows=@()"), "{cmd}");
        assert!(
            cmd.contains(&format!(
                "if($rows.Count -ge {PRINT_JOB_LIMIT}){{$truncated=$true;break}}"
            )),
            "{cmd}"
        );
        assert!(
            cmd.contains("count=$total;returned=$rows.Count;truncated=$truncated"),
            "{cmd}"
        );
        assert!(cmd.contains("jobs=$rows"), "{cmd}");
        assert!(cmd.contains("$total=$jobs.Count"), "{cmd}");
    }

    /// The submit time is an invariant ISO UTC string and the job state is the
    /// enum name as a string, so neither depends on the host locale (TR-REL-15).
    #[test]
    fn get_print_jobs_uses_locale_independent_fields() {
        let cmd = get_print_jobs("HQ-Printer", false).expect("valid");
        assert!(cmd.contains("[string]$job.JobStatus"), "{cmd}");
        assert!(
            cmd.contains("$job.SubmittedTime.ToUniversalTime()"),
            "{cmd}"
        );
        assert!(
            cmd.contains(
                ".ToString('yyyy-MM-ddTHH:mm:ssZ',[Globalization.CultureInfo]::InvariantCulture)"
            ),
            "{cmd}"
        );
        assert!(cmd.contains("size=[long]$job.Size"), "{cmd}");
    }

    /// TR-SEC-12: the printer name enters a single-quoted string, so every
    /// single-quote form is doubled (AC-OBS02-1).
    #[test]
    fn get_print_jobs_escapes_the_printer_name() {
        for quote in SINGLE_QUOTES {
            let name = format!("HQ{quote}Printer");
            let cmd = get_print_jobs(&name, false).expect("valid");
            let doubled = format!("HQ{quote}{quote}Printer");
            assert!(cmd.contains(&doubled), "the quote must be doubled: {cmd}");
        }
    }

    /// A printer name above the sanity bound is refused before any host call, and
    /// the refusal names the length and the limit (TR-REL-15).
    #[test]
    fn get_print_jobs_refuses_a_name_above_the_sanity_bound() {
        let name = "a".repeat(PRINT_JOB_PRINTER_MAX_CHARS + 1);
        let error = get_print_jobs(&name, false).expect_err("above the sanity bound");
        assert!(
            error.contains(&(PRINT_JOB_PRINTER_MAX_CHARS + 1).to_string()),
            "{error}"
        );
        assert!(
            error.contains(&PRINT_JOB_PRINTER_MAX_CHARS.to_string()),
            "{error}"
        );
    }

    /// Worst case for the WinRS command line: a name whose every character is a
    /// single quote, so the escape doubles it. The maximum name still fits one
    /// command line (TR-REL-15).
    #[test]
    fn get_print_jobs_command_fits_the_winrs_line_for_the_worst_case() {
        let name = "'".repeat(PRINT_JOB_PRINTER_MAX_CHARS);
        let cmd = get_print_jobs(&name, true).expect("the worst case must fit one command line");
        assert!(
            fits_command_line(&cmd),
            "chars: {}",
            command_line_chars(&cmd)
        );
        assert!(
            command_line_chars(&cmd) < WINRS_COMMAND_LINE_LIMIT,
            "chars: {}",
            command_line_chars(&cmd)
        );
    }

    /// The error text must keep free of an unbraced `$name:` inside a string: the
    /// registry path and the messages are safe (TR-REL-15).
    #[test]
    fn print_generators_have_no_scope_qualified_variable_in_a_string() {
        assert_eq!(unbraced_variable_colon(&get_printers()), None);
        assert_eq!(
            unbraced_variable_colon(&get_print_jobs("HQ-Printer", true).expect("valid")),
            None
        );
    }

    /// The number of characters PowerShell 5.1 `ConvertTo-Json` writes for a value.
    ///
    /// 5.1 escapes `'`, `<`, `>` and `&` as `\uXXXX` (six characters, unlike
    /// `serde_json`), so the JSON on the wire is longer than the bytes that
    /// `serde_json` produces.
    fn ps51_json_chars(value: &Value) -> usize {
        let text = serde_json::to_string(value).expect("serialize");
        let escapable = text.matches(&['\'', '<', '>', '&'][..]).count();
        text.len() + 5 * escapable
    }

    /// The size budget makes the bound independent of the row count: the script
    /// keeps rows only while their compressed JSON, the separators and the
    /// envelope stay under the budget, so the answer always fits the executor
    /// output limit (TR-REL-15). The worst-case single row must also fit the row
    /// budget, or the tool would return nothing.
    #[test]
    fn print_results_fit_the_executor_cap() {
        assert!(
            std::hint::black_box(PRINT_OUTPUT_BUDGET_CHARS + PRINT_ENVELOPE_CHARS)
                <= crate::executor::MAX_OUTPUT_CHARS,
            "the budget plus the envelope must fit the {} executor limit",
            crate::executor::MAX_OUTPUT_CHARS
        );

        let row_budget = PRINT_OUTPUT_BUDGET_CHARS - PRINT_ENVELOPE_CHARS;
        let state_all = "Paused, Error, PendingDeletion, PaperJam, PaperOut, ManualFeed, \
             PaperProblem, Offline, IOActive, Busy, Printing, OutputBinFull, NotAvailable, \
             Waiting, Processing, Initializing, WarmingUp, TonerLow, NoToner, PagePunt, \
             UserInterventionRequired, OutOfMemory, DoorOpen, ServerUnknown, PowerSave, \
             ServerOffline, DriverUpdateNeeded";
        let printer = serde_json::json!({
            "name": "'".repeat(PRINTER_NAME_CAP),
            "share_name": "'".repeat(PRINTER_FIELD_CAP),
            "driver": "'".repeat(PRINTER_FIELD_CAP),
            "port": "'".repeat(PRINTER_FIELD_CAP),
            "port_host": "'".repeat(PORT_HOST_CAP),
            "port_number": 65535,
            "state": state_all,
            "state_flags": 0x07FF_FFFF_i64,
            "job_count": 9_999_999_i64,
        });
        assert!(
            ps51_json_chars(&printer) <= row_budget,
            "a worst-case printer row is {} characters, over the {row_budget} row budget",
            ps51_json_chars(&printer)
        );

        let job = serde_json::json!({
            "job_id": 9999999,
            "document_name": "'".repeat(DOCUMENT_NAME_CAP),
            "user": "'".repeat(JOB_USER_CAP),
            "state": "UserInterventionRequired",
            "size": 9_999_999_999_i64,
            "submitted": "2099-12-31T23:59:59Z",
        });
        assert!(
            ps51_json_chars(&job) <= row_budget,
            "a worst-case job row is {} characters, over the {row_budget} row budget",
            ps51_json_chars(&job)
        );
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

    /// The first `$name:` (a single, unbraced colon) inside a double-quoted string, if
    /// any. PowerShell reads `$name:` as a scope qualifier and fails to parse; `${name}`
    /// is the safe form. The scan ignores a `::` (a static call such as `$t::Method`).
    fn unbraced_variable_colon(script: &str) -> Option<String> {
        let chars: Vec<char> = script.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '"' {
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    if chars[i] == '`' {
                        i += 2;
                        continue;
                    }
                    if chars[i] == '$' && i + 1 < chars.len() {
                        let mut j = i + 1;
                        if chars[j].is_ascii_alphabetic() || chars[j] == '_' {
                            j += 1;
                            while j < chars.len()
                                && (chars[j].is_ascii_alphanumeric() || chars[j] == '_')
                            {
                                j += 1;
                            }
                            if j < chars.len() && chars[j] == ':' && chars.get(j + 1) != Some(&':')
                            {
                                return Some(chars[i..=j].iter().collect());
                            }
                        }
                    }
                    i += 1;
                }
            }
            i += 1;
        }
        None
    }

    /// Every generator must stay free of an unbraced `$name:` inside a double-quoted
    /// string: PowerShell 5.1 reads `$name:` as a scope qualifier and fails to parse
    /// the whole script (TR-REL-14, TR-REL-18). The check runs over every branch of
    /// every generator.
    #[test]
    fn no_generator_has_an_unbraced_variable_colon() {
        let mut hits = Vec::new();
        for command in every_generator_command("x") {
            if let Some(hit) = unbraced_variable_colon(&command) {
                hits.push(format!("{hit} in: {command}"));
            }
        }
        assert!(hits.is_empty(), "{}", hits.join("\n\n"));
    }

    /// Collects the helpers the script declares, in order. A name ends at the
    /// first character that is not part of a name.
    fn function_names(script: &str) -> Vec<String> {
        let mut names = Vec::new();
        let mut rest = script;
        while let Some(index) = rest.find("function ") {
            rest = &rest[index + "function ".len()..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                .collect();
            if !name.is_empty() {
                names.push(name);
            }
        }
        names
    }

    /// The temporary path the server builds for a target.
    fn temp_for(path: &str) -> String {
        format!("{path}.winrig-0000000000000000.part")
    }

    /// A target path with exactly `chars` characters, without quotes.
    fn path_of(chars: usize) -> String {
        format!("C:\\{}", "a".repeat(chars.saturating_sub(3)))
    }

    /// TR-FS-05: every command the server sends for a plan fits one command line
    /// (TR-REL-10). The chunk commands carry no preamble of their own; the helper
    /// adds it.
    fn assert_plan_fits(path: &str, temp: &str, plan: &[String]) {
        assert!(fits_command_line(&write_scan(path)), "scan does not fit");
        assert!(fits_command_line(&write_abort(temp)), "abort does not fit");
        for command in plan {
            assert!(
                fits_command_line(command),
                "plan command does not fit: {command}"
            );
        }
    }

    /// TR-EXE-04: the command text reaches the host as a decoded script block, so
    /// a quote or a terminator in the text cannot break out of the wrapper.
    #[test]
    fn run_command_encodes_the_text_instead_of_splicing_it() {
        let evil = "x'; Remove-Item C:\\ -Recurse; '";
        let script = run_command(evil).expect("fits");
        assert!(!script.contains(evil), "the raw text reached the wrapper");
        assert!(
            script.contains("[ScriptBlock]::Create"),
            "the wrapper must run a script block: {script}"
        );
        let encoded = encode_utf16_base64(evil);
        assert!(script.contains(&encoded), "{script}");
        assert!(fits_command_line(&script), "{script}");
    }

    /// TR-EXE-04: the wrapper returns the exit code of the command, so a failure
    /// is visible in `status_code`.
    #[test]
    fn run_command_wrapper_reports_the_exit_code() {
        let script = run_command("cmd /c exit 3").expect("fits");
        assert!(script.contains("$global:LASTEXITCODE=$null"), "{script}");
        assert!(script.contains("exit $LASTEXITCODE"), "{script}");
        assert!(script.contains("if (-not $ok) { exit 1 }"), "{script}");
        assert!(fits_command_line(&script), "{script}");
    }

    /// The encoded command is UTF-16LE base64, so it round-trips byte for byte.
    #[test]
    fn run_command_encodes_utf16le_base64() {
        // "AB" in UTF-16LE is 41 00 42 00, which base64 is "QQBCAA==".
        assert_eq!(encode_utf16_base64("AB"), "QQBCAA==");
    }

    /// An empty command is refused before the network.
    #[test]
    fn run_command_refuses_an_empty_command() {
        assert!(run_command("   ").is_err());
    }

    /// TR-EXE-04: a command above the computed limit is refused, and the error
    /// names the limit. The largest accepted command still fits one command line.
    #[test]
    fn run_command_refuses_a_command_above_the_limit() {
        let max = max_command_chars();
        assert!(run_command(&"a".repeat(max)).is_ok(), "{max}");
        let error = run_command(&"a".repeat(max + 1)).expect_err("too long");
        assert!(error.contains("WinRS command line"), "{error}");
        assert!(fits_command_line(
            &run_command(&"a".repeat(max)).expect("fits")
        ));
    }

    /// TR-EXE-04: the tool description, the README and the site state the limit,
    /// so the computed value is pinned. A change of the wrapper moves the limit
    /// and fails this test on purpose, and the docs must move with it.
    #[test]
    fn max_command_length_is_the_stated_limit() {
        assert_eq!(max_command_chars(), 979);
    }

    /// TR-FS-05: for a short path the full chunk fits one command line, measured
    /// on the real encoding (script UTF-16LE, then base64), not on an estimate.
    #[test]
    fn a_full_chunk_fits_the_winrs_command_line() {
        let temp = temp_for("C:\\out.txt");
        assert_eq!(max_chunk_bytes(&temp), WRITE_CHUNK_BYTES);
        let content = vec![0u8; WRITE_CHUNK_BYTES];
        assert!(fits_command_line(&write_chunk(
            &temp,
            &encode_base64(&content),
            false
        )));
    }

    /// TR-FS-05: a long temporary path lowers the chunk, so the command still
    /// fits; the chunk never drops below the minimum.
    #[test]
    fn a_long_path_lowers_the_chunk() {
        let path = format!("\\\\?\\C:\\{}", "a".repeat(700));
        let temp = temp_for(&path);
        let chunk = max_chunk_bytes(&temp);
        assert!(chunk < WRITE_CHUNK_BYTES, "the chunk must shrink: {chunk}");
        assert!(chunk >= MIN_WRITE_CHUNK_BYTES, "{chunk}");
        let content = vec![0u8; chunk];
        assert!(fits_command_line(&write_chunk(
            &temp,
            &encode_base64(&content),
            false
        )));
    }

    /// TR-FS-05: a `\\?\` path may exceed MAX_PATH, and a small write is accepted
    /// as long as the whole plan fits one command line (TR-FS-04, ADR-0015).
    #[test]
    fn a_long_path_with_small_content_is_accepted() {
        let path = format!("\\\\?\\C:\\{}", "a".repeat(450));
        let temp = temp_for(&path);
        let plan = write_plan(&path, &temp, "hello", "utf8", 64 * 1024).expect("fits");
        assert!(path.chars().count() > 260, "the path must exceed MAX_PATH");
        assert_plan_fits(&path, &temp, &plan);
    }

    /// TR-FS-05: the write fits up to a computed path limit; the next character
    /// is refused before any host call, and the error names the path and the
    /// limit (TR-FS-04).
    #[test]
    fn the_write_fits_up_to_the_computed_path_limit() {
        let mut limit = 0;
        while limit < 5000
            && write_plan(
                &path_of(limit + 1),
                &temp_for(&path_of(limit + 1)),
                "x",
                "utf8",
                64 * 1024,
            )
            .is_ok()
        {
            limit += 1;
        }
        assert!(limit < 5000, "no path limit found");
        assert!(
            limit > 260,
            "the budget must allow more than MAX_PATH: {limit}"
        );

        let path = path_of(limit);
        let temp = temp_for(&path);
        let plan = write_plan(&path, &temp, "x", "utf8", 64 * 1024).expect("the boundary fits");
        assert_plan_fits(&path, &temp, &plan);

        let over = path_of(limit + 1);
        let error = write_plan(&over, &temp_for(&over), "x", "utf8", 64 * 1024)
            .expect_err("beyond the limit");
        assert!(error.contains(&over.chars().count().to_string()), "{error}");
        assert!(
            error.contains(&WINRS_COMMAND_LINE_LIMIT.to_string()),
            "{error}"
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
        assert!(utf8.contains("[IO.File]::Move("), "{utf8}");
        assert!(
            !utf8.contains("Move-Item"),
            "the wildcard-aware parameter must not carry the target: {utf8}"
        );
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
                command.contains("[IO.File]::Move(") || command.contains("[IO.File]::Replace("),
                "{encoding} must replace the target by a file move: {command}"
            );
            assert!(
                !command.contains("Move-Item"),
                "{encoding} must not use a wildcard-aware destination: {command}"
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
        let content = "x".repeat(4096);
        let plan =
            write_plan("C:\\out.txt", "C:\\out.part", &content, "utf8", 64 * 1024).expect("valid");
        // 4096 bytes at a 1536-byte chunk give three chunks, then the replacement.
        assert_eq!(plan.len(), 4, "{plan:#?}");
        assert!(plan[0].contains("WriteAllBytes"));
        assert!(plan[1].contains("Append"));
        assert!(plan[2].contains("Append"));
        assert!(plan[3].contains("[IO.File]::Move("));
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
        assert!(plan[1].contains("[IO.File]::Move("));
    }

    /// The size counts bytes, not characters: Cyrillic is twice as long in
    /// UTF-8, and the limit must count bytes.
    #[test]
    fn plan_counts_bytes_not_characters() {
        let content = "я".repeat(1500); // 3000 bytes in UTF-8
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

    /// TR-EXE-06: the staging plan refuses a script above the byte limit and one
    /// that does not fit the command line, and the refusal names both numbers.
    #[test]
    fn script_plan_refuses_above_the_limit() {
        let over = "x".repeat(5000);
        let error = script_plan("C:\\Temp\\winrig-a.ps1", &over, 4096).expect_err("above");
        assert!(error.contains("5000"), "{error}");
        assert!(error.contains("4096"), "{error}");
        assert!(script_plan("C:\\Temp\\winrig-a.ps1", "Write-Output 1", 4096).is_ok());
    }

    /// TR-EXE-06: the first staging chunk creates the file with `CreateNew` and the
    /// rest append, and the plan carries no rename (the staging file is written in
    /// place).
    #[test]
    fn script_plan_chunks_create_and_append_without_a_rename() {
        let content = "x".repeat(WRITE_CHUNK_BYTES + 10);
        let plan = script_plan("C:\\Temp\\winrig-a.ps1", &content, 64 * 1024).expect("valid");
        assert_eq!(plan.len(), 2, "two chunks, no commit: {plan:#?}");
        assert!(plan[0].contains("'CreateNew'"), "{}", plan[0]);
        assert!(!plan[0].contains("Append"), "{}", plan[0]);
        assert!(plan[1].contains("Append"), "{}", plan[1]);
        assert!(
            !plan
                .iter()
                .any(|step| step.contains("Move-Item") || step.contains("[IO.File]::Move(")),
            "the staging write must not rename: {plan:#?}"
        );
    }

    /// TR-EXE-06, ADR-0017 §31: the run verifies the SHA-256, reads the bytes once
    /// and runs the text as a script block from the expression, so the `Restricted`
    /// execution policy does not block it and no variable holds the text.
    #[test]
    fn script_run_uses_a_script_block_not_a_path() {
        let hash = script_sha256("Write-Output 1");
        let command = run_script_file("C:\\Temp\\winrig-a.ps1", &hash).expect("fits");
        assert!(command.contains("[ScriptBlock]::Create"), "{command}");
        assert!(
            command.contains("ReadAllBytes('C:\\Temp\\winrig-a.ps1')"),
            "{command}"
        );
        // The hash is computed inside try/catch, and the guard follows it, so an
        // exception (empty `$h`) refuses instead of running the script (fail-closed).
        assert!(
            command.contains("try { $h=["),
            "the hash must be computed inside try: {command}"
        );
        assert!(command.contains("catch { $h='' }"), "{command}");
        assert!(command.contains("SHA256CryptoServiceProvider"), "{command}");
        assert!(
            command.contains(&format!("if ($h -ne '{hash}')")),
            "{command}"
        );
        assert!(command.contains("UTF8.GetString($b)"), "{command}");
        assert!(command.contains("TrimStart([char]0xFEFF)"), "{command}");
        assert!(
            command.contains(&format!("exit {SCRIPT_HASH_MISMATCH_EXIT}")),
            "{command}"
        );
        assert!(
            command.contains(SCRIPT_HASH_MISMATCH_MARKER),
            "the mismatch path must carry a clear message: {command}"
        );
        // The comparison and the guard come before any script block, so the script
        // cannot run unless `$h` equals the confirmed value.
        let catch = command.find("catch { $h='' }").expect("catch");
        let guard = command.find("if ($h -ne").expect("guard");
        let block = command.find("[ScriptBlock]::Create").expect("block");
        assert!(
            catch < guard && guard < block,
            "the guard must stand between the check and the run: {command}"
        );
        assert!(
            !command.contains("[IO.File]::ReadAllText"),
            "the file must be read as bytes: {command}"
        );
        assert!(
            !command.contains("$c="),
            "the command text must come from the expression: {command}"
        );
    }

    /// TR-EXE-06: the first staging chunk refuses an existing file with
    /// `CreateNew`, and the later chunks append.
    #[test]
    fn script_first_chunk_uses_create_new() {
        let first = script_chunk_create("C:\\Temp\\winrig-a.ps1", "QUJD");
        assert!(first.contains("'CreateNew'"), "{first}");
        assert!(!first.contains("WriteAllBytes"), "{first}");
        let next = write_chunk("C:\\Temp\\winrig-a.ps1", "QUJD", false);
        assert!(next.contains("'Append'"), "{next}");
    }

    /// TR-EXE-06: the SHA-256 is stable and lowercase hex.
    #[test]
    fn script_sha256_is_lowercase_hex() {
        let hash = script_sha256("abc");
        assert_eq!(
            hash,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(hash.len(), 64);
        assert_ne!(script_sha256("a"), script_sha256("b"));
    }

    /// TR-EXE-06: the cleanup reports `removed` or `absent`, and a failed removal
    /// stops the script so the caller sees it.
    #[test]
    fn script_cleanup_reports_the_outcome() {
        let command = script_cleanup("C:\\Temp\\winrig-a.ps1");
        assert!(command.contains("Remove-Item"), "{command}");
        assert!(command.contains("-ErrorAction Stop"), "{command}");
        assert!(
            command.contains("'removed'") && command.contains("'absent'"),
            "{command}"
        );
    }

    /// TR-EXE-06: the staging temp path comes from the host environment, so the
    /// command is independent of the host locale.
    #[test]
    fn script_temp_path_reads_the_temp_directory() {
        let command = script_temp_path("abc");
        assert!(command.contains("$env:TEMP"), "{command}");
        assert!(command.contains("'winrig-abc.ps1'"), "{command}");
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

    /// Every generator with `text` in each free-text slot, in every branch that
    /// changes the emitted script. The escape check and the brace guard share it,
    /// so a new generator is covered by both at once.
    fn every_generator_command(text: &str) -> Vec<String> {
        // The service tools refuse a name outside the allowed charset, so they are
        // covered with a valid name; the charset guard is tested on its own.
        let service = "Spooler";
        let mut commands = vec![
            list_directory(text),
            find_files(text, text, 5, true),
            read_file(text, 1, 10, false, "UTF8", "").expect("valid"),
            read_file(text, 1, 10, true, "UTF8", text).expect("valid"),
            search_file_content(
                text,
                text,
                text,
                10,
                0,
                0,
                &SearchOptions {
                    from_end: false,
                    count_only: false,
                    since: "",
                    until: "",
                    timestamp_format: "",
                },
            )
            .expect("valid"),
            search_file_content(
                text,
                text,
                text,
                10,
                0,
                0,
                &SearchOptions {
                    from_end: true,
                    count_only: false,
                    since: "2026-01-01 00:00:00",
                    until: "2026-01-02 00:00:00",
                    timestamp_format: "yyyy-MM-dd HH:mm:ss",
                },
            )
            .expect("valid"),
            search_file_content(
                text,
                text,
                text,
                10,
                0,
                0,
                &SearchOptions {
                    from_end: false,
                    count_only: true,
                    since: "2026-01-01 00:00:00",
                    until: "",
                    timestamp_format: "yyyy-MM-dd HH:mm:ss",
                },
            )
            .expect("valid"),
            file_info(text),
            compare_files(text, text, 5),
            get_event_log(text, "error", 24, text, 10).expect("valid"),
            list_event_logs(text),
            get_services(text, "all", true),
            get_service_config(service).expect("valid"),
            set_service_start_type(service, "Automatic", "auto").expect("valid"),
            set_service_start_type(service, "Disabled", "disabled").expect("valid"),
            restart_service(service).expect("valid"),
            stop_service_verified(service, false, 15, "Manual").expect("valid"),
            stop_service_verified(service, true, 15, "Manual").expect("valid"),
            list_processes(text, "memory", 10),
            process_details(1),
            get_registry(text, text, false, 1),
            get_registry(text, text, true, 2),
            registry_value_presence(text, text),
            get_system_info(),
            get_disk_space(),
            get_network_config(),
            get_certificates("LocalMachine", 30).expect("valid"),
            get_local_users(),
            get_security_context(),
            get_environment_variables(text, "machine").expect("valid"),
            test_network(text, 443),
            get_tcp_connections("established", 1, 0, text, false).expect("valid"),
            get_tcp_connections("listen", 0, 0, text, true).expect("valid"),
            get_open_handles(text).expect("valid"),
            get_printers(),
            get_print_jobs(text, false).expect("valid"),
            get_print_jobs(text, true).expect("valid"),
            resolve_dns_name(text, "A", text).expect("valid"),
            get_perf_snapshot(2, text),
            get_scheduled_tasks(text, false),
            get_user_groups(text),
            get_permissions(text),
            get_dns_cache(text),
            get_installed_software(text),
            write_chunk(text, text, true),
            write_chunk(text, text, false),
            write_commit(text, text, "utf8").expect("valid"),
            write_commit(text, text, "unicode").expect("valid"),
            write_abort(text),
            write_scan(text),
            delete_file_scan(text),
            delete_directory_scan(text, 10),
            copy_source_scan(text),
            download_scan(text),
            download_chunk(text, 0, TRANSFER_WINDOW_BYTES),
            download_hash(text, TRANSFER_WINDOW_BYTES),
            upload_chunk(text, 0, UPLOAD_WINDOW_BYTES).expect("valid"),
            upload_chunk(text, UPLOAD_WINDOW_BYTES, 7).expect("valid"),
            upload_commit(text, text, 10, &"ab".repeat(32), false).expect("valid"),
            upload_commit(text, text, 10, &"ab".repeat(32), true).expect("valid"),
            upload_remove_temp(text).expect("valid"),
            copy_command(text, text, false, false).expect("valid"),
            copy_command(text, text, true, true).expect("valid"),
            move_rename_command(text, text, false, false).expect("valid"),
            move_rename_command(text, text, true, true).expect("valid"),
            move_copy_delete_command(text, text, false).expect("valid"),
            rename_command(text, text, false, false).expect("valid"),
            move_case_command(text, text, false, false).expect("valid"),
            move_case_command(text, text, true, true).expect("valid"),
            create_directory_scan(text),
            create_directory_command(text).expect("valid"),
            run_command(text).expect("valid"),
            script_temp_path(text),
            run_script_file(text, &script_sha256(text)).expect("valid"),
            script_cleanup(text),
            script_chunk_create(text, text),
            script_sha256(text),
        ];
        // write_plan returns every command of a whole plan, so the plan is
        // flattened into the list.
        commands.extend(write_plan(text, text, text, "utf8", 1_000_000).expect("valid"));
        commands.extend(script_plan(text, text, 1_000_000).expect("valid"));
        commands
    }

    /// TR-FS-05, DR-5: a .NET exception ends only its own statement, so a
    /// modifying command without `Stop` can print success and exit 0 after a
    /// failed write. Every modifying generator starts with the preference or is
    /// listed as exempt with its reason.
    #[test]
    fn every_modifying_command_stops_on_the_first_error() {
        const STOP: &str = "$ErrorActionPreference = 'Stop'";
        let mut modifying = vec![
            write_chunk("p", "AA==", true),
            write_chunk("p", "AA==", false),
            script_chunk_create("p", "AA=="),
            upload_chunk("p", 0, 1).expect("valid"),
            upload_chunk("p", 5, 1).expect("valid"),
            upload_commit("p", "t", 1, &"ab".repeat(32), false).expect("valid"),
            upload_commit("p", "t", 1, &"ab".repeat(32), true).expect("valid"),
            copy_command("s", "t", false, false).expect("valid"),
            copy_command("s", "t", true, true).expect("valid"),
            move_rename_command("s", "t", false, false).expect("valid"),
            move_rename_command("s", "t", true, true).expect("valid"),
            move_copy_delete_command("s", "t", false).expect("valid"),
            rename_command("s", "t", false, false).expect("valid"),
            move_case_command("s", "T", false, false).expect("valid"),
            move_case_command("s", "T", true, true).expect("valid"),
            create_directory_command("d").expect("valid"),
        ];
        for encoding in VALID_ENCODINGS {
            modifying.push(write_commit("p", "t", encoding).expect("valid"));
            modifying.extend(write_plan("t", "p", "x", encoding, 1000).expect("valid"));
        }
        modifying.extend(script_plan("p", "x", 1000).expect("valid"));
        for command in &modifying {
            assert!(command.starts_with(STOP), "{command}");
        }
        // Exempt, each with its reason:
        // - `run_command` and `run_script_file` run user code under the default
        //   preference, and their wrappers exit with the code of that code.
        // - `write_abort` and `script_cleanup` are cleanup; the first is quiet by
        //   design and the second has its own `-ErrorAction Stop` on the removal.
        // - `upload_remove_temp` proves the removal with its exit code.
        // - The service commands use `-ErrorAction Stop` and `throw` per step.
        let exempt = [
            run_command("x").expect("valid"),
            run_script_file("p", &script_sha256("x")).expect("valid"),
            write_abort("p"),
            script_cleanup("p"),
            upload_remove_temp("p").expect("valid"),
        ];
        for command in &exempt {
            assert!(!command.starts_with(STOP), "{command}");
        }
    }

    /// A failed `Write` must not be hidden by the `Close` after it.
    #[test]
    fn append_closes_the_file_in_a_finally_block() {
        let append = write_chunk("p", "AA==", false);
        assert!(append.contains("try {"), "{append}");
        assert!(append.contains("finally { $f.Close() }"), "{append}");
    }

    /// Injection: free text that enters a PowerShell single-quoted string must
    /// double the quote in every generator (AC-OBS02-1, AC-SEC12-1).
    fn assert_generators_escape(quote: char) {
        let evil = format!("x{quote} ; Remove-Item -Recurse C:\\ ; {quote}");
        let evil = evil.as_str();
        let opened = format!("x{quote}");
        let doubled = format!("x{quote}{quote}");
        for command in every_generator_command(evil) {
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

    /// A `format!` turns `{{` into `{`; a plain string literal keeps it. A stray
    /// `{{` or `}}` reaches PowerShell as a doubled brace and breaks the script,
    /// so no generator may emit one (the `name_table` bug).
    /// A `format!` turns `{{` into `{`; a plain string literal keeps it, and the
    /// doubled opening brace reaches PowerShell as a broken script — exactly the
    /// `name_table` bug. A doubled closing brace `}}` is not checked: it is
    /// legitimate where a scriptblock close meets a hashtable close (for example
    /// `E={…}}` in `file_info`, `else{'N/A'} }}` in `resolve_dns_name`).
    #[test]
    fn every_generator_emits_no_doubled_open_braces() {
        for command in every_generator_command("x") {
            assert!(
                !command.contains("{{"),
                "a doubled opening brace reached the script: {command}"
            );
        }
    }

    /// The process-name hashtable is built by one `Get-Process` call with single
    /// braces; a doubled brace would leave it empty and print junk per process
    /// (TR-REL-13).
    #[test]
    fn tcp_connections_builds_the_process_table_with_single_braces() {
        let cmd = get_tcp_connections("all", 0, 0, "chrome", false).expect("valid");
        assert!(
            cmd.contains("ForEach-Object { $names[[int]$_.Id]=$_.ProcessName }"),
            "{cmd}"
        );
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

    /// TR-XFER-02: one read window stays under the winrm-rs output cap, and the
    /// read and hash commands are bounded to the scanned length.
    #[test]
    fn transfer_window_fits_under_the_output_cap() {
        assert!(transfer_window_fits());
        let base64 = 4 * (TRANSFER_WINDOW_BYTES as usize).div_ceil(3);
        assert!(
            base64 + 4096 <= WINRM_MAX_OUTPUT_BYTES,
            "one window is {base64} base64 bytes, too close to the cap"
        );
        let chunk = download_chunk("C:\\Logs\\CBS.log", 0, TRANSFER_WINDOW_BYTES);
        assert!(fits_command_line(&chunk), "{chunk}");
        assert!(
            chunk.contains("[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete"),
            "{chunk}"
        );
        assert!(chunk.contains("Seek(0, [IO.SeekOrigin]::Begin)"), "{chunk}");
        assert!(
            !chunk.contains("ReadAllBytes"),
            "the whole file must not load into memory: {chunk}"
        );
    }

    /// TR-XFER-02: the scan reads the length without hashing, and the read and the
    /// hash are bounded to the scanned length, so an append-only log verifies.
    #[test]
    fn download_commands_are_bounded_to_the_scan_size() {
        let scan = download_scan("C:\\Logs\\CBS.log");
        assert!(scan.contains("PSProvider.Name -ne 'FileSystem'"), "{scan}");
        assert!(scan.contains("$size = [long]$fs.Length"), "{scan}");
        assert!(
            !scan.contains("ComputeHash") && !scan.contains("TransformBlock"),
            "the scan must not hash the whole file: {scan}"
        );
        let hash = download_hash("C:\\Logs\\CBS.log", 1234);
        assert!(fits_command_line(&hash), "{hash}");
        assert!(hash.contains("$remaining = 1234;"), "{hash}");
        assert!(hash.contains("while ($remaining -gt 0)"), "{hash}");
        assert!(hash.contains("if ($remaining -ne 0)"), "{hash}");
        assert!(hash.contains("TransformBlock"), "{hash}");
        assert!(hash.contains("TransformFinalBlock"), "{hash}");
        let chunk = download_chunk("C:\\Logs\\CBS.log", 100, 500);
        assert!(chunk.contains("$remaining = 500;"), "{chunk}");
        assert!(chunk.contains("while ($remaining -gt 0)"), "{chunk}");
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
        // ADR-0017 §10, item 6: the target is read with `-ErrorAction Stop`, and the
        // scan reports the link type and the directory flag. A reparse point that is
        // not a link reports a null `LinkType`.
        assert!(command.contains("LinkType="), "{command}");
        assert!(command.contains("IsDirectory="), "{command}");
        assert!(
            !command.contains("IsReparsePoint"),
            "the reparse attribute bit is not the refusal key: {command}"
        );
        assert!(
            command.contains("Get-Item -LiteralPath 'x.ps1' -Force -ErrorAction Stop"),
            "{command}"
        );
        let delete = delete_file_scan("x");
        assert!(delete.contains("LinkType="), "{delete}");
        assert!(!delete.contains("IsReparsePoint"), "{delete}");
    }

    /// AC-REL17-1: `get_service_config` reads the start type, the account, the binary
    /// path and the recovery actions from CIM and the registry, never from the
    /// localized `sc.exe` text. The `FailureActions` layout is read with `cActions` at
    /// offset 12 and the action-array offset at 16 (TR-REL-17, finding 5).
    #[test]
    fn get_service_config_reads_cim_and_the_registry() {
        let command = get_service_config("Spooler").expect("valid");
        assert!(command.contains("$n = 'Spooler'"), "{command}");
        assert!(
            command.contains("Get-CimInstance Win32_Service"),
            "{command}"
        );
        assert!(command.contains("[string]$svc.StartMode"), "{command}");
        assert!(command.contains("$svc.StartName"), "{command}");
        assert!(command.contains("$svc.PathName"), "{command}");
        assert!(command.contains("FailureActions"), "{command}");
        assert!(
            command.contains("[BitConverter]::ToUInt32($fa, 0)"),
            "{command}"
        );
        assert!(
            command.contains("[BitConverter]::ToUInt32($fa, 12)"),
            "cActions is not read at offset 12: {command}"
        );
        assert!(
            command.contains("[BitConverter]::ToUInt32($fa, 16)"),
            "the action-array offset is not read at offset 16: {command}"
        );
        assert!(command.contains("$off = $start_at + ($i * 8)"), "{command}");
        assert!(command.contains("DelayedAutostart"), "{command}");
        assert!(command.contains("'AutomaticDelayed'"), "{command}");
        // The localized text of `sc.exe` is not parsed.
        assert!(!command.contains("sc qfailure"), "{command}");
        assert!(!command.contains("sc.exe"), "{command}");
    }

    /// AC-REL18-2: the start type maps to the `sc.exe` value, case-insensitively, and
    /// an unknown value is refused (TR-REL-18).
    #[test]
    fn start_type_maps_the_accepted_labels() {
        assert_eq!(start_type("Automatic"), Some(("Automatic", "auto")));
        assert_eq!(
            start_type(" automaticdelayed "),
            Some(("AutomaticDelayed", "delayed-auto"))
        );
        assert_eq!(start_type("MANUAL"), Some(("Manual", "demand")));
        assert_eq!(start_type("Disabled"), Some(("Disabled", "disabled")));
        assert_eq!(start_type("Automatic (Delayed)"), None);
        assert_eq!(start_type(""), None);
    }

    /// AC-REL18-2, findings 2/6/8: `set_service_start_type` resolves the canonical
    /// name, writes with `sc.exe config`, sets `DelayedAutostart` explicitly with
    /// `-ErrorAction Stop`, re-reads the start type, refuses a mismatch with both
    /// values, and — for `Disabled` — refuses a protected dependent before the write
    /// (TR-REL-18).
    #[test]
    fn set_service_start_type_uses_sc_config() {
        let command =
            set_service_start_type("Spooler", "AutomaticDelayed", "delayed-auto").expect("valid");
        assert!(
            command.contains("$n=Resolve-WinrigService 'Spooler'"),
            "{command}"
        );
        assert!(
            command.contains("& sc.exe config $n start= delayed-auto"),
            "{command}"
        );
        assert!(command.contains("$LASTEXITCODE"), "{command}");
        assert!(
            command.contains("-Name DelayedAutostart -Value $delayed -PropertyType DWord -Force -ErrorAction Stop"),
            "the registry write must stop on error: {command}"
        );
        assert!(
            command.contains("if('AutomaticDelayed' -eq 'AutomaticDelayed'){1}else{0}"),
            "{command}"
        );
        assert!(
            command.contains("$after=Get-WinrigStartType $n"),
            "{command}"
        );
        assert!(
            command.contains(
                "if($after -ne 'AutomaticDelayed'){throw \"the start type is $after, but the tool requested 'AutomaticDelayed'\"}"
            ),
            "a mismatch must be refused with both values: {command}"
        );
        assert!(
            command.contains("start_type=$after;requested='AutomaticDelayed'"),
            "the answer must return the re-read label, not the sc.exe value: {command}"
        );
        // The helper escapes the WQL literal (finding 2).
        assert!(
            command.contains(r#".Replace('\','\\').Replace("'","\'")"#),
            "{command}"
        );
        assert!(
            command.contains("$protected -contains $c"),
            "the host does not re-check the protected list: {command}"
        );
        // A non-Disabled change carries no dependent guard.
        assert!(
            !command.contains("Get-WinrigDependents"),
            "only Disabled needs the dependent guard: {command}"
        );

        // finding 2: Disabled refuses a protected dependent before `sc.exe config`.
        let disabled = set_service_start_type("Spooler", "Disabled", "disabled").expect("valid");
        let dep_at = disabled
            .find("Get-WinrigDependents $n")
            .expect("the dependent guard must be present for Disabled");
        let config_at = disabled
            .find("sc.exe config $n start= disabled")
            .expect("config");
        assert!(
            dep_at < config_at,
            "the dependent guard must precede the write: {disabled}"
        );
        assert!(
            disabled.contains("Refusing to disable ${n}: dependent $($bad -join ', ') is critical"),
            "{disabled}"
        );
    }

    /// AC-REL18-1, findings 1/4: the verified stop resolves the canonical name,
    /// refuses a protected dependent before any write, sets `Disabled` first when
    /// asked, stops without `-Force`, waits, and matches the events by the decoded
    /// `Binary` name (TR-REL-18).
    #[test]
    fn stop_service_verified_waits_and_checks_the_events() {
        let plain = stop_service_verified("Spooler", false, 15, "Manual").expect("valid");
        assert!(
            plain.contains("$n=Resolve-WinrigService 'Spooler'"),
            "{plain}"
        );
        assert!(
            !plain.contains("-Force"),
            "the stop must not use -Force: {plain}"
        );
        assert!(!plain.contains("sc.exe config"), "{plain}");
        assert!(plain.contains("$t0=(Get-Date).AddSeconds(-2)"), "{plain}");
        let dep_at = plain
            .find("Get-WinrigDependents $n")
            .expect("dependent check");
        let stop_at = plain.find("Stop-Service -Name $n").expect("stop");
        let sleep_at = plain.find("Start-Sleep -Seconds 15").expect("wait");
        assert!(
            dep_at < stop_at && stop_at < sleep_at,
            "the dependent check must precede the stop, and the wait must follow it: {plain}"
        );
        assert!(
            plain.contains("$bad -join ', ') is critical for the remote session"),
            "{plain}"
        );
        assert!(
            plain.contains("Refusing to stop ${n}:"),
            "the braced form must guard the colon: {plain}"
        );
        assert!(plain.contains("Id=@(7031,7034,7036)"), "{plain}");
        // The service name comes from the event Binary, not from the localized display name.
        assert!(plain.contains("(Get-WinrigEventName $_) -eq $n"), "{plain}");
        assert!(plain.contains("$e.ToXml()"), "{plain}");
        assert!(
            plain.contains("[Text.Encoding]::Unicode.GetString($b)"),
            "{plain}"
        );
        assert!(plain.contains(".Split('/')[0]"), "{plain}");
        assert!(plain.contains("[Convert]::ToByte("), "{plain}");
        assert!(
            plain.contains("NoMatchingEventsFound"),
            "only a missing-event result must be empty: {plain}"
        );
        assert!(plain.contains("running_again=[bool]$run"), "{plain}");
        assert!(plain.contains("previous_start_type=$prev"), "{plain}");
        assert!(plain.contains("$prev='Manual'"), "{plain}");

        let disabled = stop_service_verified("Spooler", true, 30, "Automatic").expect("valid");
        let dep_at = disabled
            .find("Get-WinrigDependents $n")
            .expect("dependent check");
        let config_at = disabled
            .find("sc.exe config $n start= disabled")
            .expect("config");
        let stop_at = disabled.find("Stop-Service -Name $n").expect("stop");
        assert!(
            dep_at < config_at && config_at < stop_at,
            "the dependent check and the start-type change must precede the stop: {disabled}"
        );
        assert!(disabled.contains("Start-Sleep -Seconds 30"), "{disabled}");
        assert!(disabled.contains("disabled=$true"), "{disabled}");
        assert!(disabled.contains("start_type_changed=$ch"), "{disabled}");
        assert!(disabled.contains("stop_error=$err"), "{disabled}");
        assert!(
            disabled.contains("catch{$err=[string]$_.Exception.Message}"),
            "{disabled}"
        );
        assert!(
            disabled.contains("events_error=$everr"),
            "an event read error must land in events_error, not a throw: {disabled}"
        );
    }

    /// finding 7: `restart_service` resolves the canonical name, re-checks the
    /// protected list on the host and runs without `-Force`.
    #[test]
    fn restart_service_resolves_and_checks_on_the_host() {
        let command = restart_service("Spooler").expect("valid");
        assert!(
            command.contains("$n=Resolve-WinrigService 'Spooler'"),
            "{command}"
        );
        assert!(command.contains("$protected -contains $c"), "{command}");
        assert!(
            command.contains("Restart-Service -Name $n -ErrorAction Stop"),
            "{command}"
        );
        assert!(!command.contains("-Force"), "{command}");
    }

    /// finding 3: a service name outside the allowed charset is refused before the
    /// command is built; the name at the cap still fits one command line.
    #[test]
    fn service_generators_refuse_a_long_or_invalid_name() {
        let long = "a".repeat(SERVICE_NAME_MAX_CHARS + 1);
        for error in [
            get_service_config(&long).expect_err("too long"),
            set_service_start_type(&long, "Automatic", "auto").expect_err("too long"),
            stop_service_verified(&long, false, 15, "Manual").expect_err("too long"),
            restart_service(&long).expect_err("too long"),
        ] {
            assert!(
                error.contains(&SERVICE_NAME_MAX_CHARS.to_string()),
                "{error}"
            );
        }
        for name in ["a\"b", "a\\b", "a/b", "a'b", "a\u{1}b"] {
            for error in [
                get_service_config(name).expect_err("invalid"),
                set_service_start_type(name, "Automatic", "auto").expect_err("invalid"),
                stop_service_verified(name, false, 15, "Manual").expect_err("invalid"),
                restart_service(name).expect_err("invalid"),
            ] {
                assert!(error.contains("outside letters"), "{error}");
            }
        }
        // A worst-case name at the cap still fits one command line.
        let worst = "a".repeat(SERVICE_NAME_MAX_CHARS);
        for command in [
            get_service_config(&worst).expect("valid"),
            set_service_start_type(&worst, "AutomaticDelayed", "delayed-auto").expect("valid"),
            stop_service_verified(&worst, true, 15, "Automatic").expect("valid"),
            restart_service(&worst).expect("valid"),
        ] {
            assert!(
                command_line_chars(&command) < WINRS_COMMAND_LINE_LIMIT,
                "{}",
                command_line_chars(&command)
            );
        }
    }

    /// AC-FS-11: on one volume `move_file` renames the object with `[IO.File]::Move`,
    /// re-checks the source kind and link and never uses a wildcard-aware parameter.
    #[test]
    fn move_file_renames_on_one_volume() {
        let command =
            move_rename_command("C:\\Data\\a.txt", "C:\\Data\\b.txt", false, false).expect("valid");
        assert!(
            command.contains("[IO.File]::Move($s.FullName, 'C:\\Data\\b.txt')"),
            "{command}"
        );
        assert!(!command.contains("Move-Item"), "{command}");
        assert!(!command.contains("-Destination"), "{command}");
        assert!(
            command.contains("$s.LinkType"),
            "the command must re-check the source link: {command}"
        );
        assert!(
            command.contains("[bool]$s.PSIsContainer -ne $false"),
            "the command must re-check the source kind: {command}"
        );
        let dir = move_rename_command("C:\\Data\\d", "C:\\Data\\e", true, false).expect("valid");
        assert!(
            dir.contains("[IO.Directory]::Move($s.FullName, 'C:\\Data\\e')"),
            "{dir}"
        );
        // An existing file target needs `overwrite` and uses the atomic `Replace`.
        let over = move_rename_command("C:\\a", "C:\\b", false, true).expect("valid");
        assert!(
            over.contains("[IO.File]::Replace($s.FullName, 'C:\\b', [NullString]::Value)"),
            "{over}"
        );
        let no_over = move_rename_command("C:\\a", "C:\\b", false, false).expect("valid");
        assert!(no_over.contains("pass overwrite=true"), "{no_over}");
    }

    /// AC-FS-11: across volumes a file is copied with `[IO.File]::Copy`, its size is
    /// verified, and only then the source is deleted; a directory is refused at run
    /// time and a partial result is reported, never as success.
    #[test]
    fn move_file_copies_and_deletes_a_file_across_volumes() {
        let command =
            move_copy_delete_command("C:\\Data\\a.txt", "D:\\Data\\a.txt", false).expect("valid");
        let copy_at = command.find("[IO.File]::Copy").expect("copy");
        let check_at = command.find("$after -ne $before").expect("size check");
        let delete_at = command.find("[IO.File]::Delete").expect("delete");
        assert!(
            copy_at < check_at && check_at < delete_at,
            "the delete must follow the verified copy: {command}"
        );
        assert!(
            command.contains("if ($s.PSIsContainer) { throw"),
            "a directory must be refused at run time: {command}"
        );
        assert!(command.contains("the target may be partial"), "{command}");
        assert!(command.contains("both copies remain"), "{command}");
        assert!(command.contains("if ($err) { exit 1 }"), "{command}");
        assert!(!command.contains("Copy-Item"), "{command}");
        assert!(!command.contains("-Destination"), "{command}");
    }

    /// AC-FS-11, ADR-0017 §19: `rename_file` moves inside its own directory with
    /// `[IO.File]::Move`, replaces an existing target atomically with
    /// `[IO.File]::Replace`, and offers no wildcard-aware parameter.
    #[test]
    fn rename_file_changes_the_last_component() {
        let command =
            rename_command("C:\\Data\\old.txt", "C:\\Data\\new.txt", false, false).expect("valid");
        assert!(
            command.contains("[IO.File]::Move($s.FullName, 'C:\\Data\\new.txt')"),
            "{command}"
        );
        assert!(!command.contains("-Destination"), "{command}");
        assert!(!command.contains("Rename-Item"), "{command}");
        let over =
            rename_command("C:\\Data\\old.txt", "C:\\Data\\new.txt", false, true).expect("valid");
        assert!(
            over.contains(
                "[IO.File]::Replace($s.FullName, 'C:\\Data\\new.txt', [NullString]::Value)"
            ),
            "{over}"
        );
        let dir = rename_command("C:\\Data\\old", "C:\\Data\\new", true, true).expect("valid");
        assert!(
            dir.contains("[IO.Directory]::Move($s.FullName, 'C:\\Data\\new')"),
            "{dir}"
        );
    }

    /// TR-FS-10: a change of case only (`a.txt` → `A.txt`) moves through a unique
    /// temporary name, because the two-step avoids the `File.Move` case collision and
    /// the case-insensitive `Test-Path` of the source.
    #[test]
    fn move_case_command_uses_a_temporary_name() {
        let command =
            move_case_command("D:\\Data\\a.txt", "D:\\Data\\A.txt", false, false).expect("valid");
        assert!(
            command.contains("[IO.File]::Move($s.FullName, $tmp)"),
            "{command}"
        );
        assert!(
            command.contains("[IO.File]::Move($tmp, 'D:\\Data\\A.txt')"),
            "{command}"
        );
        assert!(command.contains("[Guid]::NewGuid"), "{command}");
        assert!(
            !command.contains("Test-Path -LiteralPath 'D:\\Data\\a.txt'"),
            "a case-only move must not re-read the source path: {command}"
        );
        // A directory uses the directory class on both steps.
        let dir = move_case_command("D:\\Data\\Old", "D:\\Data\\OLD", true, false).expect("valid");
        assert!(
            dir.contains("[IO.Directory]::Move($s.FullName, $tmp)"),
            "{dir}"
        );
        assert!(
            dir.contains("[IO.Directory]::Move($tmp, 'D:\\Data\\OLD')"),
            "{dir}"
        );
    }

    /// TR-FS-09, item 2: the directory copy refuses an unreadable tree before the
    /// first write; the pre-scan collects the walk errors in `Unreadable`.
    #[test]
    fn copy_command_refuses_an_unreadable_tree_before_the_first_write() {
        let command =
            copy_command("D:\\Data\\logs", "E:\\Backup\\logs", false, true).expect("valid");
        let walk_err = command
            .find("-ErrorVariable walkErr")
            .expect("the walk collects its errors");
        let throw = command
            .find("the source tree is not fully readable")
            .expect("the walk error throws");
        let first_write = command
            .find("[IO.Directory]::CreateDirectory('E:\\Backup\\logs')")
            .expect("the write");
        assert!(
            walk_err < throw && throw < first_write,
            "the unreadable check must precede the first write: {command}"
        );

        let scan = copy_source_scan("D:\\Data\\logs");
        assert!(scan.contains("-ErrorVariable walkErr"), "{scan}");
        assert!(scan.contains("Unreadable=$unread"), "{scan}");
    }

    /// AC-FS-12, ADR-0017 §20: `create_directory` makes the final directory and the
    /// missing parents with `[IO.Directory]::CreateDirectory`, and the scan counts the
    /// levels and names the shallowest one.
    #[test]
    fn create_directory_makes_the_missing_parents() {
        let command = create_directory_command("C:\\Data\\a\\b\\c").expect("valid");
        assert!(
            command.contains("[IO.Directory]::CreateDirectory('C:\\Data\\a\\b\\c')"),
            "{command}"
        );
        assert!(!command.contains("New-Item"), "{command}");
        assert!(!command.contains("-Path '"), "{command}");
        let scan = create_directory_scan("C:\\Data\\a\\b\\c");
        assert!(scan.contains("MissingLevels=$levels"), "{scan}");
        assert!(scan.contains("TopMissing=$top"), "{scan}");
        assert!(scan.contains("Split-Path -Parent $cur"), "{scan}");
    }

    /// Every file-operation command fits one WinRS command line for a long path, and
    /// a path too long for the line is refused before the transport.
    #[test]
    fn file_operation_commands_fit_the_winrs_line() {
        let long = format!("C:\\{}", "d".repeat(120));
        for command in [
            copy_command(&long, &long, true, true).expect("valid"),
            move_rename_command(&long, &long, true, false).expect("valid"),
            move_copy_delete_command(&long, &long, true).expect("valid"),
            rename_command(&long, &long, true, false).expect("valid"),
            create_directory_command(&long).expect("valid"),
        ] {
            assert!(
                command_line_chars(&command) < WINRS_COMMAND_LINE_LIMIT,
                "{}",
                command_line_chars(&command)
            );
        }
        let over = format!("C:\\{}", "d".repeat(3_500));
        assert!(copy_command(&over, &over, false, false).is_err());
    }

    /// TR-XFER-04: the window command takes its bytes from the standard input, so the
    /// bytes never enter the command text. The first window creates the temp file with
    /// `CreateNew`, and a later window requires the length it expects.
    #[test]
    fn upload_chunk_reads_the_standard_input_into_the_temp_file() {
        let first = upload_chunk("C:\\Data\\db.bin.part", 0, UPLOAD_WINDOW_BYTES).expect("valid");
        assert!(first.contains("OpenStandardInput()"), "{first}");
        assert!(first.contains("[IO.FileMode]::CreateNew"), "{first}");
        assert!(first.contains("[IO.FileShare]::Delete)"), "{first}");
        assert!(!first.contains("[IO.FileShare]::None"), "{first}");
        assert!(first.contains("if ($fs.Length -ne 0)"), "{first}");
        assert!(
            first.contains(&format!("if ($got -ne {UPLOAD_WINDOW_BYTES})")),
            "{first}"
        );
        assert!(
            !first.contains("FromBase64String"),
            "the bytes must not travel in the command: {first}"
        );
        assert!(!first.contains("WriteAllBytes"), "{first}");
        let later = upload_chunk("C:\\Data\\db.bin.part", 4194304, 7).expect("valid");
        assert!(later.contains("if ($fs.Length -ne 4194304)"), "{later}");
        assert!(later.contains("if ($got -ne 7)"), "{later}");
        assert!(later.contains("$mode = if (4194304 -eq 0)"), "{later}");
        assert!(
            later.contains("$fs.Seek(0, [IO.SeekOrigin]::End)"),
            "{later}"
        );
    }

    /// TR-XFER-04: the commit hashes the temp file with a lock that stops writers,
    /// compares the confirmed digest before it touches the target, repeats the target
    /// checks and places the file without a wildcard-aware parameter.
    #[test]
    fn upload_commit_verifies_the_digest_before_it_places_the_file() {
        let sha = "0123456789abcdef".repeat(4);
        let plain = upload_commit(
            "C:\\Data\\db.bin.part",
            "C:\\Data\\db.bin",
            1234,
            &sha,
            false,
        )
        .expect("valid");
        assert!(plain.contains("[IO.FileShare]::Read)"), "{plain}");
        assert!(plain.contains("if ($fs.Length -ne 1234)"), "{plain}");
        assert!(plain.contains("exit 3"), "{plain}");
        assert!(
            plain.contains(&format!("if ($actual -ne '{sha}') {{ exit 4 }}")),
            "{plain}"
        );
        let digest_check = plain.find("exit 4").expect("digest check");
        let placement = plain.find("[IO.File]::Move(").expect("placement");
        assert!(
            digest_check < placement,
            "the placement must follow the digest check: {plain}"
        );
        assert!(plain.contains("if (-not $false)"), "{plain}");
        assert!(plain.contains("$t.PSIsContainer"), "{plain}");
        assert!(plain.contains("$t.LinkType"), "{plain}");
        assert!(plain.contains("[IO.File]::Move($src, $dst)"), "{plain}");
        assert!(
            !plain.contains("[IO.File]::Replace"),
            "a replace without overwrite could take a file that appeared late: {plain}"
        );
        assert!(plain.ends_with("Write-Output 'placed'"), "{plain}");
        let over = upload_commit(
            "C:\\Data\\db.bin.part",
            "C:\\Data\\db.bin",
            1234,
            &sha,
            true,
        )
        .expect("valid");
        assert!(
            over.contains("[IO.File]::Replace($src, $dst, [NullString]::Value)"),
            "{over}"
        );
        assert!(over.contains("[NullString]::Value"), "{over}");
        assert!(over.contains("if (-not $true)"), "{over}");
        assert!(
            !over.contains("Move-Item") && !over.contains("-Destination"),
            "{over}"
        );
        // A digest that is not 64 hexadecimal characters never enters a command.
        assert!(upload_commit("t", "p", 1, "abc", false).is_err());
        assert!(upload_commit("t", "p", 1, &"g".repeat(64), false).is_err());
        assert!(upload_commit("t", "p", 1, &format!("{}' ; x", "a".repeat(60)), false).is_err());
    }

    /// TR-XFER-04: the commit applies the same link rule as the scan (a name surrogate
    /// only), so a reparse point that is not a link, such as a OneDrive placeholder, is
    /// not refused as a link.
    #[test]
    fn upload_commit_refuses_only_a_name_surrogate_at_the_target() {
        let sha = "ab".repeat(32);
        let command = upload_commit("C:\\D\\t.part", "C:\\D\\t", 1, &sha, true).expect("valid");
        assert!(
            command.contains("if ($t.LinkType -in 'SymbolicLink','Junction')"),
            "{command}"
        );
        assert!(
            !command.contains("if ($t.LinkType)"),
            "a bare LinkType test refuses a reparse point that is not a link: {command}"
        );
    }

    /// TR-XFER-04: the commit re-checks the parents. The target must be its own full
    /// path, every parent up to the root is read, a link in a parent refuses, and the
    /// loop is bounded and fails closed.
    #[test]
    fn upload_commit_rechecks_the_parent_directories() {
        let sha = "ab".repeat(32);
        let command = upload_commit("C:\\D\\t.part", "C:\\D\\t", 1, &sha, false).expect("valid");
        assert!(
            command.contains("if ([IO.Path]::GetFullPath($dst) -ne $dst)"),
            "{command}"
        );
        assert!(
            command.contains("$d = [IO.Path]::GetDirectoryName($dst)"),
            "{command}"
        );
        assert!(
            command.contains(&format!("($n -lt {UPLOAD_PARENT_DEPTH})")),
            "{command}"
        );
        assert!(
            command.contains("$di.LinkType -in 'SymbolicLink','Junction'"),
            "{command}"
        );
        assert!(
            command.contains("[IO.FileAttributes]::ReparsePoint"),
            "{command}"
        );
        assert!(
            command.contains(&format!("if ($n -ge {UPLOAD_PARENT_DEPTH}) {{ throw")),
            "the bound must fail closed: {command}"
        );
        let check = command.find("GetFullPath($dst)").expect("path check");
        let placement = command.find("[IO.File]::Move(").expect("placement");
        assert!(
            check < placement,
            "the parent check must precede the placement"
        );
    }

    /// TR-XFER-04: the cleanup command proves the removal with its exit code, and a
    /// stalled window cannot block it because the window opens the temp with
    /// `FileShare.Delete`.
    #[test]
    fn upload_remove_temp_proves_the_removal_by_its_exit_code() {
        let command = upload_remove_temp("C:\\D\\t.part").expect("valid");
        assert!(
            command.contains("Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue"),
            "{command}"
        );
        assert!(
            command.contains("if (Test-Path -LiteralPath $p) { exit 1 }"),
            "{command}"
        );
        assert!(command.ends_with("exit 0"), "{command}");
        let chunk = upload_chunk("C:\\D\\t.part", 0, 1).expect("valid");
        assert!(chunk.contains("[IO.FileShare]::Delete)"), "{chunk}");
    }

    /// TR-XFER-04: the standard input of a host command belongs to the upload window.
    /// `$input` would read it as pipeline input, so no upload command and no preamble
    /// may name it.
    #[test]
    fn upload_commands_and_the_preamble_never_use_the_pipeline_input() {
        let sha = "ab".repeat(32);
        for text in [
            crate::session::PREAMBLE.to_owned(),
            upload_chunk("C:\\D\\t.part", 0, 1).expect("valid"),
            upload_commit("C:\\D\\t.part", "C:\\D\\t", 1, &sha, true).expect("valid"),
            upload_remove_temp("C:\\D\\t.part").expect("valid"),
        ] {
            assert!(!text.to_lowercase().contains("$input"), "{text}");
        }
    }

    /// TR-XFER-04: the upload commands fit one WinRS command line for a long path, and
    /// a path too long for the line is refused before the transport.
    #[test]
    fn upload_commands_fit_the_winrs_line() {
        let sha = "ab".repeat(32);
        let target = format!("C:\\{}", "d".repeat(200));
        let temp = format!("{target}.winrig-0000000000000000.part");
        for command in [
            upload_chunk(&temp, UPLOAD_WINDOW_BYTES, UPLOAD_WINDOW_BYTES).expect("valid"),
            upload_commit(&temp, &target, i64::MAX, &sha, true).expect("valid"),
            upload_commit(&temp, &target, i64::MAX, &sha, false).expect("valid"),
        ] {
            assert!(
                command_line_chars(&command) < WINRS_COMMAND_LINE_LIMIT,
                "{}",
                command_line_chars(&command)
            );
        }
        let over = format!("C:\\{}", "d".repeat(3_500));
        assert!(upload_chunk(&over, 0, 1).is_err());
        assert!(upload_commit(&over, &over, 1, &sha, true).is_err());
    }

    /// ADR-0017 §18: a user path never reaches a wildcard-aware parameter. Only
    /// `-LiteralPath` may carry it; `-Destination` and `-Path` expand a wildcard, so
    /// `C:\[W]indows\x` would reach `System32`. The `[IO.File]` and `[IO.Directory]`
    /// classes act on the literal path.
    #[test]
    fn no_generator_passes_a_user_path_to_a_wildcard_parameter() {
        let mut hits = Vec::new();
        for command in every_generator_command("x") {
            for needle in ["-Destination '", "-Path '"] {
                if command.contains(needle) {
                    hits.push(format!("{needle} in: {command}"));
                }
            }
            // A path-item cmdlet followed directly by a quoted path is positional and
            // wildcard-aware; the literal form is the only permitted one.
            for cmdlet in [
                "Copy-Item",
                "Move-Item",
                "Rename-Item",
                "New-Item",
                "Remove-Item",
                "Set-Content",
                "Get-Content",
            ] {
                if command.contains(&format!("{cmdlet} '")) {
                    hits.push(format!("{cmdlet} with a positional path in: {command}"));
                }
            }
        }
        assert!(hits.is_empty(), "{}", hits.join("\n\n"));
    }

    /// A bare `$null` becomes `""` in a .NET `string` parameter, and
    /// `File.Replace` rejects an empty backup name; `[NullString]::Value` keeps the
    /// null typed (TR-FS-05, TR-FS-10).
    #[test]
    fn no_generator_passes_a_bare_null_to_a_net_call() {
        let mut hits = Vec::new();
        for command in every_generator_command("x") {
            if command.contains(", $null)") {
                hits.push(command);
            }
        }
        assert!(
            hits.is_empty(),
            "a bare $null reaches a .NET call:\n{}",
            hits.join("\n\n")
        );
    }
}
