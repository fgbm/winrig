//! Интеграционные проверки stdio-режима: реальный бинарь, временный профиль,
//! фиктивный Windows-хост не нужен (AGENTS.md §4).
//!
//! Проверяется то, чего не видят unit-тесты: stdout занят только JSON-RPC
//! (AC-PRF-22), `initialize` проходит без HTTP-заголовков (AC-PRF-04), а
//! `tools/list` возвращает ровно 37 инструментов (AC-PRF-48).

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use winrig::profile;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("winrig-stdio-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// Запускает `winrig stdio` с профилем и прогоняет рукопожатие MCP.
fn run_stdio(profile_dir: &std::path::Path, token: &str) -> (Vec<String>, Vec<String>) {
    run_stdio_with(profile_dir, token, &[])
}

/// То же с дополнительными переменными окружения.
fn run_stdio_with(
    profile_dir: &std::path::Path,
    token: &str,
    extra_env: &[(&str, &str)],
) -> (Vec<String>, Vec<String>) {
    let binary = env!("CARGO_BIN_EXE_winrig");
    let mut command = Command::new(binary);
    for (key, value) in extra_env {
        command.env(key, value);
    }
    let mut child = command
        .arg("stdio")
        .arg("--profile")
        .arg("corp")
        .env("WINRIG_PROFILE_DIR", profile_dir)
        .env("WINRIG_STATE_DIR", profile_dir.join("state"))
        .env("WINRIG_TOKEN", token)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn winrig stdio");

    {
        let stdin = child.stdin.as_mut().expect("stdin");
        for message in [
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        ] {
            writeln!(stdin, "{message}").expect("write");
        }
        stdin.flush().expect("flush");
    }
    drop(child.stdin.take());

    let stdout = child.stdout.take().expect("stdout");
    let mut out_lines = Vec::new();
    for line in BufReader::new(stdout).lines() {
        let line = line.expect("read stdout");
        if !line.trim().is_empty() {
            out_lines.push(line);
        }
    }
    let stderr = child.stderr.take().expect("stderr");
    let err_lines: Vec<String> = BufReader::new(stderr)
        .lines()
        .map_while(Result::ok)
        .collect();
    let _ = child.wait();
    (out_lines, err_lines)
}

/// AC-PRF-04/22/48: рукопожатие, чистый stdout и 37 инструментов.
#[test]
fn stdio_serves_mcp_over_clean_stdout() {
    let dir = temp_dir("serve");
    let path = dir.join("corp.json");
    let token =
        profile::create(&path, "corp", "domain\\alice", "s3cret-pass", false).expect("profile");

    let (out_lines, err_lines) = run_stdio(&dir, &token);

    // AC-PRF-22: каждая строка stdout — валидный JSON-RPC.
    for line in &out_lines {
        let value: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|error| panic!("stdout line is not JSON-RPC: {error}\n{line}"));
        assert_eq!(value["jsonrpc"], "2.0");
    }

    // AC-PRF-04: initialize ответил.
    let initialize = out_lines
        .iter()
        .find(|line| line.contains("\"id\":1"))
        .expect("initialize response");
    assert!(initialize.contains("protocolVersion"));

    // AC-PRF-48: ровно 37 инструментов.
    let tools_line = out_lines
        .iter()
        .find(|line| line.contains("\"id\":2"))
        .expect("tools/list response");
    let value: serde_json::Value = serde_json::from_str(tools_line).expect("json");
    let tools = value["result"]["tools"].as_array().expect("tools array");
    assert_eq!(tools.len(), 37, "expected 37 tools, got {}", tools.len());

    // Журнал ушёл в stderr, а не в stdout.
    assert!(
        err_lines
            .iter()
            .any(|line| line.contains("winrig starting")),
        "expected a startup log line on stderr"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// TR-FS-01: на проводе виден ровно тот набор, который разрешил оператор.
/// По умолчанию `write_file` отсутствует, с включённой настройкой появляется.
#[test]
fn write_file_appears_only_when_enabled() {
    let dir = temp_dir("filewrite");
    let path = dir.join("corp.json");
    let token =
        profile::create(&path, "corp", "domain\\alice", "s3cret-pass", false).expect("profile");

    let names = |extra: &[(&str, &str)]| -> Vec<String> {
        let (out_lines, _) = run_stdio_with(&dir, &token, extra);
        let line = out_lines
            .iter()
            .find(|line| line.contains("\"id\":2"))
            .expect("tools/list response");
        let value: serde_json::Value = serde_json::from_str(line).expect("json");
        value["result"]["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .map(|tool| tool["name"].as_str().unwrap_or_default().to_owned())
            .collect()
    };

    let off = names(&[]);
    assert_eq!(off.len(), 37, "expected 37 tools by default");
    assert!(!off.iter().any(|name| name == "write_file"));

    let on = names(&[("WINRIG_ALLOW_FILE_WRITE", "true")]);
    assert_eq!(on.len(), 38, "expected 38 tools once file write is allowed");
    assert!(on.iter().any(|name| name == "write_file"));

    std::fs::remove_dir_all(&dir).ok();
}

/// AC-PRF-42: без WINRIG_TOKEN процесс отказывает, ничего не пишет в stdout.
#[test]
fn stdio_without_token_refuses() {
    let dir = temp_dir("notoken");
    let path = dir.join("corp.json");
    let _ = profile::create(&path, "corp", "domain\\alice", "s3cret-pass", false).expect("profile");

    let output = Command::new(env!("CARGO_BIN_EXE_winrig"))
        .arg("stdio")
        .arg("--profile")
        .arg("corp")
        .env("WINRIG_PROFILE_DIR", &dir)
        .env("WINRIG_STATE_DIR", dir.join("state"))
        .env_remove("WINRIG_TOKEN")
        .stdin(Stdio::null())
        .output()
        .expect("run winrig");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty(), "stdout must stay empty");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("WINRIG_TOKEN"), "stderr: {stderr}");
    std::fs::remove_dir_all(&dir).ok();
}

/// AC-PRF-41: неверный токен даёт код 2, пароль не раскрывается.
#[test]
fn stdio_with_wrong_token_refuses() {
    let dir = temp_dir("wrongtoken");
    let path = dir.join("corp.json");
    let _ = profile::create(&path, "corp", "domain\\alice", "s3cret-pass", false).expect("profile");

    let output = Command::new(env!("CARGO_BIN_EXE_winrig"))
        .arg("stdio")
        .arg("--profile")
        .arg("corp")
        .env("WINRIG_PROFILE_DIR", &dir)
        .env("WINRIG_STATE_DIR", dir.join("state"))
        .env("WINRIG_TOKEN", "not-the-token")
        .stdin(Stdio::null())
        .output()
        .expect("run winrig");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("s3cret-pass"));
    std::fs::remove_dir_all(&dir).ok();
}

/// Запускает stdio с заданным каталогом состояния и рукопожатием; возвращает
/// код выхода и строки stdout.
fn run_stdio_with_state(
    dir: &std::path::Path,
    state_dir: &std::path::Path,
    profile: &str,
    token: &str,
) -> (Option<i32>, Vec<String>) {
    let binary = env!("CARGO_BIN_EXE_winrig");
    let mut child = Command::new(binary)
        .arg("stdio")
        .arg("--profile")
        .arg(profile)
        .env("WINRIG_PROFILE_DIR", dir)
        .env("WINRIG_STATE_DIR", state_dir)
        .env("WINRIG_TOKEN", token)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn winrig stdio");
    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().expect("stdin");
        writeln!(
            stdin,
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{{}},\"clientInfo\":{{\"name\":\"t\",\"version\":\"0\"}}}}}}"
        )
        .expect("write");
        stdin.flush().expect("flush");
    }
    drop(child.stdin.take());
    let stdout = child.stdout.take().expect("stdout");
    let mut lines = Vec::new();
    for line in BufReader::new(stdout).lines() {
        let line = line.expect("read stdout");
        if !line.trim().is_empty() {
            lines.push(line);
        }
    }
    let status = child.wait().expect("wait");
    (status.code(), lines)
}

/// AC-PRF-54/55: второй процесс на том же профиле отказывает; после
/// завершения первого lock освобождается и новый процесс отвечает.
#[test]
fn second_process_on_same_profile_refuses_then_clears() {
    let dir = temp_dir("lock");
    let path = dir.join("corp.json");
    let token =
        profile::create(&path, "corp", "domain\\alice", "s3cret-pass", false).expect("profile");
    let state_dir = dir.join("state");
    let lock_path = state_dir.join("corp").join("process.lock");

    // Первый процесс держит stdin открытым и потому остаётся жив.
    let mut first = Command::new(env!("CARGO_BIN_EXE_winrig"))
        .arg("stdio")
        .arg("--profile")
        .arg("corp")
        .env("WINRIG_PROFILE_DIR", &dir)
        .env("WINRIG_STATE_DIR", &state_dir)
        .env("WINRIG_TOKEN", &token)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn first");

    // Ждём появления lock-файла, но не дольше таймаута.
    let mut waited = 0;
    while !lock_path.exists() && waited < 100 {
        std::thread::sleep(std::time::Duration::from_millis(20));
        waited += 1;
    }
    assert!(lock_path.exists(), "first process never took the lock");

    // Второй процесс должен отказать и указать на HTTP-режим.
    let second = Command::new(env!("CARGO_BIN_EXE_winrig"))
        .arg("stdio")
        .arg("--profile")
        .arg("corp")
        .env("WINRIG_PROFILE_DIR", &dir)
        .env("WINRIG_STATE_DIR", &state_dir)
        .env("WINRIG_TOKEN", &token)
        .stdin(Stdio::null())
        .output()
        .expect("run second");
    assert_eq!(second.status.code(), Some(2), "second process must refuse");
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(stderr.contains("already in use"), "stderr: {stderr}");
    assert!(
        stderr.contains("HTTP"),
        "stderr must point to HTTP: {stderr}"
    );

    // AC-PRF-55: завершаем первый процесс, третий проходит рукопожатие.
    drop(first.stdin.take());
    let _ = first.wait();
    let (code, lines) = run_stdio_with_state(&dir, &state_dir, "corp", &token);
    assert_eq!(code, Some(0), "lock must be released");
    assert!(
        lines.iter().any(|line| line.contains("\"id\":1")),
        "third process must answer initialize: {lines:?}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// AC-PRF-44: каталог профилей нельзя подготовить — отказ с путём.
#[cfg(unix)]
#[test]
fn unusable_profile_dir_refuses_setup() {
    let dir = temp_dir("unusable");
    // Путь занят обычным файлом, поэтому каталог по нему не создаётся.
    let occupied = dir.join("not-a-dir");
    std::fs::write(&occupied, b"x").expect("write");

    let output = Command::new(env!("CARGO_BIN_EXE_winrig"))
        .arg("setup")
        .arg("corp")
        .arg("--user")
        .arg("domain\\alice")
        .env("WINRIG_PROFILE_DIR", &occupied)
        .env("WINRIG_STATE_DIR", dir.join("state"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .as_mut()
                .expect("stdin")
                .write_all(b"password\n")?;
            child.wait_with_output()
        })
        .expect("run setup");

    assert_ne!(output.status.code(), Some(0), "setup must refuse");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not-a-dir") || stderr.contains("cannot"),
        "stderr: {stderr}"
    );
    std::fs::remove_dir_all(&dir).ok();
}
