//! Integration checks of the stdio mode: the real binary, a temporary profile and
//! no fake Windows host (AGENTS.md §4).
//!
//! Checks what the unit tests cannot see: stdout carries JSON-RPC only (AC-PRF-22),
//! `initialize` passes without HTTP headers (AC-PRF-04), and `tools/list` returns
//! exactly 43 tools (AC-PRF-48).

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

/// Starts `winrig stdio` with a profile and performs the MCP handshake.
fn run_stdio(profile_dir: &std::path::Path, token: &str) -> (Vec<String>, Vec<String>) {
    run_stdio_with(profile_dir, token, &[])
}

/// Same as above, with extra environment variables.
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

/// AC-PRF-04/22/48: the handshake, a clean stdout and 41 tools.
#[test]
fn stdio_serves_mcp_over_clean_stdout() {
    let dir = temp_dir("serve");
    let path = dir.join("corp.json");
    let token =
        profile::create(&path, "corp", "domain\\alice", "s3cret-pass", false).expect("profile");

    let (out_lines, err_lines) = run_stdio(&dir, &token);

    // AC-PRF-22: every stdout line is valid JSON-RPC.
    for line in &out_lines {
        let value: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|error| panic!("stdout line is not JSON-RPC: {error}\n{line}"));
        assert_eq!(value["jsonrpc"], "2.0");
    }

    // AC-PRF-04: initialize answered.
    let initialize = out_lines
        .iter()
        .find(|line| line.contains("\"id\":1"))
        .expect("initialize response");
    assert!(initialize.contains("protocolVersion"));

    // AC-PRF-48: exactly 43 tools.
    let tools_line = out_lines
        .iter()
        .find(|line| line.contains("\"id\":2"))
        .expect("tools/list response");
    let value: serde_json::Value = serde_json::from_str(tools_line).expect("json");
    let tools = value["result"]["tools"].as_array().expect("tools array");
    assert_eq!(tools.len(), 43, "expected 43 tools, got {}", tools.len());

    // Log lines go to stderr, not stdout.
    assert!(
        err_lines.iter().any(|line| line.contains("winrig starts")),
        "expected a startup log line on stderr"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// TR-FS-01: the wire shows exactly the set the operator allowed.
/// `write_file` is absent by default and appears with the setting on.
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
    assert_eq!(off.len(), 43, "expected 43 tools by default");
    assert!(!off.iter().any(|name| name == "write_file"));

    let on = names(&[("WINRIG_ALLOW_FILE_WRITE", "true")]);
    assert_eq!(on.len(), 44, "expected 44 tools once file write is allowed");
    assert!(on.iter().any(|name| name == "write_file"));

    std::fs::remove_dir_all(&dir).ok();
}

/// TR-EXE-01: the wire shows exactly the set the operator allowed.
/// `run_command` is absent by default and appears with the setting on. The two
/// flags are independent, so both on gives 45.
#[test]
fn run_command_appears_only_when_enabled() {
    let dir = temp_dir("commandexec");
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
    assert_eq!(off.len(), 43, "expected 43 tools by default");
    assert!(!off.iter().any(|name| name == "run_command"));

    let on = names(&[("WINRIG_ALLOW_COMMAND_EXEC", "true")]);
    assert_eq!(
        on.len(),
        44,
        "expected 44 tools once command execution is allowed"
    );
    assert!(on.iter().any(|name| name == "run_command"));

    let both = names(&[
        ("WINRIG_ALLOW_COMMAND_EXEC", "true"),
        ("WINRIG_ALLOW_FILE_WRITE", "true"),
    ]);
    assert_eq!(both.len(), 45, "expected 45 tools with both flags on");

    std::fs::remove_dir_all(&dir).ok();
}

/// TR-EXE-05: the wire shows exactly the set the operator allowed.
/// `run_script` is absent by default and appears with the setting on. The three
/// flags are independent, so all three on gives 46.
#[test]
fn run_script_appears_only_when_enabled() {
    let dir = temp_dir("scriptexec");
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
    assert_eq!(off.len(), 43, "expected 43 tools by default");
    assert!(!off.iter().any(|name| name == "run_script"));

    let on = names(&[("WINRIG_ALLOW_SCRIPT_EXEC", "true")]);
    assert_eq!(
        on.len(),
        44,
        "expected 44 tools once script execution is allowed"
    );
    assert!(on.iter().any(|name| name == "run_script"));

    let all = names(&[
        ("WINRIG_ALLOW_COMMAND_EXEC", "true"),
        ("WINRIG_ALLOW_FILE_WRITE", "true"),
        ("WINRIG_ALLOW_SCRIPT_EXEC", "true"),
    ]);
    assert_eq!(all.len(), 46, "expected 46 tools with all three flags on");

    std::fs::remove_dir_all(&dir).ok();
}

/// AC-PRF-42: without WINRIG_TOKEN the process refuses and writes nothing to stdout.
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

/// AC-PRF-41: a wrong token gives exit code 2 and reveals no password.
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

/// Starts stdio with a given state directory and a handshake; returns the exit
/// code and the stdout lines.
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

/// AC-PRF-54/55: a second process on the same profile refuses; after the first
/// ends the lock is released and a new process answers.
#[test]
fn second_process_on_same_profile_refuses_then_clears() {
    let dir = temp_dir("lock");
    let path = dir.join("corp.json");
    let token =
        profile::create(&path, "corp", "domain\\alice", "s3cret-pass", false).expect("profile");
    let state_dir = dir.join("state");
    let lock_path = state_dir.join("corp").join("process.lock");

    // The first process keeps stdin open, so it stays alive.
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

    // Wait for the lock file to appear, but no longer than the timeout.
    let mut waited = 0;
    while !lock_path.exists() && waited < 100 {
        std::thread::sleep(std::time::Duration::from_millis(20));
        waited += 1;
    }
    assert!(lock_path.exists(), "first process never took the lock");

    // The second process must refuse and point to the HTTP mode.
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

    // AC-PRF-55: end the first process; the third performs the handshake.
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

/// AC-PRF-44: the profile directory cannot be prepared; the refusal names the path.
#[cfg(unix)]
#[test]
fn unusable_profile_dir_refuses_setup() {
    let dir = temp_dir("unusable");
    // A regular file occupies the path, so the directory cannot be created there.
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
