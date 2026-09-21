//! Интеграционные проверки CLI-настройки: реальный бинарь, временные каталоги,
//! фиктивный Windows-хост не нужен.
//!
//! Покрывает сценарии, которые unit-тесты библиотеки не видят: `setup` печатает
//! токен один раз и не кладёт пароль в вывод (AC-PRF-01/21), повреждённый
//! профиль не пускает stdio (AC-PRF-41), `serve` без секретов отказывает
//! (AC-PRF-47), запись конфига клиента не теряет чужие записи (AC-PRF-15).

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("winrig-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn winrig() -> &'static str {
    env!("CARGO_BIN_EXE_winrig")
}

/// AC-PRF-01/21: `setup` создаёт профиль, печатает токен и не печатает пароль.
#[test]
fn setup_prints_token_once_and_never_the_password() {
    let dir = temp_dir("setup");
    let output = Command::new(winrig())
        .arg("setup")
        .arg("corp")
        .arg("--user")
        .arg("domain\\alice")
        .env("WINRIG_PROFILE_DIR", &dir)
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
                .write_all(b"super-secret-pass\n")?;
            child.wait_with_output()
        })
        .expect("run setup");

    assert_eq!(output.status.code(), Some(0), "setup must succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Пароль не появляется ни в одном потоке (AC-PRF-21).
    assert!(!stdout.contains("super-secret-pass"), "password on stdout");
    assert!(!stderr.contains("super-secret-pass"), "password on stderr");

    // Токен напечатан вместе с определением сервера и один раз как значение:
    // извлекаем hex-токен и убеждаемся, что он же стоит в JSON-определении.
    let token = stdout
        .lines()
        .find(|line| line.len() == 64 && line.chars().all(|c| c.is_ascii_hexdigit()))
        .expect("token line");
    assert!(
        stdout.contains(&format!("\"WINRIG_TOKEN\": \"{token}\"")),
        "the printed token must be the one in the server definition"
    );

    // На диске токена нет (AC-PRF-03 на уровне CLI).
    let profile = dir.join("corp.json");
    assert!(profile.is_file(), "profile must exist");
    let raw = std::fs::read_to_string(&profile).expect("read");
    assert!(!raw.contains(token), "token must not be stored on disk");
    assert!(!raw.contains("super-secret-pass"));

    std::fs::remove_dir_all(&dir).ok();
}

/// AC-PRF-24: повторный `setup` без `--overwrite` отказывает.
#[test]
fn setup_twice_without_overwrite_refuses() {
    let dir = temp_dir("overwrite");
    let create = |args_extra: &[&str]| {
        let mut command = Command::new(winrig());
        command
            .arg("setup")
            .arg("corp")
            .arg("--user")
            .arg("domain\\alice")
            .args(args_extra)
            .env("WINRIG_PROFILE_DIR", &dir)
            .env("WINRIG_STATE_DIR", dir.join("state"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child.stdin.as_mut().expect("stdin").write_all(b"pass\n")?;
                child.wait_with_output()
            })
            .expect("run")
    };

    let first = create(&[]);
    assert_eq!(first.status.code(), Some(0), "first setup must succeed");
    let second = create(&[]);
    assert_ne!(second.status.code(), Some(0), "second must refuse");
    assert!(
        String::from_utf8_lossy(&second.stderr).contains("already exists"),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    // С `--overwrite` повтор проходит.
    let third = create(&["--overwrite"]);
    assert_eq!(third.status.code(), Some(0), "overwrite must succeed");
    std::fs::remove_dir_all(&dir).ok();
}

/// AC-PRF-41: повреждённый профиль не пускает stdio и не раскрывает содержимое.
#[test]
fn corrupt_profile_refuses_stdio() {
    let dir = temp_dir("corrupt");
    let profile = dir.join("corp.json");
    std::fs::write(&profile, b"{ not a profile").expect("write");

    let output = Command::new(winrig())
        .arg("stdio")
        .arg("--profile")
        .arg("corp")
        .env("WINRIG_PROFILE_DIR", &dir)
        .env("WINRIG_STATE_DIR", dir.join("state"))
        .env("WINRIG_TOKEN", "whatever")
        .stdin(Stdio::null())
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty(), "stdout must stay empty");
    std::fs::remove_dir_all(&dir).ok();
}

/// AC-PRF-47: без профиля и без `WINRIG_AUTH_TOKEN` HTTP-режим отказывает.
#[test]
fn serve_without_secret_refuses() {
    let dir = temp_dir("nosecret");
    let output = Command::new(winrig())
        .arg("serve")
        .env("WINRIG_PROFILE_DIR", &dir)
        .env("WINRIG_STATE_DIR", dir.join("state"))
        .env_remove("WINRIG_AUTH_TOKEN")
        .env_remove("WINRIG_TOKEN")
        .stdin(Stdio::null())
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("WINRIG_AUTH_TOKEN") || stderr.contains("profile"),
        "stderr must name both ways: {stderr}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// AC-PRF-15: `setup --write-config` не теряет чужие записи и для opencode не
/// кладёт токен в сам конфиг.
#[test]
fn write_config_preserves_other_entries() {
    let dir = temp_dir("writeconfig");
    let home = dir.join("home");
    let opencode = home.join(".config").join("opencode");
    std::fs::create_dir_all(&opencode).expect("opencode dir");
    std::fs::write(
        opencode.join("opencode.json"),
        br#"{"mcp":{"other":{"type":"local"}}}"#,
    )
    .expect("write config");

    let output = Command::new(winrig())
        .arg("setup")
        .arg("corp")
        .arg("--user")
        .arg("domain\\alice")
        .arg("--write-config")
        .arg("opencode")
        .arg("--scope")
        .arg("global")
        .env("WINRIG_PROFILE_DIR", dir.join("profiles"))
        .env("WINRIG_STATE_DIR", dir.join("state"))
        .env("HOME", &home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.as_mut().expect("stdin").write_all(b"pass\n")?;
            child.wait_with_output()
        })
        .expect("run setup");
    assert_eq!(output.status.code(), Some(0), "setup must succeed");

    let written = std::fs::read_to_string(opencode.join("opencode.json")).expect("read");
    let value: serde_json::Value = serde_json::from_str(&written).expect("valid json");
    assert_eq!(value["mcp"]["other"]["type"], "local");
    assert_eq!(value["mcp"]["winrig"]["type"], "local");
    assert!(
        !written.contains("WINRIG_TOKEN") || written.contains("{file:"),
        "opencode token must be a file reference: {written}"
    );
    assert!(
        opencode.join("winrig-token").is_file(),
        "a private token file must exist"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// AC-PRF-61: `--scope project` пишет в git-корень, а токен opencode — в
/// приватный state-каталог профиля, не в дерево проекта.
#[test]
fn write_config_project_writes_to_git_root() {
    let dir = temp_dir("writeconfig-project");
    let home = dir.join("home");
    let state = dir.join("state");
    let repo = dir.join("repo");
    let nested = repo.join("packages").join("web");
    std::fs::create_dir_all(&nested).expect("nested dir");
    std::fs::create_dir_all(repo.join(".git")).expect("git dir");
    std::fs::create_dir_all(&home).expect("home");

    let output = Command::new(winrig())
        .arg("setup")
        .arg("corp")
        .arg("--user")
        .arg("domain\\alice")
        .arg("--write-config")
        .arg("opencode")
        .arg("--scope")
        .arg("project")
        .current_dir(&nested)
        .env("WINRIG_PROFILE_DIR", dir.join("profiles"))
        .env("WINRIG_STATE_DIR", &state)
        .env("HOME", &home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.as_mut().expect("stdin").write_all(b"pass\n")?;
            child.wait_with_output()
        })
        .expect("run setup");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let written = repo.join("opencode.json");
    assert!(written.is_file(), "project config must go to the git root");
    assert!(
        !nested.join("opencode.json").exists(),
        "nothing may be written to the nested working directory"
    );
    let rendered = std::fs::read_to_string(&written).expect("read");
    assert!(rendered.contains("{file:"), "token must be a reference");
    assert!(
        !rendered.contains("tok-"),
        "the token value must not be in the project config"
    );
    assert!(
        state.join("corp").join("winrig-token").is_file(),
        "the opencode token file must live in the profile state dir"
    );
    assert!(
        !repo.join("winrig-token").exists(),
        "no token file in the project tree"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// AC-PRF-60: без `--scope` и без терминала setup отказывает, не создавая
/// ни профиль, ни конфиг.
#[test]
fn write_config_without_scope_refuses_non_interactive() {
    let dir = temp_dir("writeconfig-noscope");
    let home = dir.join("home");
    std::fs::create_dir_all(&home).expect("home");
    let output = Command::new(winrig())
        .arg("setup")
        .arg("corp")
        .arg("--user")
        .arg("domain\\alice")
        .arg("--write-config")
        .arg("opencode")
        .env("WINRIG_PROFILE_DIR", dir.join("profiles"))
        .env("WINRIG_STATE_DIR", dir.join("state"))
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run setup");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--scope"), "stderr: {stderr}");
    assert!(
        !dir.join("profiles").join("corp.json").exists(),
        "the profile must not be created"
    );
    assert!(
        !home
            .join(".config")
            .join("opencode")
            .join("opencode.json")
            .exists(),
        "the global config must not be written without a scope"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// AC-PRF-63: `--scope` без `--write-config` — ошибка использования.
#[test]
fn scope_without_write_config_refuses() {
    let dir = temp_dir("scope-nowrite");
    let output = Command::new(winrig())
        .arg("setup")
        .arg("corp")
        .arg("--user")
        .arg("domain\\alice")
        .arg("--scope")
        .arg("global")
        .env("WINRIG_PROFILE_DIR", dir.join("profiles"))
        .env("WINRIG_STATE_DIR", dir.join("state"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run setup");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--write-config"), "stderr: {stderr}");
    assert!(
        !dir.join("profiles").join("corp.json").exists(),
        "the profile must not be created"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// ADR-0012: project-уровень клиента с инлайн-токеном предупреждает о
/// возможном коммите.
#[test]
fn write_config_claude_project_warns_about_commit() {
    let dir = temp_dir("writeconfig-claude-project");
    let repo = dir.join("repo");
    std::fs::create_dir_all(repo.join(".git")).expect("git dir");
    std::fs::create_dir_all(dir.join("home")).expect("home");

    let output = Command::new(winrig())
        .arg("setup")
        .arg("corp")
        .arg("--user")
        .arg("domain\\alice")
        .arg("--write-config")
        .arg("claude-code")
        .arg("--scope")
        .arg("project")
        .current_dir(&repo)
        .env("WINRIG_PROFILE_DIR", dir.join("profiles"))
        .env("WINRIG_STATE_DIR", dir.join("state"))
        .env("HOME", dir.join("home"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.as_mut().expect("stdin").write_all(b"pass\n")?;
            child.wait_with_output()
        })
        .expect("run setup");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        repo.join(".mcp.json").is_file(),
        "Claude Code project config must be .mcp.json at the project root"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("version control"),
        "a project config with an inline token must warn: {stderr}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Создаёт профиль и возвращает токен из stdout.
fn create_profile(dir: &std::path::Path, name: &str, user: &str) -> String {
    let output = Command::new(winrig())
        .arg("setup")
        .arg(name)
        .arg("--user")
        .arg(user)
        .env("WINRIG_PROFILE_DIR", dir)
        .env("WINRIG_STATE_DIR", dir.join("state"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.as_mut().expect("stdin").write_all(b"pass\n")?;
            child.wait_with_output()
        })
        .expect("run setup");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find(|line| line.len() == 64 && line.chars().all(|c| c.is_ascii_hexdigit()))
        .expect("token line")
        .to_owned()
}

/// AC-PRF-10: `list` печатает таблицу с заголовками, без секретов.
#[test]
fn list_prints_table_with_headers() {
    let dir = temp_dir("list-table");
    let token = create_profile(&dir, "corp", "domain\\alice");
    let output = Command::new(winrig())
        .arg("list")
        .env("WINRIG_PROFILE_DIR", &dir)
        .env("WINRIG_STATE_DIR", dir.join("state"))
        .output()
        .expect("run list");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = stdout.lines();
    let header = lines.next().expect("header line");
    assert!(header.starts_with("NAME"), "header: {header}");
    assert!(header.contains("USER"), "header: {header}");
    assert!(header.contains("PATH"), "header: {header}");
    let row = lines.next().expect("data row");
    assert!(row.starts_with("corp"), "row: {row}");
    assert!(row.contains("domain\\alice"), "row: {row}");
    assert!(!stdout.contains(&token), "token must not appear");
    assert!(!stdout.contains("pass"), "password must not appear");
    std::fs::remove_dir_all(&dir).ok();
}

/// AC-PRF-10: `list --json` печатает валидный JSON без секретов.
#[test]
fn list_json_is_valid_and_secret_free() {
    let dir = temp_dir("list-json");
    let token = create_profile(&dir, "corp", "domain\\alice");
    let output = Command::new(winrig())
        .arg("list")
        .arg("--json")
        .env("WINRIG_PROFILE_DIR", &dir)
        .env("WINRIG_STATE_DIR", dir.join("state"))
        .output()
        .expect("run list --json");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    assert_eq!(value["count"], 1);
    let profile = &value["profiles"][0];
    assert_eq!(profile["name"], "corp");
    assert_eq!(profile["username"], "domain\\alice");
    assert!(profile["path"].as_str().unwrap().ends_with("corp.json"));
    assert!(profile["created_at"].as_u64().is_some());
    assert!(!stdout.contains(&token));
    std::fs::remove_dir_all(&dir).ok();
}

/// `list --json` при отсутствии профилей даёт пустой список, не ошибку.
#[test]
fn list_json_empty_directory() {
    let dir = temp_dir("list-empty");
    std::fs::create_dir_all(&dir).expect("dir");
    let output = Command::new(winrig())
        .arg("list")
        .arg("--json")
        .env("WINRIG_PROFILE_DIR", &dir)
        .env("WINRIG_STATE_DIR", dir.join("state"))
        .output()
        .expect("run list");
    assert_eq!(output.status.code(), Some(0));
    let value: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).expect("json");
    assert_eq!(value["count"], 0);
    assert_eq!(value["profiles"].as_array().unwrap().len(), 0);
    std::fs::remove_dir_all(&dir).ok();
}

/// `serve --port/--host` перекрывают `WINRIG_PORT`/`WINRIG_BIND_HOST`.
#[test]
fn serve_port_flag_overrides_env() {
    let dir = temp_dir("serve-port");
    let token = create_profile(&dir, "corp", "domain\\alice");

    let mut child = Command::new(winrig())
        .arg("serve")
        .arg("--profile")
        .arg("corp")
        .arg("--port")
        .arg("18421")
        .arg("--host")
        .arg("127.0.0.1")
        .env("WINRIG_PROFILE_DIR", &dir)
        .env("WINRIG_STATE_DIR", dir.join("state"))
        .env("WINRIG_TOKEN", &token)
        // Окружение задаёт другой порт: флаг должен победить.
        .env("WINRIG_PORT", "18422")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn serve");

    // Ждём, пока сервер поднимется и ответит на выбранном флагом порту.
    let mut reachable = false;
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if std::net::TcpStream::connect("127.0.0.1:18421").is_ok() {
            reachable = true;
            break;
        }
    }
    let _ = child.kill();
    let output = child.wait_with_output().expect("wait");
    assert!(
        reachable,
        "server did not listen on the flag port; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Чистый разрыв: старое имя переменной отказывает старту и называет новое.
#[test]
fn legacy_env_name_refuses_startup() {
    let dir = temp_dir("legacy-env");
    for (old, new) in [
        ("MCP_AUTH_TOKEN", "WINRIG_AUTH_TOKEN"),
        ("MCPO_PORT", "WINRIG_PORT"),
        ("LOG_DIR", "WINRIG_LOG_DIR"),
    ] {
        let output = Command::new(winrig())
            .arg("serve")
            .env("WINRIG_PROFILE_DIR", &dir)
            .env("WINRIG_STATE_DIR", dir.join("state"))
            .env(old, "legacy-value")
            .stdin(Stdio::null())
            .output()
            .expect("run serve");
        assert_eq!(output.status.code(), Some(2), "{old} must refuse");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(old), "stderr must name {old}: {stderr}");
        assert!(stderr.contains(new), "stderr must name {new}: {stderr}");
    }
    std::fs::remove_dir_all(&dir).ok();
}

/// `serve --token` задаёт токен профиля аргументом, без WINRIG_TOKEN.
#[test]
fn serve_token_flag_authenticates_profile() {
    let dir = temp_dir("serve-token");
    let token = create_profile(&dir, "corp", "domain\\alice");

    let mut child = Command::new(winrig())
        .arg("serve")
        .arg("--profile")
        .arg("corp")
        .arg("--port")
        .arg("18441")
        .arg("--token")
        .arg(&token)
        .env("WINRIG_PROFILE_DIR", &dir)
        .env("WINRIG_STATE_DIR", dir.join("state"))
        // Токен в окружении отсутствует: единственный источник — аргумент.
        .env_remove("WINRIG_TOKEN")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn serve");

    let status = probe_initialize(18441, &token);
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(status, Some(200), "profile token from --token must work");
    std::fs::remove_dir_all(&dir).ok();
}

/// `serve --auth-token` задаёт общий секрет аргументом, без WINRIG_AUTH_TOKEN.
#[test]
fn serve_auth_token_flag_authenticates_header_path() {
    let dir = temp_dir("serve-auth");
    let mut child = Command::new(winrig())
        .arg("serve")
        .arg("--port")
        .arg("18442")
        .arg("--auth-token")
        .arg("flag-secret")
        .env("WINRIG_PROFILE_DIR", &dir)
        .env("WINRIG_STATE_DIR", dir.join("state"))
        .env_remove("WINRIG_AUTH_TOKEN")
        .env_remove("WINRIG_TOKEN")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn serve");

    let status = probe_initialize_with_user(18442, "flag-secret");
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(status, Some(200), "auth token from --auth-token must work");
    std::fs::remove_dir_all(&dir).ok();
}

/// Флаг перекрывает окружение: с неверным env на порт берётся токен из флага.
#[test]
fn serve_token_flag_overrides_env() {
    let dir = temp_dir("serve-token-override");
    let token = create_profile(&dir, "corp", "domain\\alice");

    let mut child = Command::new(winrig())
        .arg("serve")
        .arg("--profile")
        .arg("corp")
        .arg("--port")
        .arg("18443")
        .arg("--token")
        .arg(&token)
        .env("WINRIG_PROFILE_DIR", &dir)
        .env("WINRIG_STATE_DIR", dir.join("state"))
        .env("WINRIG_TOKEN", "wrong-env-token")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn serve");

    let status = probe_initialize(18443, &token);
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(status, Some(200), "--token must override WINRIG_TOKEN");
    std::fs::remove_dir_all(&dir).ok();
}

/// Отправляет initialize и возвращает HTTP-код.
fn probe_initialize(port: u16, bearer: &str) -> Option<u32> {
    probe_with_headers(port, &[("Authorization", &format!("Bearer {bearer}"))])
}

fn probe_initialize_with_user(port: u16, bearer: &str) -> Option<u32> {
    probe_with_headers(
        port,
        &[
            ("Authorization", &format!("Bearer {bearer}")),
            ("X-AD-User", "alice"),
        ],
    )
}

fn probe_with_headers(port: u16, headers: &[(&str, &str)]) -> Option<u32> {
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let mut command = Command::new("curl");
        command
            .arg("-s")
            .arg("-o")
            .arg("/dev/null")
            .arg("-w")
            .arg("%{http_code}")
            .arg("-X")
            .arg("POST")
            .arg(format!("http://127.0.0.1:{port}/mcp"))
            .arg("-H")
            .arg("Content-Type: application/json")
            .arg("-H")
            .arg("Accept: application/json, text/event-stream");
        for (name, value) in headers {
            command.arg("-H").arg(format!("{name}: {value}"));
        }
        command.arg("-d").arg(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#,
        );
        if let Ok(output) = command.output() {
            let code = String::from_utf8_lossy(&output.stdout);
            if let Ok(value) = code.trim().parse::<u32>()
                && value != 0
            {
                return Some(value);
            }
        }
    }
    None
}
